package certauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/jwtservice"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/types"
	"github.com/gofiber/fiber/v2"
)

// These tests start from the certificate data that CertSec hands over (see certsecserver tests).

var allProfiles = []types.Profile{types.PROFILE_LOCAL, types.PROFILE_ISBE_DEV, types.PROFILE_ISBE_PRE, types.PROFILE_ISBE_PRO}

const (
	testClientID    = "rp-test"
	testRedirectURL = "https://rp.test/callback"
	testOrgID       = "NTRNL-12345678"
)

// fakeDSS is an EU DSS returning the given indication, or HTTP 503 when it is empty.
func fakeDSS(t *testing.T, indication string) (string, *atomic.Int32) {
	t.Helper()
	calls := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if indication == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		fmt.Fprintf(w, `{"simpleCertificateReport":{"Certificate":{"Indication":%q},"ChainItem":[{"Indication":%q}]}}`, indication, indication)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, calls
}

type testEnv struct {
	s   *CertAuthServer
	raw *sql.DB
}

func newTestEnv(t *testing.T, profile types.Profile, dssURL string) *testEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := database.New(path, profile)
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw.Close() })
	if err := db.UpsertRelyingParty(&models.RelyingParty{Name: "Test RP", ClientID: testClientID, RedirectURL: testRedirectURL, Scopes: "openid eidas", TokenExpiry: 3600}, "rp-test-secret"); err != nil {
		t.Fatal(err)
	}

	htmlRender, err := html.NewRendererFiber(false, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		t.Fatal(err)
	}
	jwtService, err := jwtservice.New("https://certauth.test")
	if err != nil {
		t.Fatal(err)
	}
	s := &CertAuthServer{
		httpServer:    fiber.New(),
		profile:       profile,
		euDSSURL:      dssURL,
		db:            db,
		jwtService:    jwtService,
		htmlRender:    htmlRender,
		ssoCache:      cache.NewGeneric[string, *models.SSOSession](time.Minute),
		authprocCache: cache.NewGeneric[string, *models.AuthProcess](time.Minute),
	}
	s.registerOIDCHandlers()
	s.registerCertificateHandlers()
	return &testEnv{s: s, raw: raw}
}

// newCertData returns the certificate data of a self-signed certificate as CertSec builds it.
func newCertData(t *testing.T, orgID string, manuallyApproved bool) *models.CertificateData {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test Organization", Organization: []string{"Test Organization"}, Country: []string{"NL"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if !manuallyApproved {
		tmpl.Subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: orgID}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, issuer, subject, err := x509util.ParseEIDASCertDer(der)
	if err != nil {
		t.Fatal(err)
	}
	subject.OrganizationIdentifier = orgID
	return &models.CertificateData{
		ManuallyApproved: manuallyApproved,
		OrganizationID:   orgID,
		Subject:          subject,
		Issuer:           issuer,
		ValidFrom:        cert.NotBefore,
		ValidTo:          cert.NotAfter,
		CertificateType:  "organizational",
		Certificate:      cert,
		CertificateDER:   base64.StdEncoding.EncodeToString(der),
	}
}

func fingerprint(cd *models.CertificateData) string {
	return fmt.Sprintf("%x", sha256.Sum256(cd.Certificate.Raw))
}

func (e *testEnv) approve(t *testing.T, cd *models.CertificateData) {
	t.Helper()
	if _, err := e.raw.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, ?)`, fingerprint(cd), cd.OrganizationID); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) withdraw(t *testing.T, cd *models.CertificateData) {
	t.Helper()
	if _, err := e.raw.Exec(`DELETE FROM approved_certificates WHERE certificate_sha256 = ?`, fingerprint(cd)); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) newAuthProcess(cd *models.CertificateData, accepted, completed bool) *models.AuthProcess {
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	p := &models.AuthProcess{Code: code, ClientID: testClientID, RedirectURI: testRedirectURL, Scopes: []string{"openid", "eidas"}}
	attempt := p.StartCertificateAttempt()
	p.SetCertificate(cd)
	if accepted {
		p.AcceptCertificate(attempt, cd)
	}
	if completed {
		p.CompleteCertificateFlow(attempt, cd, "user@example.com", "")
	}
	e.s.authprocCache.Set(code, p, time.Minute)
	return p
}

func (e *testEnv) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := e.s.httpServer.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

func postForm(path string, form url.Values) *http.Request {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// certificateBack runs the step after CertSec, where CertAuth decides whether to accept the certificate.
func (e *testEnv) certificateBack(t *testing.T, cd *models.CertificateData) (*models.AuthProcess, string) {
	t.Helper()
	p := e.newAuthProcess(cd, false, false)
	_, body := e.do(t, httptest.NewRequest("GET", CertificateBackEndpoint+"?code="+p.Code, nil))
	return p, body
}

func TestCertificateValidationInEveryProfile(t *testing.T) {
	cases := []struct {
		name     string
		approved bool   // manually approved by CertSec
		dss      string // EU DSS indication; empty: EU DSS is down
		dssCalls int32
		accepted func(types.Profile) bool
		page     string // what the page says about the certificate
	}{
		{"approved, EU DSS down", true, "", 0, func(types.Profile) bool { return true }, "aprobado manualmente"},
		{"eIDAS", false, "PASSED", 1, func(types.Profile) bool { return true }, ""},
		// Rejected in production, accepted in test/demo mode elsewhere, as before
		{"not approved, not eIDAS", false, "FAILED", 1, func(p types.Profile) bool { return p != types.PROFILE_ISBE_PRO }, "no es válido según las normas eIDAS"},
	}
	for _, tc := range cases {
		for _, profile := range allProfiles {
			t.Run(tc.name+"/"+string(profile), func(t *testing.T) {
				dssURL, calls := fakeDSS(t, tc.dss)
				e := newTestEnv(t, profile, dssURL)
				orgID := "VATES-B00000000"
				if tc.approved {
					orgID = testOrgID
				}
				cd := newCertData(t, orgID, tc.approved)
				if tc.approved {
					e.approve(t, cd)
				}
				p, body := e.certificateBack(t, cd)
				acceptedCert, _ := p.AcceptedCertificate()
				accepted := acceptedCert != nil
				if calls.Load() != tc.dssCalls || accepted != tc.accepted(profile) || cd.EIDASCertificate {
					t.Fatalf("dss_calls=%d accepted=%v received data modified=%v", calls.Load(), accepted, cd.EIDASCertificate)
				}
				// The result of the validation is kept for the rest of the flow
				if accepted && acceptedCert.EIDASCertificate != (tc.dss == "PASSED") {
					t.Fatalf("eIDAS result kept=%v, want %v", acceptedCert.EIDASCertificate, tc.dss == "PASSED")
				}
				for _, text := range []string{"aprobado manualmente", "no es válido según las normas eIDAS"} {
					if accepted && strings.Contains(body, text) != (text == tc.page) {
						t.Fatalf("page and %q: want %v", text, text == tc.page)
					}
				}
			})
		}
	}
}

func TestWithdrawnOrExpiredApprovalRejectedAfterCertSec(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")

	withdrawn := newCertData(t, testOrgID, true) // approved in CertSec, withdrawn since
	expired := newCertData(t, testOrgID, true)   // still approved, but expired since
	e.approve(t, expired)
	expired.Certificate.NotAfter = time.Now().Add(-time.Minute)

	for name, cd := range map[string]*models.CertificateData{"withdrawn": withdrawn, "expired": expired} {
		p, body := e.certificateBack(t, cd)
		if accepted, _ := p.AcceptedCertificate(); accepted != nil || !strings.Contains(body, "no longer approved") {
			t.Fatalf("%s approval accepted", name)
		}
	}
}

func TestLaterStepsRequireAnAcceptedCertificate(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)

	// Not accepted (e.g. CertSec received another certificate): the email step refuses it
	p := e.newAuthProcess(cd, false, false)
	e.do(t, postForm(sendEmailVerificationEndpoint, url.Values{"auth_code": {p.Code}, "email": {"user@example.com"}}))
	if p.Email != "" || p.EmailVerificationCode != "" {
		t.Fatalf("email step run for a certificate that was not accepted")
	}

	// Accepted for one certificate, then another one replaced it: refused as well
	p = e.newAuthProcess(cd, true, false)
	p.StartCertificateAttempt() // CertSec receives another certificate
	p.SetCertificate(newCertData(t, testOrgID, true))
	e.do(t, postForm(sendEmailVerificationEndpoint, url.Values{"auth_code": {p.Code}, "email": {"user@example.com"}}))
	if p.Email != "" {
		t.Fatalf("email step run for a certificate other than the accepted one")
	}

	// The contract shows the organization of the certificate, whatever the form says
	p = e.newAuthProcess(cd, true, false)
	p.Email = "user@example.com"
	_, body := e.do(t, postForm(presentContractForAcceptanceEndpoint, url.Values{
		"auth_code": {p.Code}, "representative_email": {p.Email}, "representative_name": {"Jane Doe"},
		"organization_nif": {"VATES-B99999999"}, "organization_country": {"NL"},
	}))
	if !strings.Contains(body, testOrgID) || strings.Contains(body, "VATES-B99999999") {
		t.Fatalf("the contract does not take the organization identifier from the certificate")
	}
}

func TestTokensOnlyAfterAcceptedAndCompletedFlow(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cases := []struct {
		accepted, completed bool
		wantStatus          int
	}{
		{false, false, fiber.StatusBadRequest}, // rejected by CertSec or CertAuth, or never validated
		{true, false, fiber.StatusBadRequest},  // validated, but registration not completed
		{false, true, fiber.StatusBadRequest},
		{true, true, fiber.StatusOK},
	}
	for _, tc := range cases {
		cd := newCertData(t, testOrgID, true)
		e.approve(t, cd)
		p := e.newAuthProcess(cd, tc.accepted, tc.completed)
		resp, body := e.do(t, postForm(token_endpoint, url.Values{"grant_type": {"authorization_code"}, "code": {p.Code}, "client_id": {testClientID}}))
		if resp.StatusCode != tc.wantStatus {
			t.Fatalf("accepted=%v completed=%v: status %d, want %d: %s", tc.accepted, tc.completed, resp.StatusCode, tc.wantStatus, body)
		}
		if tc.wantStatus == fiber.StatusOK && !strings.Contains(body, "id_token") {
			t.Fatalf("no id_token: %s", body)
		}
	}
}

// authorizeWithSSO starts an authorization with an SSO session for the certificate, and
// reports whether the session was reused (direct redirection to the RP).
func (e *testEnv) authorizeWithSSO(t *testing.T, cd *models.CertificateData) bool {
	t.Helper()
	sessionID := fmt.Sprintf("sso-%d", time.Now().UnixNano())
	e.s.ssoCache.Set(sessionID, &models.SSOSession{SessionID: sessionID, CertificateData: cd, Email: "user@example.com"}, time.Minute)
	cookie, err := e.s.generateSSOCookie(sessionID, cd, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURL}, "scope": {"openid eidas"}, "state": {"s"}}
	req := httptest.NewRequest("GET", authorization_endpoint+"?"+q.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	resp, _ := e.do(t, req)
	location := resp.Header.Get("Location")
	reused := strings.HasPrefix(location, testRedirectURL+"?code=")
	if !reused && !strings.HasPrefix(location, certLoginEndpoint) {
		t.Fatalf("unexpected redirection: %s", location)
	}
	_, stillCached := e.s.ssoCache.Get(sessionID)
	if reused != stillCached {
		t.Fatalf("reused=%v but session cached=%v", reused, stillCached)
	}
	return reused
}

func TestSSOSessionOfWithdrawnApprovalNotReused(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	if _, err := e.raw.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, ?)`, fingerprint(cd), testOrgID); err != nil {
		t.Fatal(err)
	}
	if !e.authorizeWithSSO(t, cd) {
		t.Fatalf("SSO session of an approved certificate not reused")
	}

	// Approved for another organization
	if _, err := e.raw.Exec(`UPDATE approved_certificates SET organization_identifier = 'NTRNL-87654321'`); err != nil {
		t.Fatal(err)
	}
	if e.authorizeWithSSO(t, cd) {
		t.Fatalf("SSO session reused for a certificate approved for another organization")
	}

	// Withdrawn
	if _, err := e.raw.Exec(`DELETE FROM approved_certificates`); err != nil {
		t.Fatal(err)
	}
	if e.authorizeWithSSO(t, cd) {
		t.Fatalf("SSO session reused after the approval was withdrawn")
	}

	// The SSO sessions of eIDAS certificates do not depend on the whitelist
	if !e.authorizeWithSSO(t, newCertData(t, "VATES-B00000000", false)) {
		t.Fatalf("SSO session of an eIDAS certificate not reused")
	}
}

func TestWithdrawalStopsOpenAuthenticationProcesses(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	token := func(p *models.AuthProcess) int {
		resp, _ := e.do(t, postForm(token_endpoint, url.Values{"grant_type": {"authorization_code"}, "code": {p.Code}, "client_id": {testClientID}}))
		return resp.StatusCode
	}

	// A process in the middle of the registration: the next step is refused
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)
	p := e.newAuthProcess(cd, true, false)
	p.Email = "user@example.com"
	form := url.Values{"auth_code": {p.Code}, "representative_email": {p.Email}, "representative_name": {"Jane Doe"}}
	if _, body := e.do(t, postForm(presentContractForAcceptanceEndpoint, form)); !strings.Contains(body, testOrgID) {
		t.Fatalf("contract step refused while the certificate is approved")
	}
	e.withdraw(t, cd)
	if _, body := e.do(t, postForm(presentContractForAcceptanceEndpoint, form)); strings.Contains(body, testOrgID) {
		t.Fatalf("contract step run after the approval was withdrawn")
	}

	// A completed process whose code has not been exchanged yet: no tokens
	cd = newCertData(t, testOrgID, true)
	e.approve(t, cd)
	p = e.newAuthProcess(cd, true, true)
	e.withdraw(t, cd)
	if status := token(p); status != fiber.StatusBadRequest {
		t.Fatalf("token status %d after the approval was withdrawn, want 400", status)
	}

	// Approved again but for another organization: no tokens either
	cd = newCertData(t, testOrgID, true)
	if _, err := e.raw.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, 'NTRNL-87654321')`, fingerprint(cd)); err != nil {
		t.Fatal(err)
	}
	if status := token(e.newAuthProcess(cd, true, true)); status != fiber.StatusBadRequest {
		t.Fatalf("token status %d for a certificate approved for another organization, want 400", status)
	}

	// Whitelist unavailable: no tokens
	cd = newCertData(t, testOrgID, true)
	e.approve(t, cd)
	p = e.newAuthProcess(cd, true, true)
	e.s.db.Close()
	if status := token(p); status != fiber.StatusBadRequest {
		t.Fatalf("token status %d with the whitelist unavailable, want 400", status)
	}
}

func TestSSOSessionOfExpiredApprovedCertificateNotReused(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)
	cd.Certificate.NotAfter = time.Now().Add(-time.Minute) // expired after the session was opened
	if e.authorizeWithSSO(t, cd) {
		t.Fatalf("SSO session of an expired approved certificate reused")
	}
}

// testCredential is a minimal wallet credential for the tokens.
var testCredential = map[string]any{"credentialSubject": map[string]any{"mandate": map[string]any{
	"mandator": map[string]any{"organizationIdentifier": "VATES-W00000000"},
	"mandatee": map[string]any{"email": "wallet@example.com"},
}}}

// exchange calls the token endpoint and returns the status and the claims of the ID token.
func (e *testEnv) exchange(t *testing.T, p *models.AuthProcess) (int, string) {
	t.Helper()
	resp, body := e.do(t, postForm(token_endpoint, url.Values{"grant_type": {"authorization_code"}, "code": {p.Code}, "client_id": {testClientID}}))
	var tokens map[string]any
	if resp.StatusCode != fiber.StatusOK || json.Unmarshal([]byte(body), &tokens) != nil {
		return resp.StatusCode, ""
	}
	claims := ""
	for _, k := range []string{"id_token", "access_token"} {
		parts := strings.Split(fmt.Sprint(tokens[k]), ".")
		if len(parts) == 3 {
			payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
			claims += string(payload)
		}
	}
	return resp.StatusCode, claims
}

func TestTokensFollowTheCompletedMethod(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)

	// A certificate attempt (accepted or not), then the wallet: wallet tokens
	for _, accepted := range []bool{false, true} {
		p := e.newAuthProcess(cd, accepted, false)
		p.CompleteWalletAuthentication(testCredential)
		status, claims := e.exchange(t, p)
		if status != fiber.StatusOK || !strings.Contains(claims, "VATES-W00000000") || strings.Contains(claims, testOrgID) {
			t.Fatalf("certificate then wallet (accepted=%v): status %d claims %s", accepted, status, claims)
		}
	}

	// The wallet, then a certificate attempt that does not complete: no tokens
	p := e.newAuthProcess(nil, false, false)
	p.CompleteWalletAuthentication(testCredential)
	attempt := p.StartCertificateAttempt()
	p.SetCertificate(cd)
	if status, _ := e.exchange(t, p); status != fiber.StatusBadRequest {
		t.Fatalf("wallet then unfinished certificate: status %d, want 400", status)
	}

	// The wallet, then a certificate flow that completes: certificate tokens
	p.AcceptCertificate(attempt, cd)
	p.CompleteCertificateFlow(attempt, cd, "user@example.com", "")
	if status, claims := e.exchange(t, p); status != fiber.StatusOK || !strings.Contains(claims, testOrgID) || strings.Contains(claims, "VATES-W00000000") {
		t.Fatalf("wallet then certificate: status %d claims %s", status, claims)
	}

	// Nothing completed: no tokens
	if status, _ := e.exchange(t, e.newAuthProcess(nil, false, false)); status != fiber.StatusBadRequest {
		t.Fatalf("nothing completed: status %d, want 400", status)
	}
}

func TestStepsClosedAfterCompletion(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)
	p := e.newAuthProcess(cd, true, true) // completed with user@example.com

	e.do(t, postForm(sendEmailVerificationEndpoint, url.Values{"auth_code": {p.Code}, "email": {"other@example.com"}}))
	if status, claims := e.exchange(t, p); status != fiber.StatusOK || !strings.Contains(claims, "user@example.com") || strings.Contains(claims, "other@example.com") {
		t.Fatalf("status %d claims %s", status, claims)
	}
}

func TestRepresentativeNameRequiredBeforeTheContract(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	cd := newCertData(t, testOrgID, true)
	e.approve(t, cd)
	for _, endpoint := range []string{presentContractForAcceptanceEndpoint, contractAcceptedEndpoint} {
		p := e.newAuthProcess(cd, true, false)
		p.Email = "user@example.com"
		resp, body := e.do(t, postForm(endpoint, url.Values{"auth_code": {p.Code}, "representative_email": {p.Email}, "representative_name": {"   "}}))
		if resp.StatusCode != fiber.StatusBadRequest || !strings.Contains(body, "Missing representative name") {
			t.Fatalf("%s: status %d: %s", endpoint, resp.StatusCode, body)
		}
	}
}

// The requests of one authentication run concurrently: CertSec receiving another certificate,
// the wallet completing, CertAuth validating, the contract step and the token endpoint. Run with
// -race: tokens are only ever issued for a validated certificate or the wallet credential.
func TestConcurrentRequestsOfOneAuthentication(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, "")
	validated, other := newCertData(t, testOrgID, true), newCertData(t, "NTRNL-87654321", true)
	e.approve(t, validated)

	for range 20 {
		p := e.newAuthProcess(validated, false, false)
		p.Email = "user@example.com"
		var wg sync.WaitGroup
		run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }
		run(func() { e.do(t, httptest.NewRequest("GET", CertificateBackEndpoint+"?code="+p.Code, nil)) })
		run(func() { p.StartCertificateAttempt(); p.SetCertificate(other) })
		run(func() { p.CompleteWalletAuthentication(testCredential) })
		run(func() {
			e.do(t, postForm(presentContractForAcceptanceEndpoint, url.Values{"auth_code": {p.Code}, "representative_email": {p.Email}, "representative_name": {"Jane Doe"}}))
		})
		run(func() {
			if status, claims := e.exchange(t, p); status == fiber.StatusOK && strings.Contains(claims, "NTRNL-87654321") {
				t.Errorf("tokens for a certificate that was not validated")
			}
		})
		wg.Wait()
	}
}

// slowDSS is an EU DSS that answers PASSED only when released, to hold requests in the middle of
// the validation. entered receives a value for each request that reached it.
func slowDSS(t *testing.T) (url string, entered chan struct{}, release chan struct{}) {
	t.Helper()
	entered, release = make(chan struct{}, 10), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		fmt.Fprint(w, `{"simpleCertificateReport":{"Certificate":{"Indication":"PASSED"},"ChainItem":[{"Indication":"PASSED"}]}}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, entered, release
}

// certificateBackAsync starts the certificate-back step and returns a channel with the page.
func (e *testEnv) certificateBackAsync(t *testing.T, p *models.AuthProcess) chan string {
	page := make(chan string, 1)
	go func() {
		_, body := e.do(t, httptest.NewRequest("GET", CertificateBackEndpoint+"?code="+p.Code, nil))
		page <- body
	}()
	return page
}

func TestReloadDuringValidation(t *testing.T) {
	dssURL, entered, release := slowDSS(t)
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, dssURL)
	p := e.newAuthProcess(newCertData(t, "VATES-B00000000", false), false, false)

	// Two loads of the same attempt validate at the same time: neither invalidates the other
	first, second := e.certificateBackAsync(t, p), e.certificateBackAsync(t, p)
	<-entered
	<-entered
	close(release)
	for _, page := range []string{<-first, <-second} {
		if !strings.Contains(page, `name="email"`) {
			t.Fatalf("a load of the same attempt was rejected: %.200s", page)
		}
	}
	if cd, _ := p.AcceptedCertificate(); cd == nil || !cd.EIDASCertificate {
		t.Fatalf("certificate not accepted with its eIDAS result")
	}
}

func TestLaterStepDuringReload(t *testing.T) {
	dssURL, entered, release := slowDSS(t)
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, dssURL)
	p := e.newAuthProcess(newCertData(t, "VATES-B00000000", false), false, false)

	// The certificate is accepted
	page := e.certificateBackAsync(t, p)
	<-entered
	release <- struct{}{}
	<-page

	// A reload validates it again while the contract step of the same attempt runs
	reload := e.certificateBackAsync(t, p)
	<-entered
	p.Email = "user@example.com"
	_, body := e.do(t, postForm(presentContractForAcceptanceEndpoint, url.Values{
		"auth_code": {p.Code}, "representative_email": {p.Email}, "representative_name": {"Jane Doe"}}))
	close(release)
	if !strings.Contains(body, "VATES-B00000000") {
		t.Fatalf("the contract step was invalidated by a reload of the same attempt")
	}
	if !strings.Contains(<-reload, `name="email"`) {
		t.Fatalf("the reload was rejected")
	}
	if cd, attempt := p.AcceptedCertificate(); cd == nil || !p.CompleteCertificateFlow(attempt, cd, "user@example.com", "") {
		t.Fatalf("the flow of the attempt can not complete after the reload")
	}
}

func TestCertificateChangedDuringValidation(t *testing.T) {
	dssURL, entered, release := slowDSS(t)
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, dssURL)
	p := e.newAuthProcess(newCertData(t, "VATES-B00000000", false), false, false)

	page := e.certificateBackAsync(t, p)
	<-entered
	// CertSec receives another certificate: a new attempt
	other := newCertData(t, "VATES-B11111111", false)
	p.StartCertificateAttempt()
	p.SetCertificate(other)
	close(release)

	if body := <-page; strings.Contains(body, `name="email"`) {
		t.Fatalf("the validation of the previous attempt was accepted")
	}
	if cd, _ := p.AcceptedCertificate(); cd != nil {
		t.Fatalf("a certificate is accepted without its own validation")
	}
	if cd, _, _ := p.CertificateResult(); cd != other {
		t.Fatalf("the certificate of the new attempt was replaced")
	}
}
