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
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
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
	p.SetCertificate(cd)
	if accepted {
		p.AcceptCertificate(cd)
	}
	if completed {
		p.CompleteCertificateFlow(cd)
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

func TestManuallyApprovedCertificateDoesNotDependOnEUDSS(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			dssURL, calls := fakeDSS(t, "") // EU DSS is down
			e := newTestEnv(t, profile, dssURL)
			p, body := e.certificateBack(t, newCertData(t, testOrgID, true))
			if calls.Load() != 0 {
				t.Fatalf("EU DSS called %d times for a manually approved certificate", calls.Load())
			}
			if !(p.AcceptedCertificate() != nil) || p.CertificateData.EIDASCertificate {
				t.Fatalf("accepted=%v eidas=%v, want accepted and not eIDAS", (p.AcceptedCertificate() != nil), p.CertificateData.EIDASCertificate)
			}
			if !strings.Contains(body, "aprobado manualmente") {
				t.Fatalf("the page does not say that the certificate was manually approved")
			}
		})
	}
}

func TestEIDASCertificateUsualBehaviour(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			dssURL, calls := fakeDSS(t, "PASSED")
			e := newTestEnv(t, profile, dssURL)
			p, _ := e.certificateBack(t, newCertData(t, "VATES-B00000000", false))
			if calls.Load() != 1 || !(p.AcceptedCertificate() != nil) || !p.CertificateData.EIDASCertificate {
				t.Fatalf("dss_calls=%d accepted=%v eidas=%v", calls.Load(), (p.AcceptedCertificate() != nil), p.CertificateData.EIDASCertificate)
			}
		})
	}
}

func TestNotApprovedNonEIDASCertificateUsualBehaviour(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			dssURL, calls := fakeDSS(t, "FAILED")
			e := newTestEnv(t, profile, dssURL)
			p, _ := e.certificateBack(t, newCertData(t, "VATES-B00000000", false))
			// Rejected in production, accepted in test/demo mode elsewhere, as before
			wantAccepted := profile != types.PROFILE_ISBE_PRO
			if calls.Load() != 1 || (p.AcceptedCertificate() != nil) != wantAccepted || p.CertificateData.EIDASCertificate {
				t.Fatalf("dss_calls=%d accepted=%v eidas=%v", calls.Load(), (p.AcceptedCertificate() != nil), p.CertificateData.EIDASCertificate)
			}
		})
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
	cookie, err := e.s.generateSSOCookie(sessionID, cd)
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
