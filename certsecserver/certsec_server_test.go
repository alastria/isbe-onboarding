package certsec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/types"
)

// testCert describes a self-signed client certificate for the tests.
type testCert struct {
	orgID, serial       string
	notBefore, notAfter time.Time
	key                 crypto.Signer
	extKeyUsage         []x509.ExtKeyUsage
	isCA                bool
	issuerOrgID         string // issuer organizationIdentifier; empty: self-signed
}

// build returns the certificate as base64 DER, as Caddy sends it, and its SHA-256 fingerprint.
func (tc testCert) build(t *testing.T) (b64der string, fingerprint string) {
	t.Helper()
	key := tc.key
	if key == nil {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if tc.notBefore.IsZero() {
		tc.notBefore = time.Now().Add(-time.Hour)
	}
	if tc.notAfter.IsZero() {
		tc.notAfter = time.Now().Add(24 * time.Hour)
	}
	if tc.extKeyUsage == nil {
		tc.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	subject := pkix.Name{CommonName: "Test Organization", Organization: []string{"Test Organization"}, Country: []string{"NL"}, SerialNumber: tc.serial}
	if tc.orgID != "" {
		subject.ExtraNames = []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: tc.orgID}}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               subject,
		NotBefore:             tc.notBefore,
		NotAfter:              tc.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           tc.extKeyUsage,
		IsCA:                  tc.isCA,
		BasicConstraintsValid: true,
	}
	parent := tmpl
	if tc.issuerOrgID != "" {
		parent = &x509.Certificate{Subject: pkix.Name{CommonName: "Issuer", ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 97}, Value: tc.issuerOrgID}}}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), fmt.Sprintf("%x", sha256.Sum256(der))
}

type testEnv struct {
	s     *CertSecServer
	db    *database.Database
	raw   *sql.DB // direct access to the whitelist, as an operator would have
	cache *cache.GenericCache[string, *models.AuthProcess]
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := database.New(path, types.PROFILE_ISBE_PRO)
	if err != nil {
		t.Fatalf("creating database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	raw, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { raw.Close() })

	authprocCache := cache.NewGeneric[string, *models.AuthProcess](time.Minute)
	ssoCache := cache.NewGeneric[string, *models.SSOSession](time.Minute)
	s, err := New(db, authprocCache, ssoCache, &Config{
		Profile:                 types.PROFILE_ISBE_PRO,
		CertAuthURL:             "https://certauth.test",
		CertificateBackEndpoint: "/certificate-back",
	})
	if err != nil {
		t.Fatalf("creating CertSec: %v", err)
	}
	return &testEnv{s: s, db: db, raw: raw, cache: authprocCache}
}

func (e *testEnv) approve(t *testing.T, fingerprint, orgID string) {
	t.Helper()
	if _, err := e.raw.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, ?)`, fingerprint, orgID); err != nil {
		t.Fatalf("approving certificate: %v", err)
	}
}

// authenticate presents the certificate in the given header to /auth with a new authentication
// process and returns it as CertAuth will find it. The process starts with a previous certificate
// accepted and completed and a previous error, to check that CertSec always resets them.
func (e *testEnv) authenticate(t *testing.T, header, b64der string) *models.AuthProcess {
	t.Helper()
	authProcess := &models.AuthProcess{Code: fmt.Sprintf("code-%d", time.Now().UnixNano())}
	previous := &models.CertificateData{}
	authProcess.SetCertificate(previous)
	authProcess.AcceptCertificate(previous)
	authProcess.CompleteCertificateFlow(previous, "", "")
	authProcess.FailCertificateAttempt(errors.New("previous attempt"))
	e.cache.Set(authProcess.Code, authProcess, time.Minute)
	return e.present(t, authProcess, header, b64der)
}

// present presents the certificate to /auth for an existing authentication process.
func (e *testEnv) present(t *testing.T, authProcess *models.AuthProcess, header, b64der string) *models.AuthProcess {
	t.Helper()
	req := httptest.NewRequest("GET", "/auth?code="+authProcess.Code, nil)
	req.Header.Set(header, b64der)
	resp, err := e.s.app.Test(req, -1)
	if err != nil {
		t.Fatalf("calling /auth: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	if _, err := authProcess.CertificateResult(); authProcess.AcceptedCertificate() != nil || authProcess.Completed() != nil ||
		(err != nil && strings.Contains(err.Error(), "previous attempt")) {
		t.Fatalf("CertSec must reset the previous certificate, error and completion")
	}
	return authProcess
}

// result summarises what CertSec handed over: the rejection, or the organization and whether
// the certificate is manually approved.
func result(p *models.AuthProcess) string {
	cd, err := p.CertificateResult()
	if err != nil {
		return "rejected: " + err.Error()
	}
	if cd.EIDASCertificate {
		return "marked as eIDAS"
	}
	return fmt.Sprintf("org=%s manual=%v", cd.OrganizationID, cd.ManuallyApproved)
}

const header = stdCertHeader

func TestCertificateAuthentication(t *testing.T) {
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		cert     testCert
		approved string // organization identifier of the approval; empty: not approved
		want     string // prefix of result()
	}{
		{"approved without organizationIdentifier nor serialNumber", testCert{}, "NTRNL-12345678", "org=NTRNL-12345678 manual=true"},
		{"approved with its own organizationIdentifier", testCert{orgID: "NTRNL-12345678"}, "NTRNL-12345678", "org=NTRNL-12345678 manual=true"},
		{"approved with a serialNumber", testCert{serial: "IDCNL-1234"}, "NTRNL-12345678", "org=NTRNL-12345678 manual=true"},
		{"approved for another organization", testCert{orgID: "VATES-B00000000"}, "NTRNL-12345678", "rejected: " /* does not match */},
		{"approved but expired", testCert{notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)}, "NTRNL-12345678", "rejected: "},
		{"approved but not yet valid", testCert{notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(48 * time.Hour)}, "NTRNL-12345678", "rejected: "},
		{"approved with a weak key", testCert{key: weakKey}, "NTRNL-12345678", "rejected: "},
		{"approved without clientAuth", testCert{extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, "NTRNL-12345678", "rejected: "},
		{"approved CA certificate", testCert{isCA: true}, "NTRNL-12345678", "rejected: "},
		// Not approved: the usual flow, CertAuth validates it with EU DSS
		{"not approved with organizationIdentifier", testCert{orgID: "VATES-B00000000"}, "", "org=VATES-B00000000 manual=false"},
		{"not approved without organizationIdentifier nor serialNumber", testCert{}, "", "rejected: "},
	}
	wantErr := map[string]string{
		"approved for another organization":                            "does not match the approved",
		"approved but expired":                                         "expired",
		"approved but not yet valid":                                   "not yet valid",
		"approved with a weak key":                                     "RSA key of 1024 bits",
		"approved without clientAuth":                                  "does not include clientAuth",
		"approved CA certificate":                                      "CA certificate",
		"not approved without organizationIdentifier nor serialNumber": "Both organizationIdentifier and serialNumber are empty",
	}
	e := newTestEnv(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cert, fp := tc.cert.build(t)
			if tc.approved != "" {
				e.approve(t, fp, tc.approved)
			}
			got := result(e.authenticate(t, header, cert))
			if !strings.HasPrefix(got, tc.want) || !strings.Contains(got, wantErr[tc.name]) {
				t.Fatalf("got %q, want %q %q", got, tc.want, wantErr[tc.name])
			}
		})
	}
}

func TestWithdrawnApprovalCannotAuthenticateAgain(t *testing.T) {
	e := newTestEnv(t)
	cert, fp := testCert{}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	if got := result(e.authenticate(t, header, cert)); got != "org=NTRNL-12345678 manual=true" {
		t.Fatalf("approved: %s", got)
	}
	if _, err := e.raw.Exec(`DELETE FROM approved_certificates WHERE certificate_sha256 = ?`, fp); err != nil {
		t.Fatal(err)
	}
	if got := result(e.authenticate(t, header, cert)); !strings.HasPrefix(got, "rejected: ") {
		t.Fatalf("withdrawn: %s", got)
	}
}

func TestRetryAfterARejectedCertificate(t *testing.T) {
	e := newTestEnv(t)
	bad, _ := testCert{}.build(t)
	good, fp := testCert{}.build(t)
	e.approve(t, fp, "NTRNL-12345678")

	p := e.authenticate(t, header, bad)
	if got := result(p); !strings.HasPrefix(got, "rejected: ") {
		t.Fatalf("first attempt: %s", got)
	}
	if got := result(e.present(t, p, header, good)); got != "org=NTRNL-12345678 manual=true" {
		t.Fatalf("retry with the same code: %s", got)
	}
}

func TestWhitelistErrorRejects(t *testing.T) {
	e := newTestEnv(t)
	cert, _ := testCert{orgID: "VATES-B00000000"}.build(t)
	e.db.Close()
	p := e.authenticate(t, header, cert)
	if cd, _ := p.CertificateResult(); !strings.Contains(result(p), "checking approved certificate") || cd != nil {
		t.Fatalf("got %q", result(p))
	}
}

func TestOnlyTheStandardHeader(t *testing.T) {
	e := newTestEnv(t)
	cert, fp := testCert{}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	if got := result(e.authenticate(t, "X-Amzn-Mtls-Clientcert", cert)); !strings.Contains(got, "No certificate provided in "+header) {
		t.Fatalf("got %q", got)
	}
}

func TestAdminPages(t *testing.T) {
	e := newTestEnv(t)
	approved, fp := testCert{serial: "IDCNL-1234"}.build(t)
	e.approve(t, fp, adminIssuerOrganizationIdentifiers[0]) // even approved for the organization of the administrators
	noIdentifiers, _ := testCert{issuerOrgID: adminIssuerOrganizationIdentifiers[0]}.build(t)

	for cert, want := range map[string]string{
		approved:      "is invalid",
		noIdentifiers: "Both organizationIdentifier and serialNumber are empty",
	} {
		req := httptest.NewRequest("GET", "/admin/registrations", nil)
		req.Header.Set(header, cert)
		resp, err := e.s.app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), want) {
			t.Fatalf("admin pages: want %q: %s", want, body)
		}
	}
}
