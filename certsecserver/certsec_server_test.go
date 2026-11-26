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

var allProfiles = []types.Profile{types.PROFILE_LOCAL, types.PROFILE_ISBE_DEV, types.PROFILE_ISBE_PRE, types.PROFILE_ISBE_PRO}

// testCert describes a self-signed client certificate for the tests.
type testCert struct {
	orgID, serial       string
	notBefore, notAfter time.Time
	key                 crypto.Signer
	extKeyUsage         []x509.ExtKeyUsage
	isCA                bool
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
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

func newTestEnv(t *testing.T, profile types.Profile, manualApproval bool, header string) *testEnv {
	t.Helper()
	t.Chdir("..") // the local profile reads the templates from certsecserver/views

	path := filepath.Join(t.TempDir(), "test.db")
	db, err := database.New(path, profile)
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
		Profile:                 profile,
		CertAuthURL:             "https://certauth.test",
		CertificateBackEndpoint: "/certificate-back",
		ManualApprovalEnabled:   manualApproval,
		ClientCertHeader:        header,
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

func (e *testEnv) withdraw(t *testing.T, fingerprint string) {
	t.Helper()
	if _, err := e.raw.Exec(`DELETE FROM approved_certificates WHERE certificate_sha256 = ?`, fingerprint); err != nil {
		t.Fatalf("withdrawing certificate: %v", err)
	}
}

// authenticate presents the certificate in the given header to /auth and returns the
// authentication process as CertAuth will find it. The process starts as already accepted
// and completed, to check that CertSec always resets it.
func (e *testEnv) authenticate(t *testing.T, header, b64der string) *models.AuthProcess {
	t.Helper()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	authProcess := &models.AuthProcess{Code: code, AcceptedCertificate: &models.CertificateData{}, CertificateFlowCompleted: true}
	e.cache.Set(code, authProcess, time.Minute)

	req := httptest.NewRequest("GET", "/auth?code="+code, nil)
	if header != "" {
		req.Header.Set(header, b64der)
	}
	resp, err := e.s.app.Test(req, -1)
	if err != nil {
		t.Fatalf("calling /auth: %v", err)
	}
	if resp.StatusCode != 302 {
		t.Fatalf("status %d, want 302", resp.StatusCode)
	}
	if authProcess.AcceptedCertificate != nil || authProcess.CertificateFlowCompleted {
		t.Fatalf("CertSec must reset the acceptance of the previous certificate")
	}
	if authProcess.ErrorInProcess == nil && authProcess.CertificateData == nil {
		t.Fatalf("neither certificate data nor error")
	}
	return authProcess
}

func assertRejected(t *testing.T, p *models.AuthProcess, contains string) {
	t.Helper()
	if p.ErrorInProcess == nil {
		t.Fatalf("certificate accepted, want rejection containing %q", contains)
	}
	if !strings.Contains(p.ErrorInProcess.Error(), contains) {
		t.Fatalf("error %q does not contain %q", p.ErrorInProcess, contains)
	}
}

func assertManuallyApproved(t *testing.T, p *models.AuthProcess, orgID string) {
	t.Helper()
	if p.ErrorInProcess != nil {
		t.Fatalf("certificate rejected: %v", p.ErrorInProcess)
	}
	cd := p.CertificateData
	if !cd.ManuallyApproved || cd.EIDASCertificate || cd.OrganizationID != orgID || cd.Subject.OrganizationIdentifier != orgID || cd.CertificateType != "organizational" {
		t.Fatalf("unexpected certificate data: manually_approved=%v eidas=%v org=%q type=%q", cd.ManuallyApproved, cd.EIDASCertificate, cd.OrganizationID, cd.CertificateType)
	}
}

const header = stdCertHeader

func TestApprovedNonEIDASCertificateAcceptedInEveryProfile(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			e := newTestEnv(t, profile, true, header)
			// An organizational certificate without organizationIdentifier nor serialNumber
			cert, fp := testCert{}.build(t)
			e.approve(t, fp, "NTRNL-12345678")
			assertManuallyApproved(t, e.authenticate(t, header, cert), "NTRNL-12345678")
		})
	}
}

func TestApprovedCertificateWithItsOwnOrganizationIdentifier(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	cert, fp := testCert{orgID: "NTRNL-12345678"}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	assertManuallyApproved(t, e.authenticate(t, header, cert), "NTRNL-12345678")
}

func TestApprovedCertificateForAnotherOrganizationRejected(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	cert, fp := testCert{orgID: "VATES-B00000000"}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	assertRejected(t, e.authenticate(t, header, cert), "does not match the approved")
}

func TestApprovedCertificateOutsideValidityRejected(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	expired, fp1 := testCert{notBefore: time.Now().Add(-48 * time.Hour), notAfter: time.Now().Add(-time.Hour)}.build(t)
	future, fp2 := testCert{notBefore: time.Now().Add(time.Hour), notAfter: time.Now().Add(48 * time.Hour)}.build(t)
	e.approve(t, fp1, "NTRNL-12345678")
	e.approve(t, fp2, "NTRNL-12345678")
	assertRejected(t, e.authenticate(t, header, expired), "expired")
	assertRejected(t, e.authenticate(t, header, future), "not yet valid")
}

func TestApprovedCertificateMinimumChecks(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	weakKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]testCert{
		"RSA key of 1024 bits":        {key: weakKey},
		"does not include clientAuth": {extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		"CA certificate":              {isCA: true},
	}
	for want, tc := range cases {
		cert, fp := tc.build(t)
		e.approve(t, fp, "NTRNL-12345678")
		assertRejected(t, e.authenticate(t, header, cert), want)
	}
}

func TestNotApprovedCertificateKeepsTheUsualFlow(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)

	// An eIDAS-like certificate goes on to CertAuth, which validates it with EU DSS
	cert, _ := testCert{orgID: "VATES-B00000000"}.build(t)
	p := e.authenticate(t, header, cert)
	if p.ErrorInProcess != nil || p.CertificateData.ManuallyApproved || p.CertificateData.OrganizationID != "VATES-B00000000" {
		t.Fatalf("unexpected result: err=%v data=%+v", p.ErrorInProcess, p.CertificateData)
	}

	// Without organizationIdentifier nor serialNumber it is rejected, as before
	cert, _ = testCert{}.build(t)
	assertRejected(t, e.authenticate(t, header, cert), "Both organizationIdentifier and serialNumber are empty")
}

func TestWithdrawnApprovalCannotAuthenticateAgain(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	cert, fp := testCert{}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	assertManuallyApproved(t, e.authenticate(t, header, cert), "NTRNL-12345678")

	e.withdraw(t, fp)
	assertRejected(t, e.authenticate(t, header, cert), "Both organizationIdentifier and serialNumber are empty")

	// A withdrawn certificate with a serialNumber is no longer approved: CertAuth sees a personal certificate
	cert, fp = testCert{serial: "IDCNL-1234"}.build(t)
	e.approve(t, fp, "NTRNL-12345678")
	e.withdraw(t, fp)
	p := e.authenticate(t, header, cert)
	if p.ErrorInProcess != nil || p.CertificateData.ManuallyApproved || p.CertificateData.OrganizationID != "" {
		t.Fatalf("unexpected result: err=%v data=%+v", p.ErrorInProcess, p.CertificateData)
	}
}

func TestWhitelistErrorRejects(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("enabled=%v", enabled), func(t *testing.T) {
			e := newTestEnv(t, types.PROFILE_ISBE_PRO, enabled, header)
			cert, _ := testCert{}.build(t)
			e.db.Close()
			p := e.authenticate(t, header, cert)
			assertRejected(t, p, "checking approved certificate")
			if p.CertificateData != nil {
				t.Fatalf("certificate data set after a whitelist error")
			}
		})
	}
}

func TestPolicyDisabledKeepsOriginalBehaviour(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			e := newTestEnv(t, profile, false, "")

			// An approved certificate without organizationIdentifier nor serialNumber: rejected, as before
			cert, fp := testCert{}.build(t)
			e.approve(t, fp, "NTRNL-12345678")
			assertRejected(t, e.authenticate(t, header, cert), "Both organizationIdentifier and serialNumber are empty")

			// An approved certificate with serialNumber gets the organization identifier, but it is not
			// manually approved: CertAuth validates it with EU DSS, as before
			cert, fp = testCert{serial: "IDCNL-1234"}.build(t)
			e.approve(t, fp, "NTRNL-12345678")
			p := e.authenticate(t, header, cert)
			if p.ErrorInProcess != nil || p.CertificateData.ManuallyApproved || p.CertificateData.OrganizationID != "NTRNL-12345678" {
				t.Fatalf("unexpected result: err=%v data=%+v", p.ErrorInProcess, p.CertificateData)
			}

			// Certificates with organizationIdentifier are not looked up
			cert, fp = testCert{orgID: "VATES-B00000000"}.build(t)
			e.approve(t, fp, "NTRNL-12345678")
			p = e.authenticate(t, header, cert)
			if p.ErrorInProcess != nil || p.CertificateData.ManuallyApproved || p.CertificateData.OrganizationID != "VATES-B00000000" {
				t.Fatalf("unexpected result: err=%v data=%+v", p.ErrorInProcess, p.CertificateData)
			}

			// Both headers are read, as before
			p = e.authenticate(t, kubeCertHeader, cert)
			if p.ErrorInProcess != nil {
				t.Fatalf("certificate in %s rejected: %v", kubeCertHeader, p.ErrorInProcess)
			}
		})
	}
}

func TestConfiguredHeaderOnly(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	cert, fp := testCert{}.build(t)
	e.approve(t, fp, "NTRNL-12345678")

	// No fallback to another header
	assertRejected(t, e.authenticate(t, kubeCertHeader, cert), "No certificate provided in "+header)
	assertRejected(t, e.authenticate(t, "", cert), "No certificate provided in "+header)
	assertManuallyApproved(t, e.authenticate(t, header, cert), "NTRNL-12345678")
}

func TestApprovedCertificateIsNotAdmin(t *testing.T) {
	e := newTestEnv(t, types.PROFILE_ISBE_PRO, true, header)
	cert, fp := testCert{serial: "IDCNL-1234"}.build(t)
	e.approve(t, fp, "VATES-G87936159") // even approved for the organization of the administrators

	req := httptest.NewRequest("GET", "/admin/registrations", nil)
	req.Header.Set(header, cert)
	resp, err := e.s.app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "is invalid") {
		t.Fatalf("approved certificate reached the admin pages: %s", body)
	}
}
