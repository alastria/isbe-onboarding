package certsec

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/certpolicy/certpolicytest"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/types"
)

type testEnv struct {
	t      *testing.T
	server *CertSecServer
	cache  *cache.GenericCache[string, *models.AuthProcess]
	dbPath string
	db     *database.Database
}

func newTestEnv(t *testing.T, cfg Config) *testEnv {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "certsec.db")
	db, err := database.New(dbPath, types.PROFILE_ISBE_PRO)
	if err != nil {
		t.Fatalf("database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	authproc := cache.NewGeneric[string, *models.AuthProcess](time.Minute)
	sso := cache.NewGeneric[string, *models.SSOSession](time.Minute)
	if cfg.Profile == "" {
		cfg.Profile = types.PROFILE_ISBE_PRO
	}
	cfg.CertAuthURL = "https://certauth.test"
	cfg.CertificateBackEndpoint = "/certificate-back"
	s, err := New(db, authproc, sso, &cfg)
	if err != nil {
		t.Fatalf("certsec.New: %v", err)
	}
	return &testEnv{t: t, server: s, cache: authproc, dbPath: dbPath, db: db}
}

// approve inserts a whitelist entry the way operators do it: with SQL on the database file.
func (e *testEnv) approve(cert *x509.Certificate, orgID string) {
	e.t.Helper()
	conn, err := sql.Open("sqlite3", e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier, comment) VALUES (?, ?, 'test')`,
		models.CertificateFingerprint(cert), orgID); err != nil {
		e.t.Fatalf("approving certificate: %v", err)
	}
}

// auth runs GET /auth for a fresh authentication process with the given headers and returns
// the process after the request.
func (e *testEnv) auth(headers map[string]string) (*models.AuthProcess, *http.Response) {
	e.t.Helper()
	code := "code-" + strings.ReplaceAll(e.t.Name(), "/", "-")
	ap := &models.AuthProcess{Code: code}
	e.cache.Set(code, ap, time.Minute)
	req := httptest.NewRequest(http.MethodGet, "/auth?code="+url.QueryEscape(code), nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := e.server.app.Test(req, -1)
	if err != nil {
		e.t.Fatalf("request: %v", err)
	}
	return ap, resp
}

func expectAccepted(t *testing.T, ap *models.AuthProcess, resp *http.Response, wantOrgID string) {
	t.Helper()
	if ap.ErrorInProcess != nil {
		t.Fatalf("unexpected rejection: %v", ap.ErrorInProcess)
	}
	if loc := resp.Header.Get("Location"); strings.Contains(loc, "error=") {
		t.Fatalf("unexpected error redirect: %s", loc)
	}
	if ap.CertificateData == nil {
		t.Fatal("no certificate data propagated")
	}
	if ap.CertificateData.OrganizationID != wantOrgID || ap.CertificateData.Subject.OrganizationIdentifier != wantOrgID {
		t.Fatalf("organization identifier: got %q / %q, want %q",
			ap.CertificateData.OrganizationID, ap.CertificateData.Subject.OrganizationIdentifier, wantOrgID)
	}
	if ap.CertificateData.EIDASCertificate {
		t.Fatal("CertSec must never mark a certificate as eIDAS")
	}
}

// expectReason checks that the rejection carries the reason CertAuth uses to choose the message.
func expectReason(t *testing.T, ap *models.AuthProcess, reason error) {
	t.Helper()
	if !errors.Is(ap.ErrorInProcess, reason) {
		t.Fatalf("expected reason %v, got %v", reason, ap.ErrorInProcess)
	}
}

func expectRejected(t *testing.T, ap *models.AuthProcess, resp *http.Response, wantMsg string) {
	t.Helper()
	if ap.ErrorInProcess == nil {
		t.Fatalf("expected rejection, certificate data: %+v", ap.CertificateData)
	}
	if ap.CertificateData != nil {
		t.Fatal("rejected certificate must not propagate certificate data")
	}
	if !strings.Contains(resp.Header.Get("Location"), "error=true") {
		t.Fatalf("expected an error redirect, got %q", resp.Header.Get("Location"))
	}
	if wantMsg != "" && !strings.Contains(ap.ErrorInProcess.Error(), wantMsg) {
		t.Fatalf("expected error containing %q, got %v", wantMsg, ap.ErrorInProcess)
	}
}

func hdr(l *certpolicytest.Leaf) map[string]string {
	return map[string]string{stdCertHeader: l.B64DER()}
}

func TestHandleCertificateAuth(t *testing.T) {
	p := certpolicytest.New(t, "certsec")
	org := func(cn string) certpolicytest.LeafOptions {
		return certpolicytest.LeafOptions{Subject: certpolicytest.Name(cn, cn, "GB", "London")}
	}

	eidasOrg := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("REP", "ORG SA", "ES", "Madrid",
		certpolicytest.OrganizationIdentifier("VATES-A00000000"), certpolicytest.SubjectSerialNumber("IDCES-00000000T"))})
	personal := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("PERSON", "ORG", "NL", "Amsterdam",
		certpolicytest.SubjectSerialNumber("PNONL-000000"))})
	approved := p.Intermediate.Issue(org("APPROVED ORG"))
	unlisted := p.Intermediate.Issue(org("UNLISTED ORG"))
	sameSubject := p.Intermediate.Issue(org("APPROVED ORG")) // identical Subject, different key and fingerprint
	expired := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: org("EXPIRED").Subject,
		NotBefore: p.Now.Add(-48 * time.Hour), NotAfter: p.Now.Add(-time.Hour)})
	notYetValid := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: org("FUTURE").Subject,
		NotBefore: p.Now.Add(time.Hour), NotAfter: p.Now.Add(48 * time.Hour)})

	e := newTestEnv(t, Config{})
	e.approve(approved.Cert, "NTRGB-00000001")
	e.approve(personal.Cert, "NTRNL-00000002")
	e.approve(expired.Cert, "NTRGB-00000003")
	e.approve(notYetValid.Cert, "NTRGB-00000004")
	// A whitelist entry for a certificate that already has its own organizationIdentifier is ignored
	e.approve(eidasOrg.Cert, "NTRGB-99999999")

	t.Run("eIDAS organizational certificate keeps its own identifier", func(t *testing.T) {
		ap, resp := e.auth(hdr(eidasOrg))
		expectAccepted(t, ap, resp, "VATES-A00000000")
	})
	t.Run("approved personal certificate with Subject serialNumber gets the approved identifier", func(t *testing.T) {
		ap, resp := e.auth(hdr(personal))
		expectAccepted(t, ap, resp, "NTRNL-00000002")
	})
	t.Run("approved certificate without identifiers gets the approved identifier", func(t *testing.T) {
		ap, resp := e.auth(hdr(approved))
		expectAccepted(t, ap, resp, "NTRGB-00000001")
		if ap.CertificateData.CertificateType != "organizational" {
			t.Errorf("certificate type %q", ap.CertificateData.CertificateType)
		}
	})
	t.Run("approved certificate in PEM (URL-encoded, as the AWS ALB header)", func(t *testing.T) {
		pemCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: approved.Cert.Raw}))
		ap, resp := e.auth(map[string]string{kubeCertHeader: url.PathEscape(pemCert)})
		expectAccepted(t, ap, resp, "NTRGB-00000001")
	})
	t.Run("certificate without identifiers and not approved is rejected", func(t *testing.T) {
		ap, resp := e.auth(hdr(unlisted))
		expectRejected(t, ap, resp, "has not been approved")
		expectReason(t, ap, models.ErrCertificateNotApproved)
	})
	t.Run("same Subject with a different fingerprint is rejected", func(t *testing.T) {
		ap, resp := e.auth(hdr(sameSubject))
		expectRejected(t, ap, resp, "has not been approved")
		expectReason(t, ap, models.ErrCertificateNotApproved)
	})
	t.Run("approved but expired is rejected", func(t *testing.T) {
		ap, resp := e.auth(hdr(expired))
		expectRejected(t, ap, resp, "expired")
		expectReason(t, ap, models.ErrCertificateNotValidNow)
	})
	t.Run("approved but not yet valid is rejected", func(t *testing.T) {
		ap, resp := e.auth(hdr(notYetValid))
		expectRejected(t, ap, resp, "not yet valid")
		expectReason(t, ap, models.ErrCertificateNotValidNow)
	})
	t.Run("missing certificate is rejected", func(t *testing.T) {
		ap, resp := e.auth(nil)
		expectRejected(t, ap, resp, "No certificate provided")
		expectReason(t, ap, models.ErrCertificateUnreadable)
	})
	t.Run("malformed certificate is rejected", func(t *testing.T) {
		ap, resp := e.auth(map[string]string{stdCertHeader: strings.Repeat("A", 200)})
		expectRejected(t, ap, resp, "Failed to parse certificate")
		expectReason(t, ap, models.ErrCertificateUnreadable)
	})
	t.Run("truncated certificate is rejected", func(t *testing.T) {
		ap, resp := e.auth(map[string]string{stdCertHeader: approved.B64DER()[:50]})
		expectRejected(t, ap, resp, "too short")
		expectReason(t, ap, models.ErrCertificateUnreadable)
	})
	t.Run("invalid authorization code is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth?code=unknown", nil)
		req.Header.Set(stdCertHeader, approved.B64DER())
		resp, _ := e.server.app.Test(req, -1)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
}

func TestHandleCertificateAuthDatabaseFailure(t *testing.T) {
	p := certpolicytest.New(t, "dbfail")
	approved := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("APPROVED", "APPROVED", "GB", "London")})
	e := newTestEnv(t, Config{})
	e.approve(approved.Cert, "NTRGB-00000001")
	e.db.Close() // the whitelist lookup fails

	ap, resp := e.auth(hdr(approved))
	expectRejected(t, ap, resp, "checking approved certificate")
}

func TestAdminAuthenticationIgnoresWhitelist(t *testing.T) {
	p := certpolicytest.New(t, "admin")
	// A whitelisted certificate, even when approved for an organization that is an admin issuer
	approved := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("APPROVED", "APPROVED", "GB", "London")})
	// A certificate with a Subject serialNumber that is not an administrator
	nonAdmin := p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("PERSON", "ORG", "ES", "Madrid",
		certpolicytest.SubjectSerialNumber("IDCES-00000000T"))})
	e := newTestEnv(t, Config{})
	e.approve(approved.Cert, adminIssuerOrganizationIdentifiers[0])
	e.approve(nonAdmin.Cert, adminIssuerOrganizationIdentifiers[0])

	for name, leaf := range map[string]*certpolicytest.Leaf{"whitelisted without identifiers": approved, "whitelisted non-admin": nonAdmin} {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{"/admin", "/admin/registrations", "/admin/contract?orgid=X"} {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set(stdCertHeader, leaf.B64DER())
				resp, err := e.server.app.Test(req, -1)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := io.ReadAll(resp.Body)
				body := string(raw)
				if !strings.Contains(body, "is invalid") && !strings.Contains(body, "are empty") {
					t.Fatalf("%s: expected an authentication error, got: %.300s", path, body)
				}
			}
		})
	}

	t.Run("isAdmin is not granted by an approved identifier", func(t *testing.T) {
		_, issuer, subject, err := x509util.ParseEIDASCertB64Der(approved.B64DER())
		if err != nil {
			t.Fatal(err)
		}
		subject.OrganizationIdentifier = adminIssuerOrganizationIdentifiers[0] // what the whitelist would assign
		if isAdmin(issuer, subject) {
			t.Fatal("an organization identifier assigned to the Subject must not grant admin")
		}
	})
}
