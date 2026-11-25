package certauth

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/certpolicy"
	"github.com/alastria/isbe-onboarding/internal/certpolicy/certpolicytest"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/jwtservice"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/tmfservice"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/types"
)

var allProfiles = []types.Profile{types.PROFILE_LOCAL, types.PROFILE_ISBE_DEV, types.PROFILE_ISBE_PRE, types.PROFILE_ISBE_PRO}

// fakeEUDSS stands in for the EU DSS validation boundary: certificates registered as qualified
// pass; any other certificate fails validation, or the service is down.
type fakeEUDSS struct {
	qualified map[string]bool
	down      bool
}

func (f *fakeEUDSS) verify(der string, _ string) ([]byte, error, error) {
	if f.down {
		return nil, errors.New("EU DSS unavailable"), nil
	}
	if f.qualified[der] {
		return []byte(`{}`), nil, nil
	}
	return nil, nil, errors.New("certificate is not eIDAS compliant")
}

type trustEnv struct {
	t      *testing.T
	s      *CertAuthServer
	dss    *fakeEUDSS
	dbPath string
	db     *database.Database
	pki    *certpolicytest.PKI
}

// newTrustEnv builds a CertAuth server for the given profile with an isolated database, a fake
// EU DSS and, when withPolicy, the manual approval policy trusting only the test PKI.
func newTrustEnv(t *testing.T, profile types.Profile, withPolicy bool) *trustEnv {
	t.Helper()
	p := certpolicytest.New(t, "certauth")
	dbPath := filepath.Join(t.TempDir(), "certauth.db")
	db, err := database.New(dbPath, profile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	render, err := html.NewRendererFiber(false, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		t.Fatal(err)
	}
	dss := &fakeEUDSS{qualified: map[string]bool{}}
	s := &CertAuthServer{
		profile:       profile,
		db:            db,
		htmlRender:    render,
		verifyEIDAS:   dss.verify,
		euDSSURL:      "http://eudss.invalid",
		authprocCache: cache.NewGeneric[string, *models.AuthProcess](time.Minute),
		ssoCache:      cache.NewGeneric[string, *models.SSOSession](time.Minute),
		httpServer:    fiber.New(),
		// Never reached in these tests: a real call would fail instead of touching a real service
		managementURL: "http://management.invalid",
	}
	if withPolicy {
		v, err := certpolicy.NewValidator([]*x509.Certificate{p.Root.Cert, p.Intermediate.Cert},
			certpolicy.WithClock(func() time.Time { return p.Now }))
		if err != nil {
			t.Fatal(err)
		}
		s.manualApproval = v
	}
	s.registerCertificateHandlers()
	return &trustEnv{t: t, s: s, dss: dss, dbPath: dbPath, db: db, pki: p}
}

func (e *trustEnv) approve(cert *x509.Certificate, orgID string) {
	e.t.Helper()
	conn, err := sql.Open("sqlite3", e.dbPath)
	if err != nil {
		e.t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, ?)`,
		models.CertificateFingerprint(cert), orgID); err != nil {
		e.t.Fatal(err)
	}
}

// certData builds the CertificateData exactly as CertSec does, including the identifier
// assigned from the whitelist (assignedOrgID, empty for none).
func certData(t *testing.T, leaf *certpolicytest.Leaf, assignedOrgID string) *models.CertificateData {
	t.Helper()
	cert, issuer, subject, err := x509util.ParseEIDASCertB64Der(leaf.B64DER())
	if err != nil {
		t.Fatal(err)
	}
	if subject.OrganizationIdentifier == "" && assignedOrgID != "" {
		subject.OrganizationIdentifier = assignedOrgID
	}
	certType := "personal"
	if subject.OrganizationIdentifier != "" {
		certType = "organizational"
	}
	return &models.CertificateData{
		Subject: subject, Issuer: issuer, ValidFrom: cert.NotBefore, ValidTo: cert.NotAfter,
		OrganizationID: subject.OrganizationIdentifier, CertificateType: certType,
		Certificate: cert, CertificateDER: leaf.B64DER(),
	}
}

func orgLeaf(p *certpolicytest.PKI, ca *certpolicytest.CA, cn string) *certpolicytest.Leaf {
	return ca.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name(cn, cn, "GB", "London")})
}

// TestEvaluateCertificateTrust runs the acceptance matrix in every profile, with controlled
// trust anchors, an isolated database, a fake EU DSS and real CRLs over HTTP.
func TestEvaluateCertificateTrust(t *testing.T) {
	type scenario struct {
		name  string
		setup func(e *trustEnv) *models.CertificateData
		// expected decision in production and in the other profiles
		pro, nonPro certificateTrust
		wantErr     error // expected manual policy error (errors.Is), if any
	}
	const approvedID = "NTRGB-00000001"

	scenarios := []scenario{
		{
			name: "existing eIDAS organizational certificate",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("REP", "ORG SA", "ES", "Madrid",
					certpolicytest.OrganizationIdentifier("VATES-A00000000"))})
				e.dss.qualified[l.B64DER()] = true
				return certData(e.t, l, "")
			},
			pro: trustEIDAS, nonPro: trustEIDAS,
		},
		{
			name: "existing qualified personal certificate with whitelist approval",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("PERSON", "ORG BV", "NL", "Amsterdam",
					certpolicytest.SubjectSerialNumber("PNONL-000000"))})
				e.dss.qualified[l.B64DER()] = true
				e.approve(l.Cert, "NTRNL-00000002")
				return certData(e.t, l, "NTRNL-00000002")
			},
			pro: trustEIDAS, nonPro: trustEIDAS,
		},
		{
			name: "non-eIDAS organizational certificate without identifiers, whitelisted and trusted",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustManualApproval, nonPro: trustManualApproval,
		},
		{
			name: "whitelisted and trusted while EU DSS is down",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
				e.approve(l.Cert, approvedID)
				e.dss.down = true
				return certData(e.t, l, approvedID)
			},
			pro: trustManualApproval, nonPro: trustManualApproval,
		},
		{
			name: "whitelisted personal-serial certificate that is not eIDAS",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("PERSON", "ORG", "GB", "London",
					certpolicytest.SubjectSerialNumber("LAB-PERSON-0001"))})
				e.approve(l.Cert, "NTRGB-00000005")
				return certData(e.t, l, "NTRGB-00000005")
			},
			pro: trustManualApproval, nonPro: trustManualApproval,
		},
		{
			name: "whitelisted but revoked",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "REVOKED")
				e.pki.Intermediate.Revoke(l.Cert)
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrRevoked,
		},
		{
			name: "whitelisted but expired",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("EXPIRED", "EXPIRED", "GB", "London"),
					NotBefore: e.pki.Now.Add(-48 * time.Hour), NotAfter: e.pki.Now.Add(-time.Hour)})
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrInvalidCertificate,
		},
		{
			name: "whitelisted but not yet valid",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("FUTURE", "FUTURE", "GB", "London"),
					NotBefore: e.pki.Now.Add(time.Hour), NotAfter: e.pki.Now.Add(48 * time.Hour)})
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrInvalidCertificate,
		},
		{
			name: "whitelisted with an untrusted chain (unexpected issuer)",
			setup: func(e *trustEnv) *models.CertificateData {
				other := certpolicytest.New(e.t, "other")
				l := orgLeaf(other, other.Intermediate, "UNTRUSTED")
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrUntrusted,
		},
		{
			name: "whitelisted without clientAuth usage",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("SERVER", "SERVER", "GB", "London"),
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrUnsuitable,
		},
		{
			name: "whitelisted, revocation status unavailable",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
				e.pki.Intermediate.CRLMode = certpolicytest.CRLUnavailable
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, approvedID)
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: certpolicy.ErrRevocationUnavailable,
		},
		{
			name: "approved fingerprint but organization identifier changed after CertSec",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
				e.approve(l.Cert, approvedID)
				return certData(e.t, l, "NTRGB-99999999")
			},
			pro: trustRejected, nonPro: trustUnverified,
		},
		{
			name: "certificate with its own organizationIdentifier is never on the manual path",
			setup: func(e *trustEnv) *models.CertificateData {
				l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("SEAL", "ORG", "ES", "Madrid",
					certpolicytest.OrganizationIdentifier("VATES-B00000000"))})
				e.approve(l.Cert, "VATES-B00000000")
				return certData(e.t, l, "")
			},
			pro: trustRejected, nonPro: trustUnverified,
		},
		{
			name: "whitelist lookup failure",
			setup: func(e *trustEnv) *models.CertificateData {
				l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
				e.approve(l.Cert, approvedID)
				cd := certData(e.t, l, approvedID)
				e.db.Close()
				return cd
			},
			pro: trustRejected, nonPro: trustRejected, wantErr: errWhitelistUnavailable,
		},
	}

	for _, profile := range allProfiles {
		for _, sc := range scenarios {
			t.Run(string(profile)+"/"+sc.name, func(t *testing.T) {
				e := newTrustEnv(t, profile, true)
				cd := sc.setup(e)
				d := e.s.evaluateCertificateTrust(context.Background(), cd)
				want := sc.nonPro
				if profile == types.PROFILE_ISBE_PRO {
					want = sc.pro
				}
				if d.trust != want {
					t.Fatalf("trust %s, want %s (manual policy error: %v)", d.trust, want, d.manualPolicyError)
				}
				if sc.wantErr != nil && !errors.Is(d.manualPolicyError, sc.wantErr) {
					t.Fatalf("manual policy error %v, want %v", d.manualPolicyError, sc.wantErr)
				}
			})
		}
	}
}

// TestManualApprovalWithoutPolicy: without the alternative policy configured, production
// rejects whitelisted non-eIDAS certificates; other profiles keep the previous behaviour.
func TestManualApprovalWithoutPolicy(t *testing.T) {
	for _, profile := range allProfiles {
		t.Run(string(profile), func(t *testing.T) {
			e := newTrustEnv(t, profile, false)
			l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
			e.approve(l.Cert, "NTRGB-00000001")
			d := e.s.evaluateCertificateTrust(context.Background(), certData(t, l, "NTRGB-00000001"))
			if profile == types.PROFILE_ISBE_PRO {
				if d.trust != trustRejected || !errors.Is(d.manualPolicyError, errManualPolicyNotConfigured) {
					t.Fatalf("got %s / %v", d.trust, d.manualPolicyError)
				}
				return
			}
			if d.trust != trustUnverified {
				t.Fatalf("got %s", d.trust)
			}
		})
	}
}

// requestEmailPage simulates the redirection from CertSec to CertAuth and returns the page.
func (e *trustEnv) requestEmailPage(cd *models.CertificateData, english bool) (int, string) {
	e.t.Helper()
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	ap := &models.AuthProcess{Code: code, CertificateData: cd, RedirectURI: "https://rp.invalid/callback"}
	e.s.authprocCache.Set(code, ap, time.Minute)
	path := CertificateBackEndpoint
	if english {
		path += "/en"
	}
	resp, err := e.s.httpServer.Test(httptest.NewRequest(http.MethodGet, path+"?code="+code, nil), -1)
	if err != nil {
		e.t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestPageRequestEmailInProduction(t *testing.T) {
	const approvedID = "NTRGB-00000001"

	t.Run("manually approved certificate is accepted without eIDAS or demo messages", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
		e.approve(l.Cert, approvedID)
		cd := certData(t, l, approvedID)
		status, body := e.requestEmailPage(cd, false)
		if status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		mustContain(t, body, "Certificado aprobado manualmente", "no es un certificado cualificado eIDAS", approvedID, `name="email"`)
		mustNotContain(t, body, "modo de prueba", "no es válido según las normas eIDAS")
		if cd.EIDASCertificate {
			t.Fatal("a manually approved certificate must not be marked as eIDAS")
		}

		_, body = e.requestEmailPage(certData(t, l, approvedID), true)
		mustContain(t, body, "Manually approved certificate", "not a qualified eIDAS certificate")
		mustNotContain(t, body, "demonstration mode")
	})

	t.Run("eIDAS certificate is unchanged", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("REP", "ORG SA", "ES", "Madrid",
			certpolicytest.OrganizationIdentifier("VATES-A00000000"))})
		e.dss.qualified[l.B64DER()] = true
		cd := certData(t, l, "")
		_, body := e.requestEmailPage(cd, false)
		mustContain(t, body, "Certificado recibido", `name="email"`)
		mustNotContain(t, body, "aprobado manualmente", "modo de prueba")
		if !cd.EIDASCertificate {
			t.Fatal("eIDAS certificate not marked as eIDAS")
		}
	})

	t.Run("revoked whitelisted certificate is rejected", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		l := orgLeaf(e.pki, e.pki.Intermediate, "REVOKED")
		e.pki.Intermediate.Revoke(l.Cert)
		e.approve(l.Cert, approvedID)
		_, body := e.requestEmailPage(certData(t, l, approvedID), false)
		mustContain(t, body, "no cumple la política de confianza")
		mustNotContain(t, body, `name="email"`)
		_, body = e.requestEmailPage(certData(t, l, approvedID), true)
		mustContain(t, body, "does not comply with the trust policy")
	})

	t.Run("revocation status unavailable asks to retry", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		l := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
		e.pki.Intermediate.CRLMode = certpolicytest.CRLUnavailable
		e.approve(l.Cert, approvedID)
		_, body := e.requestEmailPage(certData(t, l, approvedID), false)
		mustContain(t, body, "no hemos podido comprobar su estado de")
		mustNotContain(t, body, `name="email"`)
	})

	t.Run("non-approved non-eIDAS certificate is rejected as before", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("SEAL", "ORG", "ES", "Madrid",
			certpolicytest.OrganizationIdentifier("VATES-B00000000"))})
		_, body := e.requestEmailPage(certData(t, l, ""), false)
		mustContain(t, body, "no es válido según las normas eIDAS, y no podemos aceptarlo")
		mustNotContain(t, body, `name="email"`, "aprobado manualmente")
	})

	t.Run("EU DSS outage for a non-approved certificate is reported as before", func(t *testing.T) {
		e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
		e.dss.down = true
		l := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("SEAL", "ORG", "ES", "Madrid",
			certpolicytest.OrganizationIdentifier("VATES-B00000000"))})
		_, body := e.requestEmailPage(certData(t, l, ""), false)
		mustContain(t, body, "problemas temporales validando el certificado")
	})
}

// TestRealEUDSSClientBoundary exercises VerifyCertificate (the real HTTP client) against a
// local EU DSS mock, to check that the decision is driven by the DSS indication.
func TestRealEUDSSClientBoundary(t *testing.T) {
	var passed string
	dssMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), passed) {
			fmt.Fprint(w, `{"simpleCertificateReport":{"Certificate":{"Indication":"PASSED"},"ChainItem":[{"Indication":"PASSED"}]}}`)
			return
		}
		fmt.Fprint(w, `{"simpleCertificateReport":{"Certificate":{"Indication":"INDETERMINATE"},"ChainItem":[{"Indication":"INDETERMINATE"}]}}`)
	}))
	defer dssMock.Close()

	e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
	e.s.verifyEIDAS = VerifyCertificate
	e.s.euDSSURL = dssMock.URL

	qualified := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("REP", "ORG SA", "ES", "Madrid",
		certpolicytest.OrganizationIdentifier("VATES-A00000000"))})
	passed = qualified.B64DER()
	if d := e.s.evaluateCertificateTrust(context.Background(), certData(t, qualified, "")); d.trust != trustEIDAS {
		t.Fatalf("qualified: got %s", d.trust)
	}

	approved := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED")
	e.approve(approved.Cert, "NTRGB-00000001")
	if d := e.s.evaluateCertificateTrust(context.Background(), certData(t, approved, "NTRGB-00000001")); d.trust != trustManualApproval || d.eidasValidationError == nil {
		t.Fatalf("approved: got %s, eIDAS validation error %v", d.trust, d.eidasValidationError)
	}
}

func mustContain(t *testing.T, body string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(body, p) {
			t.Errorf("page does not contain %q", p)
		}
	}
}

func mustNotContain(t *testing.T, body string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(body, p) {
			t.Errorf("page unexpectedly contains %q", p)
		}
	}
}

// --- Organization identifier and contract form ---

func TestContractFormIdentity(t *testing.T) {
	const approvedID = "NTRGB-00000001"
	e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
	approved := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED ORG")
	e.approve(approved.Cert, approvedID)

	newProcess := func(cd *models.CertificateData) *models.AuthProcess {
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		ap := &models.AuthProcess{Code: code, CertificateData: cd, Email: "rep@example.test", EmailVerificationCode: "123456",
			RedirectURI: "https://rp.invalid/callback"}
		// As left by pageRequestEmail after accepting the certificate
		ap.TrustedCertificateSHA256 = models.CertificateFingerprint(cd.Certificate)
		e.s.authprocCache.Set(code, ap, time.Minute)
		return ap
	}
	post := func(path string, form url.Values) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := e.s.httpServer.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}

	t.Run("organizational certificate without person names asks for the representative", func(t *testing.T) {
		ap := newProcess(certData(t, approved, approvedID))
		status, body := post(verifyEmailCodeEndpoint, url.Values{"verification_code": {"123456"}, "auth_code": {ap.Code}, "email": {"rep@example.test"}})
		if status != http.StatusOK {
			t.Fatalf("status %d: %.300s", status, body)
		}
		mustContain(t, body, `<input type="text" name="representative_name"`, approvedID)
		mustNotContain(t, body, `<input type="hidden" name="representative_name"`)
	})

	t.Run("certificate of a natural person keeps the common name", func(t *testing.T) {
		person := e.pki.Intermediate.Issue(certpolicytest.LeafOptions{Subject: certpolicytest.Name("ANA GARCIA", "ORG SA", "ES", "Madrid",
			certpolicytest.OrganizationIdentifier("VATES-A00000000"),
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 42}, Value: "ANA"},
			pkix.AttributeTypeAndValue{Type: asn1.ObjectIdentifier{2, 5, 4, 4}, Value: "GARCIA"})})
		ap := newProcess(certData(t, person, ""))
		_, body := post(verifyEmailCodeEndpoint, url.Values{"verification_code": {"123456"}, "auth_code": {ap.Code}, "email": {"rep@example.test"}})
		mustContain(t, body, `<input type="hidden" name="representative_name" value="ANA GARCIA">`)
	})

	baseForm := func(code, nif string) url.Values {
		return url.Values{"auth_code": {code}, "representative_email": {"rep@example.test"}, "representative_name": {"Jane Doe"},
			"organization_nif": {nif}, "organization_country": {"GB"}, "organization_name": {"APPROVED ORG"},
			"contract_base": {"on"}, "contract_basic": {"on"}}
	}

	for _, path := range []string{presentContractForAcceptanceEndpoint, contractAcceptedEndpoint} {
		t.Run(path+" rejects a manipulated organization identifier", func(t *testing.T) {
			ap := newProcess(certData(t, approved, approvedID))
			status, body := post(path, baseForm(ap.Code, "VATES-B99999999"))
			if status != http.StatusBadRequest || !strings.Contains(body, "does not match the certificate") {
				t.Fatalf("status %d: %s", status, body)
			}
		})
		t.Run(path+" rejects an empty representative name", func(t *testing.T) {
			ap := newProcess(certData(t, approved, approvedID))
			f := baseForm(ap.Code, approvedID)
			f.Set("representative_name", " ")
			status, body := post(path, f)
			if status != http.StatusBadRequest || !strings.Contains(body, "missing representative name") {
				t.Fatalf("status %d: %s", status, body)
			}
		})
	}

	t.Run("contract print uses the approved identifier even if the field is removed", func(t *testing.T) {
		ap := newProcess(certData(t, approved, approvedID))
		f := baseForm(ap.Code, "")
		f.Del("organization_nif")
		status, body := post(presentContractForAcceptanceEndpoint, f)
		if status != http.StatusOK {
			t.Fatalf("status %d: %.300s", status, body)
		}
		mustContain(t, body, `name="organization_nif" value="`+approvedID+`"`)
	})
}

func TestEnforceCertificateIdentity(t *testing.T) {
	cd := &models.CertificateData{OrganizationID: "B12345678", Subject: &x509util.ELSIName{Country: "ES"}}
	f := &models.ContractForm{OrganizationNif: "VATES-B12345678", RepresentativeName: "X"}
	if err := enforceCertificateIdentity(f, cd, true); err != nil || f.OrganizationNif != "VATES-B12345678" {
		t.Fatalf("normalized equivalent value: %v %q", err, f.OrganizationNif)
	}
	f = &models.ContractForm{OrganizationNif: "B12345678", RepresentativeName: "X"}
	if err := enforceCertificateIdentity(f, cd, false); err != nil || f.OrganizationNif != "B12345678" {
		t.Fatalf("raw value: %v %q", err, f.OrganizationNif)
	}
	f = &models.ContractForm{OrganizationNif: "VATES-A00000000", RepresentativeName: "X"}
	if err := enforceCertificateIdentity(f, cd, true); !errors.Is(err, errOrganizationIdentifierMismatch) {
		t.Fatalf("expected mismatch, got %v", err)
	}
	f = &models.ContractForm{RepresentativeName: "X"}
	if err := enforceCertificateIdentity(f, &models.CertificateData{}, true); err == nil {
		t.Fatal("expected an error without certificate organization identifier")
	}
}

func TestRepresentativeNameFromCertificate(t *testing.T) {
	for _, tc := range []struct {
		subject  x509util.ELSIName
		name     string
		editable bool
	}{
		{x509util.ELSIName{CommonName: "ANA GARCIA", GivenName: "ANA", Surname: "GARCIA", Organization: "ORG"}, "ANA GARCIA", false},
		{x509util.ELSIName{CommonName: "ACME LTD", Organization: "ACME LTD"}, "", true},
		{x509util.ELSIName{CommonName: "acme ltd ", Organization: "ACME LTD"}, "", true},
		{x509util.ELSIName{CommonName: "John Smith", Organization: "ACME LTD"}, "John Smith", true},
		{x509util.ELSIName{Organization: "ACME LTD"}, "", true},
	} {
		name, editable := representativeNameFromCertificate(&tc.subject)
		if name != tc.name || editable != tc.editable {
			t.Errorf("%+v: got %q/%v, want %q/%v", tc.subject, name, editable, tc.name, tc.editable)
		}
	}
}

// TestApprovedIdentifierDownstream checks that the identifier assigned by the whitelist is the
// one in the ID token, the access token, the TMF organization and its DID.
func TestApprovedIdentifierDownstream(t *testing.T) {
	const approvedID = "NTRGB-00000001"
	p := certpolicytest.New(t, "downstream")
	cd := certData(t, orgLeaf(p, p.Intermediate, "APPROVED ORG"), approvedID)

	js, err := jwtservice.New("https://certauth.test")
	if err != nil {
		t.Fatal(err)
	}
	ap := &models.AuthProcess{Code: "c", Email: "rep@example.test", Nonce: "n"}
	rp := &models.RelyingParty{ClientID: "rp", TokenExpiry: 60}

	claimsOf := func(token string) jwt.MapClaims {
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
			t.Fatal(err)
		}
		return claims
	}

	idToken, err := js.GenerateIDTokenForCert(ap, cd, rp)
	if err != nil {
		t.Fatal(err)
	}
	idc := claimsOf(idToken)
	if idc["sub"] != approvedID || idc["organization_identifier"] != approvedID {
		t.Errorf("ID token: sub %v, organization_identifier %v", idc["sub"], idc["organization_identifier"])
	}

	at, err := js.GenerateAccessTokenForCert(ap, cd, rp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(claimsOf(at)), "did:elsi:"+approvedID) {
		t.Errorf("access token does not carry did:elsi:%s", approvedID)
	}

	f := &models.ContractForm{OrganizationNif: "", RepresentativeName: "Jane Doe"}
	if err := enforceCertificateIdentity(f, cd, true); err != nil {
		t.Fatal(err)
	}
	org := tmfservice.BuildTMFOrganizationFromRequest(tmfservice.RegistrationRequest{VatId: f.OrganizationNif, Country: "GB", CompanyName: "APPROVED ORG"}, cd.CertificateDER)
	if got := org.OrganizationIdentification[0].IdentificationID; got != "did:elsi:"+approvedID {
		t.Errorf("TMF organization DID %q", got)
	}
	if got := org.ExternalReference[0].Name; got != approvedID {
		t.Errorf("TMF external reference %q", got)
	}
}

// --- The trust decision cannot be skipped ---

// TestCertificateFlowRequiresAcceptance checks that the steps after pageRequestEmail and the
// token endpoint require an accepted certificate and, for tokens, a completed flow.
func TestCertificateFlowRequiresAcceptance(t *testing.T) {
	const approvedID = "NTRGB-00000001"
	e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
	e.s.httpServer.Post(token_endpoint, e.s.APITokenExchange)

	approved := orgLeaf(e.pki, e.pki.Intermediate, "APPROVED ORG")
	e.approve(approved.Cert, approvedID)
	revoked := orgLeaf(e.pki, e.pki.Intermediate, "REVOKED ORG")
	e.approve(revoked.Cert, approvedID)
	e.pki.Intermediate.Revoke(revoked.Cert)

	// newProcess leaves the process as CertSec does, before CertAuth evaluates the certificate.
	newProcess := func(cd *models.CertificateData) *models.AuthProcess {
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		ap := &models.AuthProcess{Code: code, ClientID: "rp", CertificateData: cd, RedirectURI: "https://rp.invalid/callback"}
		e.s.authprocCache.Set(code, ap, time.Minute)
		return ap
	}
	do := func(req *http.Request) (int, string) {
		t.Helper()
		resp, err := e.s.httpServer.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	post := func(path string, form url.Values) (int, string) {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return do(req)
	}
	certificateBack := func(ap *models.AuthProcess) {
		t.Helper()
		do(httptest.NewRequest(http.MethodGet, CertificateBackEndpoint+"?code="+ap.Code, nil))
	}
	token := func(ap *models.AuthProcess) (int, string) {
		return post(token_endpoint, url.Values{"grant_type": {"authorization_code"}, "code": {ap.Code}, "client_id": {"rp"},
			"redirect_uri": {ap.RedirectURI}})
	}
	sendEmail := func(ap *models.AuthProcess) (int, string) {
		return post(sendEmailVerificationEndpoint, url.Values{"auth_code": {ap.Code}, "email": {"rep@example.test"}})
	}
	const notAccepted = "has not been accepted"

	t.Run("certificate never evaluated", func(t *testing.T) {
		ap := newProcess(certData(t, revoked, approvedID))
		if _, body := sendEmail(ap); !strings.Contains(body, notAccepted) {
			t.Errorf("email verification reached without evaluation")
		}
		for _, path := range []string{verifyEmailCodeEndpoint, presentContractForAcceptanceEndpoint, contractAcceptedEndpoint} {
			if _, body := post(path, url.Values{"auth_code": {ap.Code}, "email": {"rep@example.test"}, "verification_code": {"1"}}); !strings.Contains(body, notAccepted) {
				t.Errorf("%s reached without evaluation", path)
			}
		}
		if status, body := token(ap); status != http.StatusBadRequest || !strings.Contains(body, "invalid_grant") {
			t.Errorf("token issued without evaluation: %d %s", status, body)
		}
	})

	t.Run("certificate rejected", func(t *testing.T) {
		ap := newProcess(certData(t, revoked, approvedID))
		certificateBack(ap)
		if ap.CertificateAccepted() {
			t.Fatal("revoked certificate accepted")
		}
		if _, body := sendEmail(ap); !strings.Contains(body, notAccepted) {
			t.Errorf("email verification reached after rejection")
		}
		if status, _ := token(ap); status != http.StatusBadRequest {
			t.Errorf("token issued after rejection: %d", status)
		}
	})

	t.Run("accepted but the flow was not completed", func(t *testing.T) {
		ap := newProcess(certData(t, approved, approvedID))
		certificateBack(ap)
		if !ap.CertificateAccepted() || ap.CertificateFlowCompleted {
			t.Fatalf("accepted %v, completed %v", ap.CertificateAccepted(), ap.CertificateFlowCompleted)
		}
		if status, _ := token(ap); status != http.StatusBadRequest {
			t.Errorf("token issued before registration: %d", status)
		}
	})

	t.Run("certificate replaced after acceptance", func(t *testing.T) {
		ap := newProcess(certData(t, approved, approvedID))
		certificateBack(ap)
		ap.CertificateData = certData(t, revoked, approvedID)
		if _, body := sendEmail(ap); !strings.Contains(body, notAccepted) {
			t.Errorf("email verification reached with a replaced certificate")
		}
	})
}

// TestCertSecRejectionMessages checks that a certificate rejected by CertSec is shown with a
// message for its reason, in Spanish and English, and never with the internal error.
func TestCertSecRejectionMessages(t *testing.T) {
	e := newTrustEnv(t, types.PROFILE_ISBE_PRO, true)
	for _, tc := range []struct {
		name   string
		reason error
		es, en string
	}{
		{"not approved", models.ErrCertificateNotApproved, "No podemos aceptar este certificado", "We cannot accept this certificate"},
		{"expired", models.ErrCertificateNotValidNow, "Certificado no vigente", "Certificate not valid"},
		{"unreadable", models.ErrCertificateUnreadable, "No hemos recibido un certificado válido", "We did not receive a valid certificate"},
		{"other", errors.New("checking approved certificate: database is locked"), "problemas temporales", "temporary problems"},
	} {
		for _, english := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s english=%v", tc.name, english), func(t *testing.T) {
				code := fmt.Sprintf("code-%d", time.Now().UnixNano())
				internal := fmt.Errorf("../../src/certsecserver/certsec_server.go:418 requireSubjectIdentifier: detail: %w", tc.reason)
				e.s.authprocCache.Set(code, &models.AuthProcess{Code: code, ErrorInProcess: internal}, time.Minute)
				path := CertificateBackEndpoint
				want := tc.es
				if english {
					path += "/en"
					want = tc.en
				}
				resp, err := e.s.httpServer.Test(httptest.NewRequest(http.MethodGet, path+"?code="+code+"&error=true", nil), -1)
				if err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(resp.Body)
				page := string(body)
				if resp.StatusCode != http.StatusOK || !strings.Contains(page, want) {
					t.Fatalf("status %d, page without %q", resp.StatusCode, want)
				}
				for _, leak := range []string{"certsec_server.go", "requireSubjectIdentifier", "database is locked"} {
					if strings.Contains(page, leak) {
						t.Errorf("the page shows the internal error (%q)", leak)
					}
				}
			})
		}
	}
}
