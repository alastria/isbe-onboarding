package database

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// End-to-end tests of the registration flow against an in-process TSA: the
// contract is timestamped, the token verified, the evidence stored and later
// re-verified from what is in the database and on disk.

func newRegistrationEnv(t *testing.T) (*Database, *tsatest.Server, *tsaservice.TSAService) {
	t.Helper()
	// CreateRegistration writes to the relative path data/contracts.
	t.Chdir(t.TempDir())
	if err := os.MkdirAll("data/contracts", 0o755); err != nil {
		t.Fatal(err)
	}

	srv := tsatest.New(t).NewServer(t)
	inter := filepath.Join(t.TempDir(), "inter.pem")
	if err := os.WriteFile(inter, []byte(srv.Authority.IntermediatePEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	tsa, err := tsaservice.NewTSAService(&tsaservice.TSAConfig{
		TSAURL:            srv.URL + "/tsa",
		TSAUser:           tsatest.User,
		TSAPassword:       tsatest.Password,
		TrustAnchorsPEM:   srv.Authority.RootPEM(),
		IntermediatesFile: inter,
		AllowInsecure:     true,
	}, tsaservice.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	return newTestDatabase(t), srv, tsa
}

func testCertificateData() *models.CertificateData {
	return &models.CertificateData{
		OrganizationID: "VATES-B00000000",
		Subject:        &x509util.ELSIName{Organization: "Test Org SL", Country: "ES"},
		CertificateDER: "MIIBdGVzdC1jZXJ0aWZpY2F0ZQ==",
	}
}

func countRegistrations(t *testing.T, d *Database) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(`SELECT count(*) FROM registrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func contractFiles(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("data/contracts/*")
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestCreateRegistrationStoresVerifiedEvidence(t *testing.T) {
	d, srv, tsa := newRegistrationEnv(t)
	cert := testCertificateData()
	contract := []byte("%PDF-1.7 test contract\n%%EOF\n")

	err := d.CreateRegistration(context.Background(), tsa, cert, "rep@example.test", &models.ContractForm{OrganizationNif: cert.OrganizationID}, contract)
	if err != nil {
		t.Fatalf("CreateRegistration: %v", err)
	}
	if n := countRegistrations(t, d); n != 1 {
		t.Fatalf("registrations = %d", n)
	}
	if len(srv.Requests()) != 1 {
		t.Fatalf("TSA requests = %d", len(srv.Requests()))
	}

	// The stored evidence can be verified independently, without the TSA.
	vt, err := d.VerifyRegistrationEvidence(tsa.Verifier, cert.OrganizationID)
	if err != nil {
		t.Fatalf("stored evidence does not verify: %v", err)
	}

	// created_at holds the TSA genTime.
	var createdAt string
	if err := d.db.QueryRow(`SELECT created_at FROM registrations`).Scan(&createdAt); err != nil {
		t.Fatal(err)
	}
	if createdAt == "" || vt.GenTime.IsZero() {
		t.Fatal("genTime not recorded")
	}

	// Tampering with the stored contract is detected.
	ev, err := d.GetRegistrationEvidence(cert.OrganizationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ev.ContractDocumentPath, []byte("%PDF-1.7 other contract\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.VerifyRegistrationEvidence(tsa.Verifier, cert.OrganizationID); !errors.Is(err, tsaservice.ErrVerificationFailed) {
		t.Fatalf("modified contract not detected: %v", err)
	}
}

func TestCreateRegistrationFailsClosed(t *testing.T) {
	cases := map[string]func(*tsatest.Server){
		"TSA unavailable": func(s *tsatest.Server) {
			s.SetHandler(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) })
		},
		"invalid signature": func(s *tsatest.Server) { s.SetOptions(tsatest.TokenOptions{TamperSignature: true}) },
		"wrong nonce":       func(s *tsatest.Server) { s.SetOptions(tsatest.TokenOptions{OmitNonce: true}) },
		"rejected":          func(s *tsatest.Server) { s.SetOptions(tsatest.TokenOptions{Status: 2}) },
	}
	for name, breakTSA := range cases {
		t.Run(name, func(t *testing.T) {
			d, srv, tsa := newRegistrationEnv(t)
			breakTSA(srv)
			cert := testCertificateData()

			err := d.CreateRegistration(context.Background(), tsa, cert, "rep@example.test", &models.ContractForm{OrganizationNif: cert.OrganizationID}, []byte("%PDF"))
			if err == nil {
				t.Fatal("registration completed with an invalid timestamp")
			}
			if n := countRegistrations(t, d); n != 0 {
				t.Fatalf("a registration was stored: %d", n)
			}
			if files := contractFiles(t); len(files) != 0 {
				t.Fatalf("contract files left behind: %v", files)
			}
		})
	}
}

func TestTimestampedEvidenceFormatIsStable(t *testing.T) {
	// Historical tokens were issued over contract || certificate. Changing this
	// function breaks their verification.
	got := TimestampedEvidence([]byte("PDF"), "CERT")
	if string(got) != "PDFCERT" {
		t.Fatalf("evidence format changed: %q", got)
	}
}
