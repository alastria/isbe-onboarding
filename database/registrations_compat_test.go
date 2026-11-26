package database

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// TestCreateRegistrationFailsClosedOnAuthAndTimeout complements
// TestCreateRegistrationFailsClosed with the TSA-side failures that depend on
// the client configuration: wrong credentials and a TSA slower than the timeout.
func TestCreateRegistrationFailsClosedOnAuthAndTimeout(t *testing.T) {
	cases := map[string]struct {
		mutate  func(*tsaservice.TSAConfig)
		breaker func(*tsatest.Server)
		want    error
	}{
		"authentication error": {
			mutate: func(c *tsaservice.TSAConfig) { c.TSAPassword = "wrong-password-for-test" },
			want:   tsaservice.ErrAuthentication,
		},
		"timeout": {
			mutate: func(c *tsaservice.TSAConfig) { c.Timeout = 200 * time.Millisecond },
			breaker: func(s *tsatest.Server) {
				s.SetHandler(func(w http.ResponseWriter, r *http.Request) {
					select {
					case <-r.Context().Done():
					case <-time.After(1500 * time.Millisecond):
					}
				})
			},
			want: tsaservice.ErrTimeout,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d, srv, tsa := newRegistrationEnvWith(t, tc.mutate)
			if tc.breaker != nil {
				tc.breaker(srv)
			}
			cert := testCertificateData()
			start := time.Now()
			err := d.CreateRegistration(context.Background(), tsa, cert, "rep@example.test", &models.ContractForm{OrganizationNif: cert.OrganizationID}, []byte("%PDF"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if time.Since(start) > time.Second {
				t.Fatalf("the configured timeout was not enforced")
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

// TestLegacyRegistrationEvidenceVerifies inserts a registration exactly as the
// previous implementation stored it (raw TimeStampResp over contract || cert,
// SHA-512, no nonce, certReq) and checks that the new verifier accepts it.
func TestLegacyRegistrationEvidenceVerifies(t *testing.T) {
	d, srv, tsa := newRegistrationEnv(t)
	cert := testCertificateData()
	contract := []byte("%PDF-1.7 legacy contract\n%%EOF\n")

	// Data built as the old code did, with bytes.Buffer.
	var buf bytes.Buffer
	buf.Write(contract)
	buf.WriteString(cert.CertificateDER)
	digest := sha512.Sum512(buf.Bytes())
	oidSHA512 := []int{2, 16, 840, 1, 101, 3, 4, 2, 3}
	tsr, err := srv.Authority.Issue(&tsatest.Request{HashOID: oidSHA512, Digest: digest[:], CertReq: true}, tsatest.TokenOptions{})
	if err != nil {
		t.Fatal(err)
	}

	path := "data/contracts/legacy.pdf"
	if err := writeFile(path, contract); err != nil {
		t.Fatal(err)
	}
	_, err = d.db.Exec(`INSERT INTO registrations (organization_identifier, organization, email, country, contract_form, contract_document, eidas_cert, timestamp, created_at, updated_at)
		VALUES (?, 'Legacy Org', 'rep@example.test', 'ES', jsonb('{}'), ?, ?, ?, '2026-10-08 10:00:00', '2026-10-08 10:00:00')`,
		cert.OrganizationID, path, cert.CertificateDER, tsr)
	if err != nil {
		t.Fatal(err)
	}

	vt, err := d.VerifyRegistrationEvidence(tsa.Verifier, cert.OrganizationID)
	if err != nil {
		t.Fatalf("legacy evidence rejected: %v", err)
	}
	if vt.Nonce != nil || vt.HashAlgorithm != "sha512" {
		t.Errorf("unexpected legacy token properties: nonce=%v alg=%s", vt.Nonce, vt.HashAlgorithm)
	}

	t.Run("row without timestamp fails cleanly", func(t *testing.T) {
		if _, err := d.db.Exec(`INSERT INTO registrations (organization_identifier, contract_document, eidas_cert) VALUES ('VATES-B11111111', ?, 'CERT')`, path); err != nil {
			t.Fatal(err)
		}
		if _, err := d.VerifyRegistrationEvidence(tsa.Verifier, "VATES-B11111111"); err == nil {
			t.Fatal("row without timestamp verified")
		}
	})
}

func writeFile(path string, data []byte) error { return os.WriteFile(path, data, 0o644) }
