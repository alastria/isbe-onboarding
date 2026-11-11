package tsaservice

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// Regression tests for PR #10 review: the embedded DigitelTS "CA TSA G1"
// intermediate used to be loaded only with the embedded trust store, so any
// external anchor source (file, PEM, pinned URL) rejected every genuine token.

const embeddedIntermediateSHA256 = "1c1e385cc2b7e02d337531150af065514b733beb702a8bdbd286e706055a0df7"

// failingTransport fails the test on any HTTP request: verification of a
// stored token must never download anything (no AIA chasing, no CA fetch).
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected network request during verification: %s %s", r.Method, r.URL.Host)
	return nil, errors.New("network disabled in test")
}

func offlineClient(t *testing.T) *http.Client { return &http.Client{Transport: failingTransport{t}} }

func readEmbedded(t *testing.T, name string) []byte {
	t.Helper()
	data, err := embeddedTrust.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertRealChain(t *testing.T, v *Verifier) {
	t.Helper()
	tsr, digest := loadRealToken(t)
	vt, err := v.VerifyDigest(tsr, "sha512", digest)
	if err != nil {
		t.Fatalf("real DigitelTS token rejected: %v", err)
	}
	if len(vt.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3", len(vt.Chain))
	}
	if got := certFingerprint(vt.Chain[1]); got != embeddedIntermediateSHA256 {
		t.Errorf("chain[1] = %s (%s), want CA TSA G1", vt.Chain[1].Subject.CommonName, got)
	}
	if got := certFingerprint(vt.Chain[2]); got != EmbeddedRootSHA256 {
		t.Errorf("chain[2] = %s (%s), want DigitelTS root", vt.Chain[2].Subject.CommonName, got)
	}
}

func TestRealTokenWithExternalTrustSources(t *testing.T) {
	root := readEmbedded(t, embeddedRootFile)

	cases := map[string]func(t *testing.T) (TSAConfig, []Option){
		"embedded": func(t *testing.T) (TSAConfig, []Option) {
			return TSAConfig{}, nil
		},
		"TSA_TRUST_ANCHORS_FILE": func(t *testing.T) (TSAConfig, []Option) {
			return TSAConfig{TrustAnchorsFile: writeTemp(t, "root.pem", root)}, nil
		},
		"TSA_TRUST_ANCHORS_FILE pinned": func(t *testing.T) (TSAConfig, []Option) {
			return TSAConfig{TrustAnchorsFile: writeTemp(t, "root.pem", root), TrustAnchorSHA256: []string{EmbeddedRootSHA256}}, nil
		},
		"TSA_TRUST_ANCHORS_FILE DER": func(t *testing.T) (TSAConfig, []Option) {
			certs, err := parseCertificates(root)
			if err != nil {
				t.Fatal(err)
			}
			return TSAConfig{TrustAnchorsFile: writeTemp(t, "root.der", certs[0].Raw)}, nil
		},
		"TSA_TRUST_ANCHORS_PEM": func(t *testing.T) (TSAConfig, []Option) {
			return TSAConfig{TrustAnchorsPEM: string(root)}, nil
		},
		"TSA_TRUST_ANCHORS_PEM with intermediate also in TSA_INTERMEDIATES_FILE": func(t *testing.T) (TSAConfig, []Option) {
			inter := writeTemp(t, "inter.pem", readEmbedded(t, embeddedIntermediateFile))
			return TSAConfig{TrustAnchorsPEM: string(root), IntermediatesFile: inter}, nil
		},
		"TSA_CA_CERT_URL pinned": func(t *testing.T) (TSAConfig, []Option) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(root) }))
			t.Cleanup(srv.Close)
			return TSAConfig{CACertURL: srv.URL + "/root.pem", TrustAnchorSHA256: []string{EmbeddedRootSHA256}}, []Option{WithHTTPClient(srv.Client())}
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, opts := build(t)
			v, err := NewVerifier(context.Background(), &cfg, append(opts, WithLogger(discardLogger()))...)
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			if n := len(v.intermediates); n != 1 {
				t.Errorf("intermediates loaded = %d, want 1 (deduplicated CA TSA G1)", n)
			}
			// From here on, any network access is a failure.
			v.revocation = nil
			assertRealChain(t, v)
		})
	}
}

func TestRealTokenVerificationIsOffline(t *testing.T) {
	cfg := TSAConfig{TrustAnchorsPEM: string(readEmbedded(t, embeddedRootFile))}
	v, err := NewVerifier(context.Background(), &cfg, WithHTTPClient(offlineClient(t)), WithLogger(discardLogger()))
	if err != nil {
		t.Fatal(err)
	}
	assertRealChain(t, v)
}

func TestEmbeddedIntermediateIsNeverAnAnchor(t *testing.T) {
	tsr, digest := loadRealToken(t)
	foreign := tsatest.New(t)

	t.Run("foreign anchor: intermediate not loaded, token rejected", func(t *testing.T) {
		v := embeddedVerifier(t, TSAConfig{TrustAnchorsPEM: foreign.RootPEM()})
		if len(v.intermediates) != 0 {
			t.Fatalf("embedded intermediate loaded for an unrelated anchor")
		}
		if _, err := v.VerifyDigest(tsr, "sha512", digest); reasonOf(err) != ReasonChain {
			t.Fatalf("expected chain failure, got %v", err)
		}
	})

	t.Run("foreign anchor plus G1 as explicit intermediate: still rejected", func(t *testing.T) {
		inter := writeTemp(t, "inter.pem", readEmbedded(t, embeddedIntermediateFile))
		v := embeddedVerifier(t, TSAConfig{TrustAnchorsPEM: foreign.RootPEM(), IntermediatesFile: inter})
		if _, err := v.VerifyDigest(tsr, "sha512", digest); reasonOf(err) != ReasonChain {
			t.Fatalf("an intermediate without its root must not validate, got %v", err)
		}
	})

	t.Run("roots pool holds only the anchors", func(t *testing.T) {
		rootCerts, _ := parseCertificates(readEmbedded(t, embeddedRootFile))
		v := embeddedVerifier(t, TSAConfig{TrustAnchorsPEM: string(readEmbedded(t, embeddedRootFile))})
		want := x509.NewCertPool()
		want.AddCert(rootCerts[0])
		if !v.roots.Equal(want) {
			t.Fatal("roots pool contains more than the configured anchor")
		}
		if len(v.intermediates) != 1 || certFingerprint(v.intermediates[0]) != embeddedIntermediateSHA256 {
			t.Fatal("G1 should be offered only as an intermediate")
		}
	})

	t.Run("mismatched pin on an external file still fails", func(t *testing.T) {
		f := writeTemp(t, "root.pem", []byte(foreign.RootPEM()))
		_, err := NewVerifier(context.Background(), &TSAConfig{TrustAnchorsFile: f, TrustAnchorSHA256: []string{EmbeddedRootSHA256}}, WithLogger(discardLogger()))
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected pin mismatch, got %v", err)
		}
	})
}
