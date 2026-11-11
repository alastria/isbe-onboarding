package tsaservice

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"
)

// acceptanceRun is the body of the real-TSA acceptance test (service_test.go,
// build tag "integration"). It is shared with TestAcceptanceHarnessAgainstMock
// so that the harness itself is exercised offline before spending quota.
//
// It makes exactly ONE timestamp request and checks: SHA-512, a nonce echoed
// by the TSA, full verification, a 3-certificate chain, the expected anchor,
// that no host other than the TSA is contacted (the intermediate must come
// from the trust store) and that the stored form re-verifies offline.
// Secrets are never logged.
func acceptanceRun(t *testing.T, cfg *TSAConfig, wantAnchorSHA256 string) {
	t.Helper()
	if cfg.HashAlgorithm != "" && cfg.HashAlgorithm != "sha512" {
		t.Fatalf("TSA_HASH_ALGORITHM must be sha512 for this test")
	}
	if cfg.DisableNonce {
		t.Fatalf("TSA_NONCE must not be false for this test")
	}
	if cfg.CACertURL != "" {
		t.Fatalf("unset TSA_CA_CERT_URL: no certificate may be downloaded during this test")
	}
	cfg.RevocationCheck = RevocationNone // CRL fetching would be a second network destination.
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}

	tsaURL, err := url.Parse(cfg.TSAURL)
	if err != nil || tsaURL.Host == "" {
		t.Fatal("TSA_URL is not a valid URL")
	}
	guard := &hostGuard{allowed: tsaURL.Host, next: http.DefaultTransport}
	svc, err := NewTSAService(cfg, WithHTTPClient(&http.Client{Transport: guard, Timeout: cfg.Timeout}), WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("NewTSAService: %v", err)
	}
	t.Logf("config: host=%s hash=sha512 nonce=true timeout=%s policy=%q trust=%s", tsaURL.Host, cfg.Timeout, cfg.PolicyOID, cfg.trustSource())

	data := []byte("isbe-onboarding TSA acceptance test " + time.Now().UTC().Format(time.RFC3339Nano))
	ctx, cancel := context.WithTimeout(context.Background(), 2*cfg.Timeout)
	defer cancel()

	// The single request. Timestamp returns a token only after full
	// verification: PKIStatus, CMS signature, ESS, EKU, chain to the anchor at
	// genTime, MessageImprint, nonce echo, policy (if set) and freshness.
	tok, err := svc.Timestamp(ctx, data)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}

	if n := guard.count(); n != 1 {
		t.Errorf("HTTP requests = %d, want exactly 1", n)
	}
	if hosts := guard.blockedHosts(); len(hosts) > 0 {
		t.Errorf("blocked requests to other hosts: %v", hosts)
	}
	if tok.HashAlgorithm != "sha512" {
		t.Errorf("hash = %s, want sha512", tok.HashAlgorithm)
	}
	if tok.Nonce == nil {
		t.Error("the response does not carry the nonce")
	}
	if len(tok.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3 (TSU, intermediate, root)", len(tok.Chain))
	}
	if wantAnchorSHA256 != "" {
		if got := certFingerprint(tok.Chain[2]); got != wantAnchorSHA256 {
			t.Errorf("anchor sha256 = %s, want %s", got, wantAnchorSHA256)
		}
	}
	t.Logf("intermediate %q included in the token: %v (taken from the trust store either way)",
		tok.Chain[1].Subject.CommonName, bytes.Contains(tok.Response, tok.Chain[1].Raw))
	t.Logf("OK genTime=%s serial=%s policy=%s signer=%q response_bytes=%d",
		tok.GenTime.Format(time.RFC3339Nano), tok.SerialNumber.Text(16), tok.Policy, tok.Signer.Subject.CommonName, len(tok.Response))
	for i, c := range tok.Chain {
		t.Logf("chain[%d] %s sha256=%s", i, c.Subject.CommonName, certFingerprint(c))
	}

	// The stored form (raw TimeStampResp) re-verifies offline, as historical evidence.
	if _, err := svc.Verify(tok.Response, data); err != nil {
		t.Fatalf("offline re-verification of the new token: %v", err)
	}
	if guard.count() != 1 {
		t.Error("offline re-verification made network requests")
	}
	if p := os.Getenv("DEBUG_TSR"); p != "" {
		if err := os.WriteFile(p, tok.Response, 0o600); err != nil {
			t.Errorf("DEBUG_TSR: %v", err)
		}
	}
}

// hostGuard lets requests reach only one host and records everything else.
type hostGuard struct {
	allowed string
	next    http.RoundTripper

	mu      sync.Mutex
	n       int
	blocked []string
}

func (g *hostGuard) RoundTrip(r *http.Request) (*http.Response, error) {
	g.mu.Lock()
	if r.URL.Host != g.allowed {
		g.blocked = append(g.blocked, r.URL.Host)
		g.mu.Unlock()
		return nil, fmt.Errorf("request to %s blocked by the test", r.URL.Host)
	}
	g.n++
	g.mu.Unlock()
	return g.next.RoundTrip(r)
}

func (g *hostGuard) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.n
}

func (g *hostGuard) blockedHosts() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.blocked...)
}
