//go:build integration

package tsaservice

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestTimestampAndVerify requests ONE real timestamp from the configured TSA.
//
// It is excluded from normal builds (build tag "integration"), consumes
// provider quota and needs real credentials in the environment:
//
//	TSA_URL=... TSA_USER=... TSA_PASSWORD=... go test -tags integration -run TestTimestampAndVerify ./tsaservice/
//
// It must never run in CI and never with production credentials unless that
// is the explicit purpose of the run (e.g. after a credential rotation).
func TestTimestampAndVerify(t *testing.T) {
	if os.Getenv(EnvURL) == "" || os.Getenv(EnvUser) == "" || (os.Getenv(EnvPassword) == "" && os.Getenv(EnvPasswordFile) == "") {
		t.Skip("set TSA_URL, TSA_USER and TSA_PASSWORD (or TSA_PASSWORD_FILE) to run against a real TSA")
	}
	cfg := &TSAConfig{Environment: "integration-test"}
	if err := ApplyEnv(cfg, os.Getenv, os.ReadFile); err != nil {
		t.Fatal(err)
	}
	svc, err := NewTSAService(cfg)
	if err != nil {
		t.Fatalf("NewTSAService: %v", err)
	}

	data := []byte("isbe-onboarding TSA integration test " + time.Now().UTC().Format(time.RFC3339Nano))
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	tok, err := svc.Timestamp(ctx, data)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	t.Logf("genTime=%s serial=%s policy=%s signer=%q", tok.GenTime, tok.SerialNumber.Text(16), tok.Policy, tok.Signer.Subject.CommonName)

	if _, err := svc.Verify(tok.Response, data); err != nil {
		t.Fatalf("historical verification of the new token: %v", err)
	}
	if os.Getenv("DEBUG_TSR") != "" {
		_ = os.WriteFile(os.Getenv("DEBUG_TSR"), tok.Response, 0o600)
	}
}
