//go:build integration

package tsaservice

import (
	"os"
	"testing"
)

// TestTimestampAndVerify requests exactly ONE real timestamp from the TSA
// configured in the environment and runs the acceptance checks of
// acceptanceRun. It consumes provider quota, so it is excluded from normal
// builds (build tag "integration") and must be run on its own, never with ./...:
//
//	go test -tags integration -count=1 -run '^TestTimestampAndVerify$' -v ./tsaservice/
//
// Required: TSA_URL, TSA_USER, TSA_PASSWORD (or the _FILE variants).
// Optional: TSA_POLICY_OID (only once the provider has confirmed it),
// TSA_TIMEOUT (default 30s), TSA_TRUST_* overrides, DEBUG_TSR (path where the
// DER response is saved). With the embedded trust store the anchor must be the
// DigitelTS root.
func TestTimestampAndVerify(t *testing.T) {
	if os.Getenv(EnvURL) == "" || (os.Getenv(EnvUser) == "" && os.Getenv(EnvUserFile) == "") ||
		(os.Getenv(EnvPassword) == "" && os.Getenv(EnvPasswordFile) == "") {
		t.Skip("set TSA_URL, TSA_USER and TSA_PASSWORD (or the _FILE variants) to run against a real TSA")
	}
	cfg := &TSAConfig{Environment: "integration-test"}
	if err := ApplyEnv(cfg, os.Getenv, os.ReadFile); err != nil {
		t.Fatal(err)
	}
	want := ""
	if cfg.trustSource() == "embedded" {
		want = EmbeddedRootSHA256
	}
	acceptanceRun(t, cfg, want)
}
