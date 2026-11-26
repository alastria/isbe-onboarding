package tsaservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// TestAcceptanceHarnessAgainstMock runs the real-TSA acceptance checks against
// the in-process mock, whose tokens (like DigitelTS) omit the intermediate.
func TestAcceptanceHarnessAgainstMock(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	inter := filepath.Join(t.TempDir(), "inter.pem")
	if err := os.WriteFile(inter, []byte(srv.Authority.IntermediatePEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &TSAConfig{
		TSAURL:            srv.URL + "/tsa",
		TSAUser:           tsatest.User,
		TSAPassword:       tsatest.Password,
		TrustAnchorsPEM:   srv.Authority.RootPEM(),
		IntermediatesFile: inter,
		AllowInsecure:     true,
	}
	acceptanceRun(t, cfg, srv.Authority.RootSHA256())
	if reqs := srv.Requests(); len(reqs) != 1 || reqs[0].Nonce == nil || !reqs[0].HashOID.Equal(oidSHA512) {
		t.Fatalf("the harness must send one SHA-512 request with a nonce")
	}
}
