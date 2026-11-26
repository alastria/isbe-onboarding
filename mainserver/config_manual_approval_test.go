package mainserver

import (
	"testing"

	certauth "github.com/alastria/isbe-onboarding/certauthserver"
)

func TestConfigureManualApproval(t *testing.T) {
	cases := []struct {
		name        string
		env         map[string]string
		wantEnabled bool
		wantHeader  string
		wantErr     bool
	}{
		{name: "disabled by default"},
		{name: "header without the policy", env: map[string]string{"CLIENT_CERT_HEADER": "tls-client-certificate"}, wantHeader: "tls-client-certificate"},
		{name: "enabled with header", env: map[string]string{"MANUAL_CERTIFICATE_APPROVAL_ENABLED": "true", "CLIENT_CERT_HEADER": "tls-client-certificate"}, wantEnabled: true, wantHeader: "tls-client-certificate"},
		{name: "enabled without header", env: map[string]string{"MANUAL_CERTIFICATE_APPROVAL_ENABLED": "TRUE"}, wantErr: true},
		{name: "any other value disables it", env: map[string]string{"MANUAL_CERTIFICATE_APPROVAL_ENABLED": "yes", "CLIENT_CERT_HEADER": "tls-client-certificate"}, wantHeader: "tls-client-certificate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &certauth.ConfigCertAuth{}
			err := configureManualApproval(cfg, func(k string) string { return tc.env[k] })
			if (err != nil) != tc.wantErr {
				t.Fatalf("error %v, want error %v", err, tc.wantErr)
			}
			if err == nil && (cfg.ManualCertificateApprovalEnabled != tc.wantEnabled || cfg.ClientCertHeader != tc.wantHeader) {
				t.Fatalf("enabled=%v header=%q", cfg.ManualCertificateApprovalEnabled, cfg.ClientCertHeader)
			}
		})
	}
}
