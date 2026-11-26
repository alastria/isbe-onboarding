package tsaservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

func validConfig(a *tsatest.Authority) TSAConfig {
	return TSAConfig{
		TSAURL:          "https://tsa.example.test/tsa",
		TSAUser:         "user",
		TSAPassword:     "s3cr3t-value",
		TrustAnchorsPEM: a.RootPEM(),
	}
}

func TestNewTSAServiceValidation(t *testing.T) {
	a := tsatest.New(t)
	cases := map[string]func(*TSAConfig){
		"missing URL":         func(c *TSAConfig) { c.TSAURL = "" },
		"missing user":        func(c *TSAConfig) { c.TSAUser = "" },
		"missing password":    func(c *TSAConfig) { c.TSAPassword = "" },
		"plain HTTP":          func(c *TSAConfig) { c.TSAURL = "http://tsa.example.test/tsa" },
		"credentials in URL":  func(c *TSAConfig) { c.TSAURL = "https://u:p@tsa.example.test/tsa" },
		"unsupported scheme":  func(c *TSAConfig) { c.TSAURL = "ftp://tsa.example.test/tsa" },
		"relative URL":        func(c *TSAConfig) { c.TSAURL = "/tsa" },
		"bad hash":            func(c *TSAConfig) { c.HashAlgorithm = "sha1" },
		"bad policy":          func(c *TSAConfig) { c.PolicyOID = "not.an.oid" },
		"bad revocation mode": func(c *TSAConfig) { c.RevocationCheck = "ocsp" },
		"bad pin":             func(c *TSAConfig) { c.TrustAnchorSHA256 = []string{"abcd"} },
		"pin mismatch":        func(c *TSAConfig) { c.TrustAnchorSHA256 = []string{EmbeddedRootSHA256} },
		"invalid trust PEM": func(c *TSAConfig) {
			c.TrustAnchorsPEM = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
		},
		"private key in trust": func(c *TSAConfig) {
			c.TrustAnchorsPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		},
		"missing trust file":        func(c *TSAConfig) { c.TrustAnchorsFile = "/nonexistent/anchors.pem" },
		"unpinned CA download":      func(c *TSAConfig) { c.TrustAnchorsPEM = ""; c.CACertURL = "https://pki.example.test/root.pem" },
		"user with colon":           func(c *TSAConfig) { c.TSAUser = "a:b" },
		"timeout too long":          func(c *TSAConfig) { c.Timeout = time.Hour },
		"missing intermediate file": func(c *TSAConfig) { c.IntermediatesFile = "/nonexistent/inter.pem" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig(a)
			mutate(&cfg)
			_, err := NewTSAService(&cfg, WithLogger(discardLogger()))
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("expected ErrInvalidConfig, got %v", err)
			}
			if strings.Contains(err.Error(), "s3cr3t-value") {
				t.Fatal("error leaks the password")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		cfg := validConfig(a)
		cfg.TrustAnchorSHA256 = []string{strings.ToUpper(a.RootSHA256())}
		if _, err := NewTSAService(&cfg, WithLogger(discardLogger())); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("embedded trust store is the default", func(t *testing.T) {
		cfg := validConfig(a)
		cfg.TrustAnchorsPEM = ""
		s, err := NewTSAService(&cfg, WithLogger(discardLogger()))
		if err != nil {
			t.Fatal(err)
		}
		if len(s.intermediates) != 1 {
			t.Fatal("embedded intermediate not loaded")
		}
	})
}

func TestPinnedCADownload(t *testing.T) {
	a := tsatest.New(t)
	pki := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(a.RootPEM()))
	}))
	t.Cleanup(pki.Close)

	cfg := validConfig(a)
	cfg.TrustAnchorsPEM = ""
	cfg.CACertURL = pki.URL + "/root.pem"
	cfg.AllowInsecure = true // local profile only: plain-HTTP download

	t.Run("matching pin", func(t *testing.T) {
		c := cfg
		c.TrustAnchorSHA256 = []string{a.RootSHA256()}
		if _, err := NewTSAService(&c, WithLogger(discardLogger())); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("substituted certificate", func(t *testing.T) {
		c := cfg
		c.TrustAnchorSHA256 = []string{tsatest.New(t).RootSHA256()}
		if _, err := NewTSAService(&c, WithLogger(discardLogger())); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected pin mismatch, got %v", err)
		}
	})
}

func TestConfigRedaction(t *testing.T) {
	cfg := TSAConfig{TSAURL: "https://tsa.example.test/tsa?token=abc", TSAUser: "user", TSAPassword: "s3cr3t-value"}
	asJSON, err := json.Marshal(struct{ TSA *TSAConfig }{&cfg}) // as main.go dumps the server config
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{cfg.String(), fmt.Sprintf("%v", cfg), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg), cfg.LogValue().String(), string(asJSON)} {
		if strings.Contains(s, "s3cr3t-value") || strings.Contains(s, "token=abc") {
			t.Fatalf("configuration printed with secrets: %s", s)
		}
	}
}

func TestApplyEnv(t *testing.T) {
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	if err := os.WriteFile(pwFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		EnvURL:               "https://tsa.example.test/tsa",
		EnvUser:              "user",
		EnvPasswordFile:      pwFile,
		EnvTrustAnchorSHA256: "AA:bb, cc",
		EnvHashAlgorithm:     "SHA256",
		EnvNonce:             "false",
		EnvTimeout:           "10s",
		EnvRevocationCheck:   "CRL",
		EnvPolicyOID:         "0.4.0.2023.1.1",
	}
	var cfg TSAConfig
	if err := ApplyEnv(&cfg, func(k string) string { return env[k] }, os.ReadFile); err != nil {
		t.Fatal(err)
	}
	if cfg.TSAPassword != "from-file" || cfg.TSAUser != "user" || cfg.TSAURL != env[EnvURL] {
		t.Fatalf("credentials or URL not applied: %v", cfg)
	}
	if len(cfg.TrustAnchorSHA256) != 2 || cfg.HashAlgorithm != "sha256" || !cfg.DisableNonce || cfg.Timeout != 10*time.Second ||
		cfg.RevocationCheck != "crl" || cfg.PolicyOID != "0.4.0.2023.1.1" {
		t.Fatalf("options not applied: %+v", cfg.LogValue())
	}

	t.Run("both value and file", func(t *testing.T) {
		env := map[string]string{EnvPassword: "x", EnvPasswordFile: pwFile}
		if err := ApplyEnv(&TSAConfig{}, func(k string) string { return env[k] }, os.ReadFile); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("bad timeout", func(t *testing.T) {
		env := map[string]string{EnvTimeout: "soon"}
		if err := ApplyEnv(&TSAConfig{}, func(k string) string { return env[k] }, os.ReadFile); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("unreadable secret file", func(t *testing.T) {
		env := map[string]string{EnvPasswordFile: filepath.Join(dir, "missing")}
		err := ApplyEnv(&TSAConfig{}, func(k string) string { return env[k] }, os.ReadFile)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestVerifierNeedsNoCredentials(t *testing.T) {
	if _, err := NewVerifier(context.Background(), &TSAConfig{}, WithLogger(discardLogger())); err != nil {
		t.Fatalf("verifier with embedded trust store: %v", err)
	}
}
