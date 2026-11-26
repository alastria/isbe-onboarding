package mainserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alastria/isbe-onboarding/types"
)

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestConfigureTSA(t *testing.T) {
	real := []types.Profile{types.PROFILE_ISBE_DEV, types.PROFILE_ISBE_PRE, types.PROFILE_ISBE_PRO}

	t.Run("real profiles require TSA_URL", func(t *testing.T) {
		for _, p := range real {
			cfg := newTsaConfig()
			err := configureTSA(cfg, p, envOf(map[string]string{"TSA_USER": "u", "TSA_PASSWORD": "p"}), os.ReadFile, TSACreds{})
			if err == nil || !strings.Contains(err.Error(), "TSA_URL is required") {
				t.Errorf("%s: expected TSA_URL error, got %v", p, err)
			}
		}
	})

	t.Run("no default credentials in any profile", func(t *testing.T) {
		for _, p := range append(real, types.PROFILE_LOCAL) {
			cfg := newTsaConfig()
			err := configureTSA(cfg, p, envOf(map[string]string{"TSA_URL": "https://tsa.example.test/tsa"}), os.ReadFile, TSACreds{})
			if err == nil || !strings.Contains(err.Error(), "TSA user and password required") {
				t.Errorf("%s: expected credentials error, got %v", p, err)
			}
		}
	})

	t.Run("each environment gets its own endpoint and credentials", func(t *testing.T) {
		cfgs := map[types.Profile]string{}
		for _, p := range real {
			cfg := newTsaConfig()
			env := map[string]string{"TSA_URL": "https://" + string(p) + ".tsa.example.test/tsa", "TSA_USER": "user-" + string(p), "TSA_PASSWORD": "pw"}
			if err := configureTSA(cfg, p, envOf(env), os.ReadFile, TSACreds{}); err != nil {
				t.Fatal(err)
			}
			if cfg.AllowInsecure {
				t.Errorf("%s: insecure mode enabled outside local", p)
			}
			if cfg.Environment != string(p) || cfg.TSAUser != "user-"+string(p) {
				t.Errorf("%s: wrong config %v", p, cfg)
			}
			cfgs[p] = cfg.TSAURL
		}
		if cfgs[types.PROFILE_ISBE_DEV] == cfgs[types.PROFILE_ISBE_PRO] {
			t.Error("profiles share configuration")
		}
	})

	t.Run("secrets file fallback and mounted secret", func(t *testing.T) {
		pw := filepath.Join(t.TempDir(), "pw")
		if err := os.WriteFile(pw, []byte("mounted\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := newTsaConfig()
		env := map[string]string{"TSA_URL": "https://tsa.example.test/tsa", "TSA_PASSWORD_FILE": pw}
		if err := configureTSA(cfg, types.PROFILE_ISBE_PRO, envOf(env), os.ReadFile, TSACreds{User: "yaml-user", Password: "yaml-pw"}); err != nil {
			t.Fatal(err)
		}
		if cfg.TSAUser != "yaml-user" || cfg.TSAPassword != "mounted" {
			t.Errorf("unexpected credentials source: user=%q", cfg.TSAUser)
		}
	})

	t.Run("local profile has a development endpoint", func(t *testing.T) {
		cfg := newTsaConfig()
		if err := configureTSA(cfg, types.PROFILE_LOCAL, envOf(map[string]string{"TSA_USER": "u", "TSA_PASSWORD": "p"}), os.ReadFile, TSACreds{}); err != nil {
			t.Fatal(err)
		}
		if cfg.TSAURL != localTsaURL || !cfg.AllowInsecure {
			t.Errorf("local defaults not applied: %v", cfg)
		}
	})
}
