package mainserver

import (
	"reflect"
	"strings"
	"testing"
	"time"

	certauth "github.com/alastria/isbe-onboarding/certauthserver"
	"github.com/alastria/isbe-onboarding/internal/email"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/tsaservice"
)

// fillStrings sets every exported string field reachable from v to a unique
// marker "VAL:<path>" and returns path -> field name for each of them.
func fillStrings(t *testing.T, v reflect.Value, path string, out map[string]string) {
	t.Helper()
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		fillStrings(t, v.Elem(), path, out)
	case reflect.Struct:
		if v.Type() == reflect.TypeOf(time.Time{}) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Type().Field(i)
			if !f.IsExported() {
				continue
			}
			p := path + "." + f.Name
			if v.Field(i).Kind() == reflect.String {
				v.Field(i).SetString("VAL:" + p)
				out[p] = f.Name
				continue
			}
			fillStrings(t, v.Field(i), p, out)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			return
		}
		if v.Len() == 0 {
			v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		}
		for i := 0; i < v.Len(); i++ {
			fillStrings(t, v.Index(i), path+"[]", out)
		}
	}
}

func TestRedactedConfigJSONHidesEverySecret(t *testing.T) {
	cfg := &Config{}
	fields := map[string]string{}
	fillStrings(t, reflect.ValueOf(cfg), "cfg", fields)

	out, err := RedactedConfigJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dump := string(out)

	sensitive := 0
	for path, name := range fields {
		if sensitiveKey.MatchString(name) {
			sensitive++
			if strings.Contains(dump, "VAL:"+path+`"`) {
				t.Errorf("secret field %s printed in the configuration dump", path)
			}
		}
	}
	// The fields that motivated the change must be among the ones covered.
	for _, must := range []string{
		"cfg.CertAuthConfig.EmailConfig.Password",
		"cfg.CertAuthConfig.ManagementAPIKey",
		"cfg.CertAuthConfig.TMFAdminToken",
		"cfg.PredefinedRPs[].ClientSecret",
		"cfg.CertAuthConfig.TSAConfig.TSAPassword",
	} {
		if _, ok := fields[must]; !ok {
			t.Errorf("test did not reach %s; update the test", must)
		}
	}
	if sensitive < 5 {
		t.Fatalf("only %d sensitive fields found", sensitive)
	}
	// Non-secret settings stay visible for diagnosis.
	if !strings.Contains(dump, "VAL:cfg.OnboardURL") || !strings.Contains(dump, "VAL:cfg.CertAuthConfig.EmailConfig.SMTP") {
		t.Errorf("non-secret settings were removed:\n%s", dump)
	}
	if !strings.Contains(dump, redacted) {
		t.Error("no value was redacted")
	}
}

func TestRedactedConfigJSONRealValues(t *testing.T) {
	cfg := &Config{
		OnboardURL: "https://onboard.example.test",
		CertAuthConfig: &certauth.ConfigCertAuth{
			ManagementAPIKey: "mgmt-key-value",
			TMFAdminToken:    "tmf-token-value",
			EmailConfig:      &email.EmailConfig{User: "mailer", Password: "smtp-password-value"},
			TSAConfig:        &tsaservice.TSAConfig{TSAURL: "https://tsa.example.test/tsa", TSAUser: "u", TSAPassword: "tsa-password-value"},
		},
		PredefinedRPs: []PredefinedRP{{RelyingParty: &models.RelyingParty{ClientID: "rp", TokenExpiry: 3600}, ClientSecret: "rp-secret-value"}},
	}
	out, err := RedactedConfigJSON(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"mgmt-key-value", "tmf-token-value", "smtp-password-value", "tsa-password-value", "rp-secret-value"} {
		if strings.Contains(string(out), secret) {
			t.Errorf("%q printed:\n%s", secret, out)
		}
	}
	if !strings.Contains(string(out), `"token_expiry": 3600`) {
		t.Error("TokenExpiry must not be treated as a secret")
	}
}

func TestSensitiveKeyPattern(t *testing.T) {
	for _, k := range []string{"Password", "TSAPassword", "ClientSecret", "ManagementAPIKey", "api_key", "TMFAdminToken", "token", "PrivateKey", "credentials"} {
		if !sensitiveKey.MatchString(k) {
			t.Errorf("%s not considered sensitive", k)
		}
	}
	for _, k := range []string{"TokenExpiry", "token_expiry", "User", "OnboardURL", "ClientID", "url"} {
		if sensitiveKey.MatchString(k) {
			t.Errorf("%s wrongly considered sensitive", k)
		}
	}
}

// Regression test for PR #10 review: the boolean TSA "password_set" flag was
// printed as "[REDACTED]", hiding whether TSA_PASSWORD was configured.
func TestRedactedConfigJSONKeepsPresenceFlags(t *testing.T) {
	const secretPassword = "VAL:tsa-password-must-not-leak"
	for _, set := range []bool{true, false} {
		cfg := &Config{CertAuthConfig: &certauth.ConfigCertAuth{TSAConfig: &tsaservice.TSAConfig{TSAUser: "u"}}}
		if set {
			cfg.CertAuthConfig.TSAConfig.TSAPassword = secretPassword
		}
		out, err := RedactedConfigJSON(cfg)
		if err != nil {
			t.Fatal(err)
		}
		dump := string(out)
		if strings.Contains(dump, secretPassword) {
			t.Fatal("TSA password printed in the configuration dump")
		}
		want := `"password_set": ` + map[bool]string{true: "true", false: "false"}[set]
		if !strings.Contains(dump, want) {
			t.Errorf("dump does not contain %s:\n%s", want, dump)
		}
	}
}

func TestRedactTreeOnlyKeepsBooleans(t *testing.T) {
	tree := map[string]any{
		"password_set":   true,
		"password":       "hunter2-not-real",
		"api_key":        float64(12345),
		"secret":         map[string]any{"value": "x"},
		"client_secret":  []any{"a"},
		"empty_password": "",
	}
	got := redactTree(tree).(map[string]any)
	if got["password_set"] != true {
		t.Errorf("password_set = %v", got["password_set"])
	}
	for _, k := range []string{"password", "api_key", "secret", "client_secret"} {
		if got[k] != redacted {
			t.Errorf("%s = %v, want redacted", k, got[k])
		}
	}
	if got["empty_password"] != "" {
		t.Errorf("empty secret should stay visible as empty")
	}
}
