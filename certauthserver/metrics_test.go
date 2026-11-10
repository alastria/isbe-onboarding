package certauth

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"

	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
	"github.com/gofiber/fiber/v2"
)

// Regression test for PR #10 review: the TSA metrics were registered on the
// default Prometheus registry while /metrics served a private fiberprometheus
// registry, so tsa_* never appeared. This scrapes the real /metrics handler.

func scrape(t *testing.T, app *fiber.App) string {
	t.Helper()
	resp, err := app.Test(httptest.NewRequest("GET", "/metrics", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/metrics status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// sample returns the value of the series name{labels} in a text exposition (0 if absent).
func sample(t *testing.T, body, series string) float64 {
	t.Helper()
	re := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(series) + ` ([0-9.eE+-]+)$`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func newMockTSA(t *testing.T, srv *tsatest.Server, password string) *tsaservice.TSAService {
	t.Helper()
	inter := filepath.Join(t.TempDir(), "inter.pem")
	if err := os.WriteFile(inter, []byte(srv.Authority.IntermediatePEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := tsaservice.NewTSAService(&tsaservice.TSAConfig{
		TSAURL:            srv.URL + "/tsa",
		TSAUser:           tsatest.User,
		TSAPassword:       password,
		TrustAnchorsPEM:   srv.Authority.RootPEM(),
		IntermediatesFile: inter,
		AllowInsecure:     true,
	}, tsaservice.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestMetricsEndpointExposesTSAMetrics(t *testing.T) {
	app := fiber.New()
	if err := setupMetrics(app); err != nil {
		t.Fatal(err)
	}
	app.Get("/health", func(c *fiber.Ctx) error { return c.SendString("ok") })

	before := scrape(t, app)
	for _, name := range []string{"tsa_requests_total", "tsa_request_duration_seconds", "go_goroutines", "process_cpu_seconds_total"} {
		if !regexp.MustCompile(`(?m)^# HELP ` + name + ` `).MatchString(before) {
			t.Errorf("/metrics does not describe %s", name)
		}
	}

	srv := tsatest.New(t).NewServer(t)
	ctx := context.Background()

	// One success.
	if _, err := newMockTSA(t, srv, tsatest.Password).Timestamp(ctx, []byte("ok")); err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	// One authentication error.
	if _, err := newMockTSA(t, srv, "wrong-password").Timestamp(ctx, []byte("auth")); err == nil {
		t.Fatal("expected an authentication error")
	}
	// One verification failure (tampered signature).
	srv.SetOptions(tsatest.TokenOptions{TamperSignature: true})
	if _, err := newMockTSA(t, srv, tsatest.Password).Timestamp(ctx, []byte("bad")); err == nil {
		t.Fatal("expected a verification failure")
	}
	if _, err := app.Test(httptest.NewRequest("GET", "/health", nil), -1); err != nil {
		t.Fatal(err)
	}

	after := scrape(t, app)
	for _, name := range []string{"tsa_errors_total", "tsa_verification_failures_total"} {
		if !regexp.MustCompile(`(?m)^# HELP ` + name + ` `).MatchString(after) {
			t.Errorf("/metrics does not describe %s after errors", name)
		}
	}
	checks := map[string]float64{
		`tsa_requests_total{outcome="success"}`:                 1,
		`tsa_requests_total{outcome="http_error"}`:              1,
		`tsa_requests_total{outcome="verification_failed"}`:     1,
		`tsa_errors_total{reason="auth"}`:                       1,
		`tsa_verification_failures_total{reason="signature"}`:   1,
		`tsa_request_duration_seconds_count{outcome="success"}`: 1,
	}
	for series, want := range checks {
		if got := sample(t, after, series) - sample(t, before, series); got != want {
			t.Errorf("%s increased by %v, want %v", series, got, want)
		}
	}
	if sample(t, after, `http_requests_total{method="GET",path="/health",service="certauth",status_code="200"}`) < 1 &&
		!regexp.MustCompile(`(?m)^http_requests_total\{.*path="/health".*\} [1-9]`).MatchString(after) {
		t.Error("/metrics does not include the HTTP metrics of the same app")
	}

	// A second server in the same process must not panic or fail (fresh registry).
	if err := setupMetrics(fiber.New()); err != nil {
		t.Fatalf("second setupMetrics: %v", err)
	}
}
