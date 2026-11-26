package tsaservice

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// newTestService returns a service pointed at srv, trusting srv's root and
// with srv's intermediate configured (the fake, like DigitelTS, only embeds the
// TSU certificate in its tokens).
func newTestService(t *testing.T, srv *tsatest.Server, mutate func(*TSAConfig), opts ...Option) *TSAService {
	t.Helper()
	inter := filepath.Join(t.TempDir(), "intermediates.pem")
	if err := os.WriteFile(inter, []byte(srv.Authority.IntermediatePEM()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := TSAConfig{
		TSAURL:            srv.URL + "/tsa",
		TSAUser:           tsatest.User,
		TSAPassword:       tsatest.Password,
		TrustAnchorsPEM:   srv.Authority.RootPEM(),
		IntermediatesFile: inter,
		AllowInsecure:     true, // httptest serves plain HTTP
		Environment:       "test",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	if !hasLogger(opts) {
		opts = append(opts, WithLogger(discardLogger()))
	}
	s, err := NewTSAService(&cfg, opts...)
	if err != nil {
		t.Fatalf("NewTSAService: %v", err)
	}
	return s
}

func hasLogger(opts []Option) bool {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	return o.logger != nil
}

func TestTimestampSuccess(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	s := newTestService(t, srv, nil)
	data := []byte("contract and certificate")

	tok, err := s.Timestamp(context.Background(), data)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if len(tok.Response) == 0 || tok.SerialNumber == nil || tok.GenTime.IsZero() {
		t.Fatalf("incomplete token: %+v", tok)
	}

	reqs := srv.Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	want := sha512.Sum512(data)
	if !bytes.Equal(reqs[0].Digest, want[:]) || !reqs[0].HashOID.Equal(oidSHA512) {
		t.Error("request does not carry the SHA-512 imprint of the data")
	}
	if reqs[0].Nonce == nil || !reqs[0].CertReq {
		t.Error("request must carry a nonce and certReq=true")
	}
	if tok.Nonce == nil || tok.Nonce.Cmp(reqs[0].Nonce) != 0 {
		t.Error("token nonce not returned")
	}

	h := srv.LastHeaders()
	if got := h.Get("Content-Type"); got != "application/timestamp-query" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := h.Get("Accept"); got != "application/timestamp-reply" {
		t.Errorf("Accept = %q", got)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(tsatest.User+":"+tsatest.Password))
	if h.Get("Authorization") != wantAuth {
		t.Error("Authorization header does not carry the configured credentials")
	}
	if srv.LastPath() != "/tsa" {
		t.Errorf("configured URL path not used: %q", srv.LastPath())
	}

	// The stored response verifies again later as historical evidence.
	if _, err := s.Verify(tok.Response, data); err != nil {
		t.Fatalf("historical verification of a fresh token: %v", err)
	}
}

func TestTimestampUsesConfiguredCredentials(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	s := newTestService(t, srv, func(c *TSAConfig) { c.TSAPassword = "wrong" })

	_, err := s.Timestamp(context.Background(), []byte("x"))
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("expected ErrAuthentication, got %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("error leaks credentials or response body: %v", err)
	}
}

func TestTimestampHTTPStatuses(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusUnauthorized, ErrAuthentication},
		{http.StatusForbidden, ErrAuthentication},
		{http.StatusTooManyRequests, ErrRateLimited},
		{http.StatusInternalServerError, ErrServiceUnavailable},
		{http.StatusBadGateway, ErrServiceUnavailable},
		{http.StatusServiceUnavailable, ErrServiceUnavailable},
		{http.StatusBadRequest, ErrUnexpectedHTTPStatus},
		{http.StatusFound, ErrUnexpectedHTTPStatus},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := tsatest.New(t).NewServer(t)
			srv.SetHandler(func(w http.ResponseWriter, r *http.Request) {
				if tc.status == http.StatusFound {
					w.Header().Set("Location", "http://127.0.0.1:1/elsewhere")
				}
				w.Header().Set("Retry-After", "30")
				http.Error(w, "secret-looking body that must not be logged", tc.status)
			})
			s := newTestService(t, srv, nil)
			_, err := s.Timestamp(context.Background(), []byte("x"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "secret-looking") {
				t.Fatalf("error contains the response body: %v", err)
			}
		})
	}
}

func TestTimestampDoesNotFollowRedirects(t *testing.T) {
	target := tsatest.New(t).NewServer(t)
	srv := tsatest.New(t).NewServer(t)
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/tsa", http.StatusTemporaryRedirect)
	})
	s := newTestService(t, srv, nil)

	_, err := s.Timestamp(context.Background(), []byte("x"))
	if !errors.Is(err, ErrUnexpectedHTTPStatus) {
		t.Fatalf("expected redirect to be refused, got %v", err)
	}
	if target.LastHeaders() != nil {
		t.Fatal("the redirect target was contacted (credentials could have leaked)")
	}
}

func TestTimestampTimeout(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	s := newTestService(t, srv, func(c *TSAConfig) { c.Timeout = 150 * time.Millisecond })

	start := time.Now()
	_, err := s.Timestamp(context.Background(), []byte("x"))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestTimestampContextCancellation(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // runs before the server is closed
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		// The server only notices a closed connection once the body has been read.
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	s := newTestService(t, srv, nil)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-started
		cancel()
	}()
	_, err := s.Timestamp(ctx, []byte("x"))
	if !errors.Is(err, ErrCanceled) {
		t.Fatalf("expected ErrCanceled, got %v", err)
	}
}

func TestTimestampResponseTooLarge(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(bytes.Repeat([]byte{0x30}, DefaultMaxResponseBytes+10))
	})
	s := newTestService(t, srv, nil)

	_, err := s.Timestamp(context.Background(), []byte("x"))
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("expected ErrResponseTooLarge, got %v", err)
	}
}

func TestTimestampMalformedResponse(t *testing.T) {
	for name, body := range map[string][]byte{
		"empty":     {},
		"garbage":   []byte("<html>not a timestamp</html>"),
		"truncated": {0x30, 0x82, 0x10, 0x00, 0x30},
		"trailing":  {0x30, 0x03, 0x02, 0x01, 0x00, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			srv := tsatest.New(t).NewServer(t)
			srv.SetHandler(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
			s := newTestService(t, srv, nil)
			_, err := s.Timestamp(context.Background(), []byte("x"))
			if !errors.Is(err, ErrMalformedResponse) || !errors.Is(err, ErrVerificationFailed) {
				t.Fatalf("expected a malformed-response verification error, got %v", err)
			}
		})
	}
}

func TestTimestampRejectedStatus(t *testing.T) {
	srv := tsatest.New(t).NewServer(t)
	srv.SetOptions(tsatest.TokenOptions{Status: 2, StatusText: "badAlg\x00\x07"})
	s := newTestService(t, srv, nil)

	_, err := s.Timestamp(context.Background(), []byte("x"))
	if !errors.Is(err, ErrTimestampRejected) {
		t.Fatalf("expected ErrTimestampRejected, got %v", err)
	}
	if strings.ContainsAny(err.Error(), "\x00\x07") {
		t.Fatal("provider text was not sanitised")
	}
}

func TestTimestampNonce(t *testing.T) {
	t.Run("wrong nonce", func(t *testing.T) {
		srv := tsatest.New(t).NewServer(t)
		srv.SetOptions(tsatest.TokenOptions{Nonce: bigOne()})
		_, err := newTestService(t, srv, nil).Timestamp(context.Background(), []byte("x"))
		if reasonOf(err) != ReasonNonce {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("missing nonce", func(t *testing.T) {
		srv := tsatest.New(t).NewServer(t)
		srv.SetOptions(tsatest.TokenOptions{OmitNonce: true})
		_, err := newTestService(t, srv, nil).Timestamp(context.Background(), []byte("x"))
		if reasonOf(err) != ReasonNonce {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("replayed response", func(t *testing.T) {
		srv := tsatest.New(t).NewServer(t)
		s := newTestService(t, srv, nil)
		data := []byte("same data")
		first, err := s.Timestamp(context.Background(), data)
		if err != nil {
			t.Fatal(err)
		}
		// An attacker (or a caching proxy) answers the next request with the
		// previous, perfectly valid, response for the same data.
		srv.SetHandler(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(first.Response) })
		_, err = s.Timestamp(context.Background(), data)
		if reasonOf(err) != ReasonNonce {
			t.Fatalf("replayed response accepted or wrong reason: %v", err)
		}
	})

	t.Run("fresh nonce per request", func(t *testing.T) {
		srv := tsatest.New(t).NewServer(t)
		s := newTestService(t, srv, nil)
		for i := 0; i < 5; i++ {
			if _, err := s.Timestamp(context.Background(), []byte("x")); err != nil {
				t.Fatal(err)
			}
		}
		seen := map[string]bool{}
		for _, r := range srv.Requests() {
			if seen[r.Nonce.String()] {
				t.Fatal("nonce repeated across requests")
			}
			seen[r.Nonce.String()] = true
		}
	})

	t.Run("disabled", func(t *testing.T) {
		srv := tsatest.New(t).NewServer(t)
		s := newTestService(t, srv, func(c *TSAConfig) { c.DisableNonce = true })
		if _, err := s.Timestamp(context.Background(), []byte("x")); err != nil {
			t.Fatal(err)
		}
		if srv.Requests()[0].Nonce != nil {
			t.Fatal("nonce sent although disabled")
		}
	})
}

func TestTimestampNeverLogsSecrets(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srv := tsatest.New(t).NewServer(t)
	s := newTestService(t, srv, nil, WithLogger(logger))
	if _, err := s.Timestamp(WithCorrelationID(context.Background(), "corr-123"), []byte("x")); err != nil {
		t.Fatal(err)
	}
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusUnauthorized) })
	_, _ = s.Timestamp(context.Background(), []byte("x"))
	srv.SetHandler(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("junk")) })
	_, _ = s.Timestamp(context.Background(), []byte("x"))

	out := buf.String()
	basic := base64.StdEncoding.EncodeToString([]byte(tsatest.User + ":" + tsatest.Password))
	for _, secret := range []string{tsatest.Password, basic, "Authorization"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log output contains %q:\n%s", secret, out)
		}
	}
	for _, want := range []string{"correlation_id=corr-123", "TSA token verified", "reason=auth", "reason=malformed", "password_set=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("log output lacks %q", want)
		}
	}
}
