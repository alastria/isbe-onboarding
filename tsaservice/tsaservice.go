// Package tsaservice is a client for RFC 3161 Time Stamping Authorities (TSA)
// together with a strict, fail-closed verifier for the tokens they return.
//
// The two entry points are:
//
//   - TSAService.Timestamp: requests a token for some data and returns it only
//     after it has passed every verification check (signature, chain of trust,
//     EKU, ESS binding, message imprint, nonce, policy and freshness).
//   - Verifier.Verify: verifies a stored token against the original data, for
//     example to re-check historical evidence. It needs no TSA credentials.
//
// A successful cryptographic verification proves that a TSA trusted by the
// configured trust anchors asserted the time. It does NOT by itself prove that
// the token is an eIDAS qualified electronic time stamp: that additionally
// requires checking the TSA service status in the EU Trusted Lists at genTime
// (see README.md in this directory).
package tsaservice

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"mime"
	"net"
	"net/http"
	"net/url"
	"time"
)

const userAgent = "isbe-onboarding-tsa-client/1"

// Option customises a TSAService or Verifier. Options exist mainly for tests.
type Option func(*options)

type options struct {
	httpClient *http.Client
	now        func() time.Time
	logger     *slog.Logger
}

// WithHTTPClient sets the HTTP client. Redirects are always disabled on it.
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.httpClient = c } }

// WithClock sets the clock used for freshness and revocation checks.
func WithClock(now func() time.Time) Option { return func(o *options) { o.now = now } }

// WithLogger sets the logger. By default slog.Default() is used at call time.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.logger = l } }

func buildOptions(cfg *TSAConfig, opts []Option) options {
	o := options{now: time.Now}
	for _, opt := range opts {
		opt(&o)
	}
	if o.httpClient == nil {
		o.httpClient = newHTTPClient(cfg.Timeout)
	} else {
		c := *o.httpClient
		o.httpClient = &c
	}
	// Never follow redirects: they could forward the Authorization header or
	// let a third party decide which certificate or CRL we load.
	o.httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return o
}

func newHTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	tr.ResponseHeaderTimeout = timeout
	return &http.Client{Timeout: timeout, Transport: tr}
}

// Verifier verifies RFC 3161 tokens against a trust store and policy.
type Verifier struct {
	roots         *x509.CertPool
	intermediates []*x509.Certificate
	policy        asn1.ObjectIdentifier
	revocation    *crlChecker
	now           func() time.Time
}

// NewVerifier builds a verifier from the trust and policy settings of cfg.
// The TSA URL and credentials are not needed.
func NewVerifier(ctx context.Context, cfg *TSAConfig, opts ...Option) (*Verifier, error) {
	c := *cfg
	c.applyDefaults()
	if err := c.validateVerification(); err != nil {
		return nil, err
	}
	o := buildOptions(&c, opts)
	return newVerifier(ctx, &c, o)
}

func newVerifier(ctx context.Context, cfg *TSAConfig, o options) (*Verifier, error) {
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "tsa", "profile", cfg.Environment)

	dlCtx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	ts, err := loadTrustStore(dlCtx, cfg, o.httpClient, logger)
	if err != nil {
		return nil, err
	}
	v := &Verifier{roots: ts.roots, intermediates: ts.intermediates, now: o.now}
	if cfg.PolicyOID != "" {
		if v.policy, err = parseOID(cfg.PolicyOID); err != nil {
			return nil, configErrorf("TSA_POLICY_OID: %v", err)
		}
	}
	if cfg.RevocationCheck == RevocationCRL {
		v.revocation = newCRLChecker(o.httpClient, o.now)
	}
	return v, nil
}

// Verify verifies a stored DER TimeStampResp against the data that was
// timestamped, as needed for historical evidence. The chain is validated at
// the token's genTime. Nonce and freshness are not checked (they only make sense
// right after the request) and neither is revocation, which for long-term
// validation requires revocation data archived at genTime.
func (v *Verifier) Verify(tsr, data []byte) (*VerifiedToken, error) {
	return v.verifyResponse(context.Background(), tsr, verifyParams{imprint: matchData(data)})
}

// VerifyDigest is like Verify but takes the digest of the data instead of the data.
func (v *Verifier) VerifyDigest(tsr []byte, hashAlgorithmName string, digest []byte) (*VerifiedToken, error) {
	alg, ok := hashAlgorithmByName(hashAlgorithmName)
	if !ok {
		return nil, fmt.Errorf("%w: unsupported hash algorithm %q", ErrInvalidConfig, hashAlgorithmName)
	}
	return v.verifyResponse(context.Background(), tsr, verifyParams{imprint: matchDigest(alg, digest)})
}

// TSAService requests and verifies timestamps from a TSA.
type TSAService struct {
	*Verifier

	cfg     TSAConfig
	hash    hashAlgorithm
	client  *http.Client
	logger  *slog.Logger
	tsaHost string
}

// Token is a verified timestamp obtained from the TSA.
type Token struct {
	// Response is the DER TimeStampResp exactly as returned by the TSA. This is
	// what must be stored as evidence.
	Response []byte
	*VerifiedToken
}

// NewTSAService validates the configuration, loads the trust store and returns
// a ready service. It fails if anything is missing or unsafe: there are no
// built-in credentials or silent fallbacks.
func NewTSAService(cfg *TSAConfig, opts ...Option) (*TSAService, error) {
	if cfg == nil {
		return nil, configErrorf("missing configuration")
	}
	c := *cfg
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	o := buildOptions(&c, opts)

	v, err := newVerifier(context.Background(), &c, o)
	if err != nil {
		return nil, err
	}
	hash, _ := hashAlgorithmByName(c.HashAlgorithm)
	u, _ := url.Parse(c.TSAURL)

	s := &TSAService{Verifier: v, cfg: c, hash: hash, client: o.httpClient, logger: o.logger, tsaHost: u.Host}
	if c.AllowInsecure && u.Scheme == "http" {
		s.log().Warn("TSA endpoint uses plain HTTP; only acceptable for local development")
	}
	s.log().Info("TSA service configured", "config", c)
	return s, nil
}

// String and GoString keep fmt from printing the credentials held in the
// unexported cfg field (fmt does not call methods on unexported fields).
func (s *TSAService) String() string { return "TSAService{" + s.cfg.String() + "}" }

// GoString implements fmt.GoStringer.
func (s *TSAService) GoString() string { return s.String() }

func (s *TSAService) log() *slog.Logger {
	l := s.logger
	if l == nil {
		l = slog.Default()
	}
	return l.With("component", "tsa", "profile", s.cfg.Environment, "tsa_host", s.tsaHost)
}

type correlationKey struct{}

// WithCorrelationID returns a context whose TSA log lines carry the given ID.
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationKey{}, id)
}

func correlationID(ctx context.Context) string {
	id, _ := ctx.Value(correlationKey{}).(string)
	return id
}

func newOperationID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Timestamp requests a time-stamp token for data and returns it only if it
// passes every verification check. No retries are made: each request may be
// billed by the provider and creates a distinct token.
func (s *TSAService) Timestamp(ctx context.Context, data []byte) (*Token, error) {
	start := s.now()
	log := s.log().With("op_id", newOperationID())
	if cid := correlationID(ctx); cid != "" {
		log = log.With("correlation_id", cid)
	}

	finish := func(outcome string) time.Duration {
		d := s.now().Sub(start)
		metricRequests.WithLabelValues(outcome).Inc()
		metricDuration.WithLabelValues(outcome).Observe(d.Seconds())
		return d
	}

	digest := s.hash.sum(data)
	var nonce *big.Int
	if !s.cfg.DisableNonce {
		n, err := newNonce()
		if err != nil {
			finish(outcomeTransportError)
			metricErrors.WithLabelValues(errReasonInternalError).Inc()
			return nil, fmt.Errorf("generating nonce: %w", err)
		}
		nonce = n
	}
	tsq, err := buildTimeStampReq(s.hash, digest, nonce, s.policy)
	if err != nil {
		finish(outcomeTransportError)
		metricErrors.WithLabelValues(errReasonInternalError).Inc()
		return nil, fmt.Errorf("encoding TimeStampReq: %w", err)
	}

	log.Info("TSA timestamp request started", "hash_algorithm", s.hash.name, "nonce", nonce != nil, "data_bytes", len(data))

	body, httpStatus, err := s.exchange(ctx, tsq, log)
	if err != nil {
		reason, outcome := classifyTransportError(err)
		d := finish(outcome)
		metricErrors.WithLabelValues(reason).Inc()
		log.Error("TSA request failed", "reason", reason, "http_status", httpStatus, "duration_ms", d.Milliseconds(), "error", err)
		return nil, err
	}
	log.Info("TSA HTTP response received", "http_status", httpStatus, "response_bytes", len(body), "duration_ms", s.now().Sub(start).Milliseconds())

	vt, err := s.verifyResponse(ctx, body, verifyParams{
		imprint:         matchDigest(s.hash, digest),
		nonce:           nonce,
		notBefore:       start.Add(-s.cfg.MaxClockSkew),
		notAfter:        s.now().Add(s.cfg.MaxClockSkew),
		checkRevocation: true,
	})
	if err != nil {
		reason := reasonOf(err)
		if errors.Is(err, ErrTimestampRejected) {
			d := finish(outcomeRejected)
			metricErrors.WithLabelValues(errReasonRejected).Inc()
			log.Error("TSA rejected the timestamp request", "duration_ms", d.Milliseconds(), "error", err)
			return nil, err
		}
		d := finish(outcomeVerificationFailed)
		metricVerificationFailures.WithLabelValues(reason).Inc()
		if reason == ReasonMalformed {
			metricErrors.WithLabelValues(errReasonMalformed).Inc()
		}
		log.Error("TSA token verification failed", "reason", reason, "duration_ms", d.Milliseconds(), "error", err)
		return nil, err
	}

	d := finish(outcomeSuccess)
	log.Info("TSA token verified",
		"duration_ms", d.Milliseconds(),
		"gen_time", vt.GenTime.Format(time.RFC3339Nano),
		"token_serial", vt.SerialNumber.Text(16),
		"policy", vt.Policy,
		"accuracy", vt.Accuracy.String(),
		"signer", vt.Signer.Subject.CommonName,
		"signer_sha256", certFingerprint(vt.Signer),
		"revocation_checked", vt.RevocationChecked,
	)
	return &Token{Response: body, VerifiedToken: vt}, nil
}

// exchange performs the HTTP POST. It never includes the response body or the
// credentials in errors or logs.
func (s *TSAService) exchange(ctx context.Context, tsq []byte, log *slog.Logger) ([]byte, int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, s.cfg.TSAURL, bytes.NewReader(tsq))
	if err != nil {
		return nil, 0, fmt.Errorf("%w: building request: %v", ErrNetwork, err)
	}
	req.SetBasicAuth(s.cfg.TSAUser, s.cfg.TSAPassword)
	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("Accept", "application/timestamp-reply")
	req.Header.Set("User-Agent", userAgent)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, 0, transportError(ctx, reqCtx, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
	}()

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
	case code == http.StatusUnauthorized || code == http.StatusForbidden:
		return nil, code, fmt.Errorf("%w (HTTP %d)", ErrAuthentication, code)
	case code == http.StatusTooManyRequests:
		log.Warn("TSA rate limit", "retry_after", sanitizeText(resp.Header.Get("Retry-After"), 40))
		return nil, code, fmt.Errorf("%w (HTTP %d)", ErrRateLimited, code)
	case code >= 500:
		return nil, code, fmt.Errorf("%w (HTTP %d)", ErrServiceUnavailable, code)
	default:
		return nil, code, fmt.Errorf("%w (HTTP %d)", ErrUnexpectedHTTPStatus, code)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "" {
		if mt, _, err := mime.ParseMediaType(ct); err != nil || mt != "application/timestamp-reply" {
			log.Warn("TSA response has an unexpected Content-Type", "content_type", sanitizeText(ct, 80))
		}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, DefaultMaxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, transportError(ctx, reqCtx, err)
	}
	if len(body) > DefaultMaxResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("%w (more than %d bytes)", ErrResponseTooLarge, DefaultMaxResponseBytes)
	}
	return body, resp.StatusCode, nil
}

func transportError(parent, reqCtx context.Context, err error) error {
	// *url.Error repeats the full URL (including any query string); keep only the cause.
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	switch {
	case errors.Is(parent.Err(), context.Canceled):
		return fmt.Errorf("%w: %v", ErrCanceled, err)
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(reqCtx.Err(), context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	default:
		return fmt.Errorf("%w: %v", ErrNetwork, err)
	}
}

func classifyTransportError(err error) (reason, outcome string) {
	switch {
	case errors.Is(err, ErrAuthentication):
		return errReasonAuth, outcomeHTTPError
	case errors.Is(err, ErrRateLimited):
		return errReasonRateLimited, outcomeHTTPError
	case errors.Is(err, ErrServiceUnavailable):
		return errReasonServerError, outcomeHTTPError
	case errors.Is(err, ErrUnexpectedHTTPStatus):
		return errReasonHTTPStatus, outcomeHTTPError
	case errors.Is(err, ErrResponseTooLarge):
		return errReasonTooLarge, outcomeTransportError
	case errors.Is(err, ErrTimeout):
		return errReasonTimeout, outcomeTransportError
	case errors.Is(err, ErrCanceled):
		return errReasonCanceled, outcomeTransportError
	default:
		return errReasonNetwork, outcomeTransportError
	}
}
