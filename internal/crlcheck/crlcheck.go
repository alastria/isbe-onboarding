// Package crlcheck checks the revocation status of a validated certificate chain with the
// CRLs published at the CRL distribution points of its certificates. It is shared by the
// TSA token verification and the trust policy for manually approved client certificates.
package crlcheck

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	maxCRLBytes = 10 << 20
	maxSkew     = 5 * time.Minute
)

var (
	// ErrRevoked: a certificate of the chain is revoked.
	ErrRevoked = errors.New("certificate revoked")
	// ErrUnavailable: the revocation status could not be determined (no usable CRL).
	ErrUnavailable = errors.New("revocation status unavailable")
)

// Checker verifies that no certificate of a validated chain (except the trust anchor)
// appears in the CRL published by its issuer. CRLs are signed by the issuer, so they may be
// fetched over plain HTTP; they are cached until their nextUpdate (or a shorter maximum age).
// Redirects are not followed.
type Checker struct {
	client *http.Client
	now    func() time.Time
	maxAge time.Duration

	mu    sync.Mutex
	cache map[string]cachedCRL
}

type cachedCRL struct {
	crl       *x509.RevocationList
	fetchedAt time.Time
}

// Option configures a Checker.
type Option func(*Checker)

// WithMaxCacheAge limits how long a downloaded CRL is reused, so that a new revocation is
// seen soon after the CA publishes it. By default a CRL is reused until its nextUpdate.
func WithMaxCacheAge(d time.Duration) Option { return func(c *Checker) { c.maxAge = d } }

// New creates a Checker that downloads CRLs with a copy of client (redirects disabled).
func New(client *http.Client, now func() time.Time, opts ...Option) *Checker {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	cl := *client
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if now == nil {
		now = time.Now
	}
	c := &Checker{client: &cl, now: now, cache: map[string]cachedCRL{}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Check returns nil if no certificate of chain, except the last one (the trust anchor), is
// revoked according to a valid CRL of its issuer. Errors wrap ErrRevoked or ErrUnavailable.
func (c *Checker) Check(ctx context.Context, chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		if len(cert.CRLDistributionPoints) == 0 {
			return fmt.Errorf("%w: certificate %q has no CRL distribution point", ErrUnavailable, cert.Subject.CommonName)
		}
		var lastErr error
		checked := false
		for _, dp := range cert.CRLDistributionPoints {
			crl, err := c.crl(ctx, dp, issuer)
			if err != nil {
				lastErr = err
				continue
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return fmt.Errorf("%w: certificate %q was revoked on %s", ErrRevoked, cert.Subject.CommonName, entry.RevocationTime.UTC().Format(time.RFC3339))
				}
			}
			checked = true
			break
		}
		if !checked {
			return fmt.Errorf("%w: revocation status of %q could not be determined: %v", ErrUnavailable, cert.Subject.CommonName, lastErr)
		}
	}
	return nil
}

func (c *Checker) crl(ctx context.Context, rawURL string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	now := c.now()

	c.mu.Lock()
	cached, ok := c.cache[rawURL]
	c.mu.Unlock()
	if ok && now.Before(cached.crl.NextUpdate) && (c.maxAge == 0 || now.Sub(cached.fetchedAt) < c.maxAge) &&
		cached.crl.CheckSignatureFrom(issuer) == nil {
		return cached.crl, nil
	}

	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("unsupported CRL distribution point")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching CRL: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching CRL: HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading CRL: %w", err)
	}
	if len(data) > maxCRLBytes {
		return nil, fmt.Errorf("CRL too large")
	}
	crl, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parsing CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, fmt.Errorf("CRL signature: %w", err)
	}
	if crl.NextUpdate.IsZero() || !now.Before(crl.NextUpdate) {
		return nil, fmt.Errorf("CRL is stale (nextUpdate %s)", crl.NextUpdate.UTC().Format(time.RFC3339))
	}
	if crl.ThisUpdate.After(now.Add(maxSkew)) {
		return nil, fmt.Errorf("CRL thisUpdate is in the future")
	}

	c.mu.Lock()
	c.cache[rawURL] = cachedCRL{crl: crl, fetchedAt: now}
	c.mu.Unlock()
	return crl, nil
}
