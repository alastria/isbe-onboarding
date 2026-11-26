package tsaservice

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const maxCRLBytes = 10 << 20

// crlChecker verifies that no certificate of a validated chain (except the
// trust anchor) appears in the CRL published by its issuer. CRLs are signed by
// the issuer, so they may be fetched over plain HTTP; they are cached until
// their nextUpdate. The client used here never carries TSA credentials.
type crlChecker struct {
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	cache map[string]*x509.RevocationList
}

func newCRLChecker(client *http.Client, now func() time.Time) *crlChecker {
	return &crlChecker{client: client, now: now, cache: map[string]*x509.RevocationList{}}
}

func (c *crlChecker) check(ctx context.Context, chain []*x509.Certificate) error {
	for i := 0; i+1 < len(chain); i++ {
		cert, issuer := chain[i], chain[i+1]
		if len(cert.CRLDistributionPoints) == 0 {
			return verificationErrorf(ReasonRevocation, "certificate %q has no CRL distribution point", cert.Subject.CommonName)
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
					return verificationErrorf(ReasonRevocation, "certificate %q was revoked on %s", cert.Subject.CommonName, entry.RevocationTime.UTC().Format(time.RFC3339))
				}
			}
			checked = true
			break
		}
		if !checked {
			return verificationErrorf(ReasonRevocation, "revocation status of %q could not be determined: %v", cert.Subject.CommonName, lastErr)
		}
	}
	return nil
}

func (c *crlChecker) crl(ctx context.Context, rawURL string, issuer *x509.Certificate) (*x509.RevocationList, error) {
	now := c.now()

	c.mu.Lock()
	cached, ok := c.cache[rawURL]
	c.mu.Unlock()
	if ok && now.Before(cached.NextUpdate) && cached.CheckSignatureFrom(issuer) == nil {
		return cached, nil
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
	if crl.ThisUpdate.After(now.Add(DefaultMaxClockSkew)) {
		return nil, fmt.Errorf("CRL thisUpdate is in the future")
	}

	c.mu.Lock()
	c.cache[rawURL] = crl
	c.mu.Unlock()
	return crl, nil
}
