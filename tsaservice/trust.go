package tsaservice

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

// The embedded trust store holds public certificates of the DigitelTS
// hierarchy, reviewed and versioned with the code. See trust/README.md for
// their provenance and fingerprints. It contains no secret material.
//
//go:embed trust/digitelts/root-ca.pem trust/digitelts/qualified-ca-tsa-g1.pem
var embeddedTrust embed.FS

const (
	embeddedRootFile         = "trust/digitelts/root-ca.pem"
	embeddedIntermediateFile = "trust/digitelts/qualified-ca-tsa-g1.pem"

	// EmbeddedRootSHA256 is the fingerprint of the embedded DigitelTS root ("DIGITEL TS CA ROOT 01").
	EmbeddedRootSHA256 = "011e258310b37f92030d14a672079507632cf72789fc101ce0a0bdc5ef2808cc"

	maxCADownloadBytes = 256 << 10
)

// trustStore is the set of certificates used for path validation.
type trustStore struct {
	source        string
	roots         *x509.CertPool
	anchors       []*x509.Certificate
	intermediates []*x509.Certificate
}

// loadTrustStore builds the trust store from the configuration. It fails when
// the configuration is invalid, when no anchor can be loaded or when a pin does
// not match: a TSA client must never run with an unknown trust configuration.
func loadTrustStore(ctx context.Context, cfg *TSAConfig, client *http.Client, logger *slog.Logger) (*trustStore, error) {
	ts := &trustStore{source: cfg.trustSource(), roots: x509.NewCertPool()}

	var anchorsData []byte
	var err error
	switch ts.source {
	case "file":
		if anchorsData, err = os.ReadFile(cfg.TrustAnchorsFile); err != nil {
			return nil, configErrorf("cannot read TSA_TRUST_ANCHORS_FILE: %v", err)
		}
	case "pem":
		anchorsData = []byte(cfg.TrustAnchorsPEM)
	case "url":
		if anchorsData, err = downloadCACertificate(ctx, client, cfg.CACertURL); err != nil {
			return nil, configErrorf("cannot download the CA certificate from %s: %v", redactURL(cfg.CACertURL), err)
		}
	default:
		if anchorsData, err = embeddedTrust.ReadFile(embeddedRootFile); err != nil {
			return nil, configErrorf("embedded trust store: %v", err)
		}
	}

	if ts.anchors, err = parseCertificates(anchorsData); err != nil {
		return nil, configErrorf("trust anchors (%s): %v", ts.source, err)
	}

	// DigitelTS tokens do not carry the "CA TSA G1" intermediate, so the
	// embedded copy is offered as a path-building candidate whatever the anchor
	// source (file, PEM, URL or embedded). It is never an anchor: it is kept
	// only when one of the configured anchors signed it, and signer.Verify still
	// requires the whole path to end in a configured anchor. With anchors of a
	// different hierarchy it is simply not loaded.
	embeddedInter, err := embeddedIntermediates()
	if err != nil {
		return nil, err
	}
	for _, c := range embeddedInter {
		if issuedByAnyOf(c, ts.anchors) {
			ts.intermediates = append(ts.intermediates, c)
		} else {
			logger.Info("embedded TSA intermediate not used: no configured trust anchor issued it", "subject", c.Subject.String(), "sha256", certFingerprint(c), "source", ts.source)
		}
	}

	if len(cfg.TrustAnchorSHA256) > 0 {
		pins := map[string]bool{}
		for _, p := range cfg.TrustAnchorSHA256 {
			f, err := normalizeFingerprint(p)
			if err != nil {
				return nil, configErrorf("TSA_TRUST_ANCHOR_SHA256: %v", err)
			}
			pins[f] = true
		}
		for _, a := range ts.anchors {
			if !pins[certFingerprint(a)] {
				return nil, configErrorf("trust anchor %q (sha256 %s) does not match TSA_TRUST_ANCHOR_SHA256", a.Subject.CommonName, certFingerprint(a))
			}
		}
	}

	if cfg.IntermediatesFile != "" {
		data, err := os.ReadFile(cfg.IntermediatesFile)
		if err != nil {
			return nil, configErrorf("cannot read TSA_INTERMEDIATES_FILE: %v", err)
		}
		extra, err := parseCertificates(data)
		if err != nil {
			return nil, configErrorf("TSA_INTERMEDIATES_FILE: %v", err)
		}
		for _, c := range extra {
			if !containsCert(ts.intermediates, c) {
				ts.intermediates = append(ts.intermediates, c)
			}
		}
	}

	now := time.Now()
	for _, a := range ts.anchors {
		ts.roots.AddCert(a)
		attrs := []any{"subject", a.Subject.String(), "sha256", certFingerprint(a), "not_after", a.NotAfter.Format(time.RFC3339), "source", ts.source}
		logger.Info("TSA trust anchor loaded", attrs...)
		if !a.IsCA || !a.BasicConstraintsValid {
			logger.Warn("TSA trust anchor is not a CA certificate; it will only validate itself", "subject", a.Subject.String())
		}
		if now.After(a.NotAfter) {
			logger.Warn("TSA trust anchor has expired; only historical tokens can validate against it", "subject", a.Subject.String())
		}
	}
	for _, c := range ts.intermediates {
		logger.Info("TSA intermediate certificate loaded", "subject", c.Subject.String(), "sha256", certFingerprint(c), "not_after", c.NotAfter.Format(time.RFC3339))
	}
	return ts, nil
}

// embeddedIntermediates returns the intermediate CA certificates versioned with the code.
func embeddedIntermediates() ([]*x509.Certificate, error) {
	data, err := embeddedTrust.ReadFile(embeddedIntermediateFile)
	if err != nil {
		return nil, configErrorf("embedded trust store: %v", err)
	}
	certs, err := parseCertificates(data)
	if err != nil {
		return nil, configErrorf("embedded intermediates: %v", err)
	}
	return certs, nil
}

// issuedByAnyOf reports whether c is a CA certificate whose signature verifies
// with the key of one of the anchors (and whose issuer name matches it).
func issuedByAnyOf(c *x509.Certificate, anchors []*x509.Certificate) bool {
	if !c.IsCA || !c.BasicConstraintsValid {
		return false
	}
	for _, a := range anchors {
		if bytes.Equal(c.RawIssuer, a.RawSubject) && c.CheckSignatureFrom(a) == nil {
			return true
		}
	}
	return false
}

func containsCert(list []*x509.Certificate, c *x509.Certificate) bool {
	for _, x := range list {
		if x.Equal(c) {
			return true
		}
	}
	return false
}

// parseCertificates accepts a PEM bundle of CERTIFICATE blocks or a single DER certificate.
func parseCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("unexpected PEM block %q", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid certificate: %v", err)
		}
		certs = append(certs, c)
	}
	if !sawPEM && len(data) > 0 {
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, fmt.Errorf("data is neither PEM nor a DER certificate")
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	return certs, nil
}

func downloadCACertificate(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCADownloadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxCADownloadBytes {
		return nil, fmt.Errorf("certificate larger than %d bytes", maxCADownloadBytes)
	}
	return data, nil
}

// Fingerprint returns the hex SHA-256 fingerprint of DER data.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
