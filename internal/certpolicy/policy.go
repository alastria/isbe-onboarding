// Package certpolicy implements the trust policy for manually approved client certificates
// that are not qualified eIDAS certificates.
//
// A certificate accepted through the EU DSS validation is trusted because it chains to the
// EU Trusted Lists. A manually approved certificate does not, so it must satisfy this policy,
// configured per environment with a single PEM bundle (MANUAL_APPROVAL_CA_FILE):
//
//   - its chain is built up to a self-signed root of the bundle, using only the
//     intermediates of the bundle (never those sent by the client), so only the CAs listed
//     in the bundle can issue an accepted certificate;
//   - every certificate in the chain is within its validity period;
//   - the end-entity certificate is not a CA, has Key Usage digitalSignature and Extended
//     Key Usage clientAuth (both extensions must be present), and a key of acceptable strength;
//   - no certificate in the chain except the root (so including the intermediates) is
//     revoked, according to a current CRL signed by its issuer (internal/crlcheck).
//
// Revocation is fail-closed: if the status cannot be determined, the certificate is rejected
// with ErrRevocationUnavailable. Proof of possession of the private key is the TLS handshake
// terminated by the reverse proxy, and the whitelist match (exact SHA-256 fingerprint) is
// done by the caller. See docs/manual-approval-policy.md.
package certpolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/alastria/isbe-onboarding/internal/crlcheck"
)

// Errors returned by Verify. They are wrapped with details, use errors.Is.
var (
	// ErrInvalidCertificate: the certificate (or its chain) is expired, not yet valid,
	// malformed or otherwise invalid.
	ErrInvalidCertificate = errors.New("certificate is not valid")
	// ErrUntrusted: no chain can be built to a configured root through configured intermediates.
	ErrUntrusted = errors.New("certificate does not chain to a configured CA")
	// ErrUnsuitable: the certificate is not a client authentication end-entity certificate
	// (wrong key usage, extended key usage, CA flag or key strength).
	ErrUnsuitable = errors.New("certificate is not suitable for client authentication")
	// ErrRevoked: a certificate in the chain is listed in a valid CRL of its issuer.
	ErrRevoked = errors.New("certificate is revoked")
	// ErrRevocationUnavailable: the revocation status could not be determined.
	ErrRevocationUnavailable = errors.New("certificate revocation status could not be determined")
)

const (
	crlTimeout = 10 * time.Second
	// A downloaded CRL is reused for at most this long (and never after its nextUpdate),
	// so that a new revocation is picked up soon after the CA publishes it.
	maxCRLCacheAge = 15 * time.Minute
)

// Validator verifies certificates against the policy. It is safe for concurrent use.
type Validator struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
	cas           []CA

	httpClient *http.Client
	now        func() time.Time
	crl        *crlcheck.Checker
}

// Option customises a Validator (mainly for tests).
type Option func(*Validator)

// WithHTTPClient sets the client used to download CRLs.
func WithHTTPClient(c *http.Client) Option { return func(v *Validator) { v.httpClient = c } }

// WithClock sets the clock used for validity and CRL freshness checks.
func WithClock(now func() time.Time) Option { return func(v *Validator) { v.now = now } }

// NewValidatorFromFile loads the CA bundle from a PEM file.
func NewValidatorFromFile(path string, opts ...Option) (*Validator, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("manual approval CA bundle: %w", err)
	}
	certs, err := ParsePEMCertificates(data)
	if err != nil {
		return nil, fmt.Errorf("manual approval CA bundle %s: %w", path, err)
	}
	return NewValidator(certs, opts...)
}

// NewValidator creates a Validator from a CA bundle: its self-signed certificates are the
// roots and the others the intermediates. Every certificate must be a CA and at least one
// root is required, so that the revocation of the intermediates is checked against the CRL
// of their parent.
func NewValidator(bundle []*x509.Certificate, opts ...Option) (*Validator, error) {
	v := &Validator{roots: x509.NewCertPool(), intermediates: x509.NewCertPool(), now: time.Now}
	roots := 0
	for _, c := range bundle {
		if !c.IsCA {
			return nil, fmt.Errorf("manual approval CA bundle: %q is not a CA certificate", c.Subject.String())
		}
		role := "intermediate"
		if bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil {
			role = "root"
			roots++
			v.roots.AddCert(c)
		} else {
			v.intermediates.AddCert(c)
		}
		v.cas = append(v.cas, CA{Role: role, Subject: c.Subject.String(),
			SHA256: fmt.Sprintf("%x", sha256.Sum256(c.Raw)), NotAfter: c.NotAfter.UTC().Format(time.RFC3339)})
	}
	if roots == 0 {
		return nil, errors.New("manual approval CA bundle: no self-signed root certificate; add the root of the issuing CA")
	}
	for _, o := range opts {
		o(v)
	}
	if v.httpClient == nil {
		v.httpClient = &http.Client{Timeout: crlTimeout}
	}
	v.crl = crlcheck.New(v.httpClient, func() time.Time { return v.now() }, crlcheck.WithMaxCacheAge(maxCRLCacheAge))
	return v, nil
}

// CA describes a certificate of the configured bundle, for logging at startup.
type CA struct {
	Role     string `json:"role"`
	Subject  string `json:"subject"`
	SHA256   string `json:"sha256"`
	NotAfter string `json:"not_after"`
}

// CAs returns a description of the configured CA bundle.
func (v *Validator) CAs() []CA { return v.cas }

// Verify checks the client certificate against the policy. It returns the verified
// chain (end-entity first, trust anchor last) or an error wrapping one of the Err* values.
func (v *Validator) Verify(ctx context.Context, cert *x509.Certificate) ([]*x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("%w: no certificate", ErrInvalidCertificate)
	}

	if err := checkEndEntityProfile(cert); err != nil {
		return nil, err
	}

	now := v.now()
	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		return nil, classifyVerifyError(err)
	}

	// Check revocation along every chain until one passes completely. Normally there is
	// a single chain. A revoked certificate is final: it is revoked on any chain.
	var lastErr error
	for _, chain := range chains {
		lastErr = v.crl.Check(ctx, chain)
		switch {
		case lastErr == nil:
			return chain, nil
		case errors.Is(lastErr, crlcheck.ErrRevoked):
			return nil, fmt.Errorf("%w: %v", ErrRevoked, lastErr)
		}
	}
	return nil, fmt.Errorf("%w: %v", ErrRevocationUnavailable, lastErr)
}

// checkEndEntityProfile checks the properties that the chain validation does not enforce
// on its own: Go accepts a certificate without EKU or without Key Usage.
func checkEndEntityProfile(cert *x509.Certificate) error {
	if cert.IsCA {
		return fmt.Errorf("%w: it is a CA certificate", ErrUnsuitable)
	}
	if cert.KeyUsage == 0 {
		return fmt.Errorf("%w: Key Usage extension is missing", ErrUnsuitable)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: Key Usage does not include digitalSignature", ErrUnsuitable)
	}
	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		return fmt.Errorf("%w: Extended Key Usage does not include clientAuth", ErrUnsuitable)
	}
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA key of %d bits, at least 2048 required", ErrUnsuitable, k.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521() {
			return fmt.Errorf("%w: unsupported elliptic curve", ErrUnsuitable)
		}
	case ed25519.PublicKey:
	default:
		return fmt.Errorf("%w: unsupported public key type %T", ErrUnsuitable, cert.PublicKey)
	}
	return nil
}

func classifyVerifyError(err error) error {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) {
		if invalid.Reason == x509.IncompatibleUsage {
			return fmt.Errorf("%w: %v", ErrUnsuitable, err)
		}
		// Expired (also covers "not yet valid"), CA not authorised to sign, constraints, ...
		return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
	}
	// x509.UnknownAuthorityError, x509.SystemRootsError, bad signatures, ...
	return fmt.Errorf("%w: %v", ErrUntrusted, err)
}

// ParsePEMCertificates parses every CERTIFICATE block of PEM data.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	return out, nil
}
