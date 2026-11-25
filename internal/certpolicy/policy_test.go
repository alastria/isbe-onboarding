package certpolicy_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/internal/certpolicy"
	"github.com/alastria/isbe-onboarding/internal/certpolicy/certpolicytest"
)

func orgSubject(cn string) certpolicytest.LeafOptions {
	// Same Subject structure as the target certificate: CN, O, C, L; no
	// organizationIdentifier and no Subject serialNumber.
	return certpolicytest.LeafOptions{Subject: certpolicytest.Name(cn, cn, "GB", "London")}
}

func newValidator(t *testing.T, p *certpolicytest.PKI, opts ...certpolicy.Option) *certpolicy.Validator {
	t.Helper()
	opts = append([]certpolicy.Option{certpolicy.WithClock(func() time.Time { return p.Now })}, opts...)
	v, err := certpolicy.NewValidator([]*x509.Certificate{p.Root.Cert, p.Intermediate.Cert}, opts...)
	if err != nil {
		t.Fatalf("NewValidator: %v", err)
	}
	return v
}

func TestVerify(t *testing.T) {
	p := certpolicytest.New(t, "policy")
	other := certpolicytest.New(t, "other")

	revoked := p.Intermediate.Issue(orgSubject("REVOKED"))
	p.Intermediate.Revoke(revoked.Cert)

	tests := []struct {
		name string
		cert *x509.Certificate
		want error // nil = accepted
	}{
		{"valid organizational certificate without identifiers", p.Intermediate.Issue(orgSubject("APPROVED")).Cert, nil},
		{"valid certificate with Subject serialNumber", p.Intermediate.Issue(certpolicytest.LeafOptions{
			Subject: certpolicytest.Name("PERSON", "ORG", "ES", "Madrid", certpolicytest.SubjectSerialNumber("IDCES-00000000T"))}).Cert, nil},
		{"ECDSA P-256 key", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("EC").Subject, ECDSA: true}).Cert, nil},
		{"expired", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("EXPIRED").Subject,
			NotBefore: p.Now.Add(-48 * time.Hour), NotAfter: p.Now.Add(-time.Hour)}).Cert, certpolicy.ErrInvalidCertificate},
		{"not yet valid", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("FUTURE").Subject,
			NotBefore: p.Now.Add(time.Hour), NotAfter: p.Now.Add(48 * time.Hour)}).Cert, certpolicy.ErrInvalidCertificate},
		{"revoked", revoked.Cert, certpolicy.ErrRevoked},
		{"issued by an untrusted CA", other.Intermediate.Issue(orgSubject("UNTRUSTED")).Cert, certpolicy.ErrUntrusted},
		{"self-signed", selfSigned(t, p), certpolicy.ErrUntrusted},
		{"EKU serverAuth only", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("SERVER").Subject,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}).Cert, certpolicy.ErrUnsuitable},
		{"EKU missing", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("NOEKU").Subject, NoExtKeyUsage: true}).Cert, certpolicy.ErrUnsuitable},
		{"Key Usage without digitalSignature", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("KU").Subject,
			KeyUsage: x509.KeyUsageKeyEncipherment}).Cert, certpolicy.ErrUnsuitable},
		{"Key Usage missing", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("NOKU").Subject, NoKeyUsage: true}).Cert, certpolicy.ErrUnsuitable},
		{"CA certificate", p.Intermediate.Cert, certpolicy.ErrUnsuitable},
		{"weak RSA key", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("WEAK").Subject, RSABits: 1024}).Cert, certpolicy.ErrUnsuitable},
		{"no CRL distribution point", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("NOCDP").Subject, NoCRLDP: true}).Cert, certpolicy.ErrRevocationUnavailable},
		{"only an LDAP CRL distribution point", p.Intermediate.Issue(certpolicytest.LeafOptions{Subject: orgSubject("LDAP").Subject,
			CRLDistributionPt: []string{"ldap://example.invalid/cn=crl"}}).Cert, certpolicy.ErrRevocationUnavailable},
		{"nil certificate", nil, certpolicy.ErrInvalidCertificate},
	}

	v := newValidator(t, p)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			chain, err := v.Verify(context.Background(), tc.cert)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("expected acceptance, got %v", err)
				}
				if len(chain) != 3 || !chain[2].Equal(p.Root.Cert) {
					t.Fatalf("unexpected chain of length %d", len(chain))
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			t.Logf("rejected as expected: %v", err)
		})
	}
}

func selfSigned(t *testing.T, p *certpolicytest.PKI) *x509.Certificate {
	t.Helper()
	// A self-made CA with the same name as the trusted intermediate: chain building
	// must fail on the signature, not match on the name.
	fake := certpolicytest.New(t, "policy")
	return fake.Intermediate.Issue(orgSubject("SAME NAME")).Cert
}

func TestVerifyRevocationFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode certpolicytest.CRLMode
	}{
		{"CRL endpoint unavailable", certpolicytest.CRLUnavailable},
		{"stale CRL", certpolicytest.CRLStale},
		{"CRL signed by another key", certpolicytest.CRLBadSig},
		{"CRL endpoint returns garbage", certpolicytest.CRLGarbage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := certpolicytest.New(t, "failclosed")
			leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
			p.Intermediate.CRLMode = tc.mode
			_, err := newValidator(t, p).Verify(context.Background(), leaf.Cert)
			if !errors.Is(err, certpolicy.ErrRevocationUnavailable) {
				t.Fatalf("expected ErrRevocationUnavailable, got %v", err)
			}
		})
	}

	t.Run("CRL endpoint times out", func(t *testing.T) {
		p := certpolicytest.New(t, "timeout")
		leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
		block := make(chan struct{})
		defer close(block)
		slow := &http.Client{Timeout: 200 * time.Millisecond, Transport: blockingTransport{block}}
		_, err := newValidator(t, p, certpolicy.WithHTTPClient(slow)).Verify(context.Background(), leaf.Cert)
		if !errors.Is(err, certpolicy.ErrRevocationUnavailable) {
			t.Fatalf("expected ErrRevocationUnavailable, got %v", err)
		}
	})

	t.Run("revoked intermediate CA", func(t *testing.T) {
		p := certpolicytest.New(t, "revokedca")
		leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
		p.Root.Revoke(p.Intermediate.Cert)
		_, err := newValidator(t, p).Verify(context.Background(), leaf.Cert)
		if !errors.Is(err, certpolicy.ErrRevoked) {
			t.Fatalf("expected ErrRevoked, got %v", err)
		}
	})

	t.Run("intermediate CRL unavailable", func(t *testing.T) {
		p := certpolicytest.New(t, "rootcrl")
		leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
		p.Root.CRLMode = certpolicytest.CRLUnavailable
		_, err := newValidator(t, p).Verify(context.Background(), leaf.Cert)
		if !errors.Is(err, certpolicy.ErrRevocationUnavailable) {
			t.Fatalf("expected ErrRevocationUnavailable, got %v", err)
		}
	})
}

type blockingTransport struct{ block chan struct{} }

func (b blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	select {
	case <-b.block:
	case <-r.Context().Done():
	}
	return nil, r.Context().Err()
}

func TestVerifyCRLCache(t *testing.T) {
	p := certpolicytest.New(t, "cache")
	leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
	now := p.Now
	v := newValidator(t, p, certpolicy.WithClock(func() time.Time { return now }))

	if _, err := v.Verify(context.Background(), leaf.Cert); err != nil {
		t.Fatalf("first verification: %v", err)
	}
	// Within the cache window the CRL is not downloaded again.
	p.Intermediate.CRLMode = certpolicytest.CRLUnavailable
	if _, err := v.Verify(context.Background(), leaf.Cert); err != nil {
		t.Fatalf("cached verification: %v", err)
	}
	// After the cache window the CRL is downloaded again, and a revocation is seen.
	p.Intermediate.CRLMode = certpolicytest.CRLValid
	p.Intermediate.Revoke(leaf.Cert)
	now = now.Add(16 * time.Minute)
	if _, err := v.Verify(context.Background(), leaf.Cert); !errors.Is(err, certpolicy.ErrRevoked) {
		t.Fatalf("expected ErrRevoked after the cache window, got %v", err)
	}
}

func TestCABundle(t *testing.T) {
	p := certpolicytest.New(t, "bundle")
	leaf := p.Intermediate.Issue(orgSubject("APPROVED"))
	clock := certpolicy.WithClock(func() time.Time { return p.Now })

	t.Run("the chain reaches the root and includes the intermediate", func(t *testing.T) {
		chain, err := newValidator(t, p).Verify(context.Background(), leaf.Cert)
		if err != nil || len(chain) != 3 {
			t.Fatalf("expected a chain of 3, got %d, %v", len(chain), err)
		}
	})

	t.Run("only the intermediates of the bundle can issue", func(t *testing.T) {
		other := p.NewIntermediate("bundle-other")
		cert := other.Issue(orgSubject("OTHER ISSUER")).Cert
		if _, err := newValidator(t, p).Verify(context.Background(), cert); !errors.Is(err, certpolicy.ErrUntrusted) {
			t.Fatalf("certificate from an intermediate outside the bundle: expected ErrUntrusted, got %v", err)
		}
	})

	t.Run("bundle order does not matter", func(t *testing.T) {
		v, err := certpolicy.NewValidator([]*x509.Certificate{p.Intermediate.Cert, p.Root.Cert}, clock)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), leaf.Cert); err != nil {
			t.Fatal(err)
		}
		roles := map[string]string{}
		for _, ca := range v.CAs() {
			roles[ca.Role] = ca.Subject
		}
		if roles["root"] != p.Root.Cert.Subject.String() || roles["intermediate"] != p.Intermediate.Cert.Subject.String() {
			t.Errorf("roles %v", roles)
		}
	})
}

func TestNewValidatorRejectsBadConfiguration(t *testing.T) {
	p := certpolicytest.New(t, "cfg")
	leaf := p.Intermediate.Issue(orgSubject("LEAF"))
	if _, err := certpolicy.NewValidator(nil); err == nil {
		t.Error("expected an error with an empty bundle")
	}
	if _, err := certpolicy.NewValidator([]*x509.Certificate{p.Intermediate.Cert}); err == nil {
		t.Error("expected an error without a root: the revocation of the intermediate could not be checked")
	}
	if _, err := certpolicy.NewValidator([]*x509.Certificate{p.Root.Cert, leaf.Cert}); err == nil {
		t.Error("expected an error with a non-CA certificate in the bundle")
	}
	if _, err := certpolicy.NewValidatorFromFile("/nonexistent/ca.pem"); err == nil {
		t.Error("expected an error with a missing bundle file")
	}
}

func TestVerifyCRLRedirectNotFollowed(t *testing.T) {
	p := certpolicytest.New(t, "redirect")
	p.Intermediate.CRLMode = certpolicytest.CRLRedirect
	leaf := p.Intermediate.Issue(orgSubject("REDIRECT"))
	if _, err := newValidator(t, p).Verify(context.Background(), leaf.Cert); !errors.Is(err, certpolicy.ErrRevocationUnavailable) {
		t.Fatalf("expected ErrRevocationUnavailable, got %v", err)
	}
}
