package tsaservice

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/tsaservice/tsatest"
)

// timestampWith issues one request against a fake TSA configured with o.
func timestampWith(t *testing.T, a *tsatest.Authority, o tsatest.TokenOptions, mutate func(*TSAConfig)) (*Token, error) {
	t.Helper()
	srv := a.NewServer(t)
	srv.SetOptions(o)
	return newTestService(t, srv, mutate).Timestamp(context.Background(), []byte("evidence"))
}

func expectReason(t *testing.T, err error, reasons ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("token accepted, want rejection")
	}
	if !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("error is not a verification failure: %v", err)
	}
	got := reasonOf(err)
	for _, r := range reasons {
		if got == r {
			return
		}
	}
	t.Fatalf("reason = %q (%v), want one of %v", got, err, reasons)
}

// TestTamperedSignatureIsRejected is the regression test for the removed
// "if true { return }" bypass: a token whose MessageImprint is intact but whose
// CMS signature is wrong must never be accepted.
func TestTamperedSignatureIsRejected(t *testing.T) {
	_, err := timestampWith(t, tsatest.New(t), tsatest.TokenOptions{TamperSignature: true}, nil)
	expectReason(t, err, ReasonSignature)
}

func TestCoherentForgeryIsRejected(t *testing.T) {
	// TSTInfo modified and message-digest attribute updated to match: only the
	// signature over the signed attributes can catch this.
	_, err := timestampWith(t, tsatest.New(t), tsatest.TokenOptions{TamperTSTInfo: true}, nil)
	expectReason(t, err, ReasonSignature)
}

func TestTamperedSignedAttributesAreRejected(t *testing.T) {
	_, err := timestampWith(t, tsatest.New(t), tsatest.TokenOptions{TamperSignedAttrs: true}, nil)
	expectReason(t, err, ReasonSignedAttributes)
}

func TestAlteredDocumentHashIsRejected(t *testing.T) {
	_, err := timestampWith(t, tsatest.New(t), tsatest.TokenOptions{Imprint: make([]byte, 64)}, nil)
	expectReason(t, err, ReasonImprint)

	// Historical verification with different data.
	a := tsatest.New(t)
	srv := a.NewServer(t)
	s := newTestService(t, srv, nil)
	tok, err := s.Timestamp(context.Background(), []byte("original"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Verify(tok.Response, []byte("modified"))
	expectReason(t, err, ReasonImprint)
}

func TestWrongSignerCertificate(t *testing.T) {
	a := tsatest.New(t)

	t.Run("key does not match embedded certificate", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &tsatest.Identity{Cert: a.TSU.Cert, Key: otherKey}}, nil)
		expectReason(t, err, ReasonSignature)
	})

	t.Run("signer certificate not in token", func(t *testing.T) {
		other := tsatest.New(t)
		_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &other.TSU, EmbeddedCert: a.TSU.Cert}, nil)
		expectReason(t, err, ReasonSigner)
	})

	t.Run("no certificates", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{OmitCertificates: true}, nil)
		expectReason(t, err, ReasonSigner)
	})

	t.Run("two signers", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{ExtraSigner: true}, nil)
		expectReason(t, err, ReasonSigner)
	})
}

func TestUntrustedChain(t *testing.T) {
	trusted := tsatest.New(t)
	rogue := tsatest.New(t)

	srv := rogue.NewServer(t)
	s := newTestService(t, srv, func(c *TSAConfig) {
		c.TrustAnchorsPEM = trusted.RootPEM()
		c.IntermediatesFile = ""
	})
	_, err := s.Timestamp(context.Background(), []byte("x"))
	expectReason(t, err, ReasonChain)
}

func TestIntermediateHandling(t *testing.T) {
	a := tsatest.New(t)

	t.Run("missing intermediate", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{}, func(c *TSAConfig) { c.IntermediatesFile = "" })
		expectReason(t, err, ReasonChain)
	})

	t.Run("intermediate carried by the token", func(t *testing.T) {
		tok, err := timestampWith(t, a, tsatest.TokenOptions{IncludeIntermediate: true}, func(c *TSAConfig) { c.IntermediatesFile = "" })
		if err != nil {
			t.Fatal(err)
		}
		if len(tok.Chain) != 3 {
			t.Fatalf("chain length %d", len(tok.Chain))
		}
	})
}

func TestExpiredCertificate(t *testing.T) {
	a := tsatest.New(t)
	// The test PKI CAs are valid from 24h ago, so the expired TSU lives inside that window.
	expired := a.NewTSU(t, tsatest.CertOptions{NotBefore: time.Now().Add(-20 * time.Hour), NotAfter: time.Now().Add(-10 * time.Hour)})

	_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &expired}, nil)
	expectReason(t, err, ReasonChain)

	// A token produced while the certificate was valid still verifies as historical evidence.
	srv := a.NewServer(t)
	srv.SetOptions(tsatest.TokenOptions{Signer: &expired, GenTime: time.Now().Add(-15 * time.Hour)})
	req := mustRequest(t, []byte("old evidence"))
	resp, err := a.Issue(req, tsatest.TokenOptions{Signer: &expired, GenTime: time.Now().Add(-15 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	s := newTestService(t, srv, nil)
	if _, err := s.Verify(resp, []byte("old evidence")); err != nil {
		t.Fatalf("historical token rejected: %v", err)
	}
}

func TestExtendedKeyUsage(t *testing.T) {
	a := tsatest.New(t)

	t.Run("server auth only", func(t *testing.T) {
		id := a.NewTSU(t, tsatest.CertOptions{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &id}, nil)
		expectReason(t, err, ReasonChain, ReasonEKU)
	})

	t.Run("time stamping plus another usage", func(t *testing.T) {
		id := a.NewTSU(t, tsatest.CertOptions{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth}})
		_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &id}, nil)
		expectReason(t, err, ReasonEKU)
	})

	t.Run("non-critical EKU", func(t *testing.T) {
		id := a.NewTSU(t, tsatest.CertOptions{NonCriticalEKU: true})
		_, err := timestampWith(t, a, tsatest.TokenOptions{Signer: &id}, nil)
		expectReason(t, err, ReasonEKU)
	})
}

func TestESSBinding(t *testing.T) {
	a := tsatest.New(t)
	_, err := timestampWith(t, a, tsatest.TokenOptions{OmitESS: true}, nil)
	expectReason(t, err, ReasonESS)

	_, err = timestampWith(t, a, tsatest.TokenOptions{WrongESSHash: true}, nil)
	expectReason(t, err, ReasonESS)
}

func TestPolicy(t *testing.T) {
	a := tsatest.New(t)

	t.Run("requested and returned", func(t *testing.T) {
		srv := a.NewServer(t)
		s := newTestService(t, srv, func(c *TSAConfig) { c.PolicyOID = "1.3.6.1.4.1.99999.7" })
		tok, err := s.Timestamp(context.Background(), []byte("x"))
		if err != nil {
			t.Fatal(err)
		}
		if got := srv.Requests()[0].Policy.String(); got != "1.3.6.1.4.1.99999.7" {
			t.Errorf("reqPolicy = %s", got)
		}
		if tok.Policy != "1.3.6.1.4.1.99999.7" {
			t.Errorf("policy = %s", tok.Policy)
		}
	})

	t.Run("unexpected policy", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{Policy: tsatest.DefaultPolicy}, func(c *TSAConfig) { c.PolicyOID = "1.3.6.1.4.1.99999.7" })
		expectReason(t, err, ReasonPolicy)
	})
}

func TestAlgorithms(t *testing.T) {
	a := tsatest.New(t)
	rsaTSU := a.NewTSU(t, tsatest.CertOptions{RSA: true})

	for _, imprint := range []string{"sha256", "sha384", "sha512"} {
		for _, digest := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			for _, signer := range []*tsatest.Identity{nil, &rsaTSU} {
				name := imprint + "/" + digest.String()
				if signer != nil {
					name += "/rsa"
				}
				t.Run(name, func(t *testing.T) {
					tok, err := timestampWith(t, a, tsatest.TokenOptions{DigestHash: digest, Signer: signer}, func(c *TSAConfig) { c.HashAlgorithm = imprint })
					if err != nil {
						t.Fatal(err)
					}
					if tok.HashAlgorithm != imprint {
						t.Fatalf("hash = %s", tok.HashAlgorithm)
					}
				})
			}
		}
	}

	t.Run("SHA-1 imprint rejected", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{ImprintOID: oidSHA1, Imprint: make([]byte, 20)}, nil)
		expectReason(t, err, ReasonAlgorithm)
	})

	t.Run("SHA-1 CMS digest rejected", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{DigestHash: crypto.SHA1}, nil)
		expectReason(t, err, ReasonAlgorithm)
	})

	t.Run("imprint algorithm differs from the request", func(t *testing.T) {
		_, err := timestampWith(t, a, tsatest.TokenOptions{ImprintOID: oidSHA256, Imprint: make([]byte, 32)}, nil)
		expectReason(t, err, ReasonImprint)
	})
}

func TestCriticalExtensionRejected(t *testing.T) {
	_, err := timestampWith(t, tsatest.New(t), tsatest.TokenOptions{CriticalExtension: true}, nil)
	expectReason(t, err, ReasonExtension)
}

func TestFreshness(t *testing.T) {
	a := tsatest.New(t)
	_, err := timestampWith(t, a, tsatest.TokenOptions{GenTime: time.Now().Add(-time.Hour)}, nil)
	expectReason(t, err, ReasonTime)

	_, err = timestampWith(t, a, tsatest.TokenOptions{GenTime: time.Now().Add(time.Hour)}, nil)
	expectReason(t, err, ReasonTime)
}

func TestRevocationCRL(t *testing.T) {
	var mu sync.Mutex
	crls := map[string][]byte{}
	crlSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if b, ok := crls[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(crlSrv.Close)
	setCRLs := func(root, inter []byte) {
		mu.Lock()
		defer mu.Unlock()
		crls["/root.crl"], crls["/intermediate.crl"] = root, inter
	}

	a := tsatest.NewWithOptions(t, tsatest.Options{CRLBaseURL: crlSrv.URL})
	now := time.Now()
	crlMode := func(c *TSAConfig) { c.RevocationCheck = RevocationCRL }

	t.Run("not revoked", func(t *testing.T) {
		setCRLs(a.RootCRL(t, now), a.CRL(t, now))
		tok, err := timestampWith(t, a, tsatest.TokenOptions{}, crlMode)
		if err != nil {
			t.Fatal(err)
		}
		if !tok.RevocationChecked {
			t.Fatal("revocation not reported as checked")
		}
	})

	t.Run("TSU revoked", func(t *testing.T) {
		setCRLs(a.RootCRL(t, now), a.CRL(t, now, a.TSU.Cert))
		_, err := timestampWith(t, a, tsatest.TokenOptions{}, crlMode)
		expectReason(t, err, ReasonRevocation)
	})

	t.Run("intermediate revoked", func(t *testing.T) {
		setCRLs(a.RootCRL(t, now, a.Intermediate.Cert), a.CRL(t, now))
		_, err := timestampWith(t, a, tsatest.TokenOptions{}, crlMode)
		expectReason(t, err, ReasonRevocation)
	})

	t.Run("CRL signed by the wrong issuer", func(t *testing.T) {
		other := tsatest.New(t)
		setCRLs(a.RootCRL(t, now), other.CRL(t, now))
		_, err := timestampWith(t, a, tsatest.TokenOptions{}, crlMode)
		expectReason(t, err, ReasonRevocation)
	})

	t.Run("CRL unavailable fails closed", func(t *testing.T) {
		setCRLs(nil, nil)
		mu.Lock()
		crls = map[string][]byte{}
		mu.Unlock()
		_, err := timestampWith(t, a, tsatest.TokenOptions{}, crlMode)
		expectReason(t, err, ReasonRevocation)
	})

	t.Run("disabled by default", func(t *testing.T) {
		tok, err := timestampWith(t, a, tsatest.TokenOptions{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if tok.RevocationChecked {
			t.Fatal("revocation reported as checked although disabled")
		}
	})
}

// TestTruncatedResponsesNeverVerify feeds every prefix of a valid response to
// the verifier: none may be accepted and none may panic.
func TestTruncatedResponsesNeverVerify(t *testing.T) {
	a := tsatest.New(t)
	srv := a.NewServer(t)
	s := newTestService(t, srv, nil)
	data := []byte("evidence")
	tok, err := s.Timestamp(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(tok.Response); i++ {
		if _, err := s.Verify(tok.Response[:i], data); err == nil {
			t.Fatalf("prefix of length %d verified", i)
		}
	}
	// Single-bit flips anywhere must never produce an accepted token with
	// different content; most are rejected outright.
	for i := 0; i < len(tok.Response); i++ {
		mutated := append([]byte(nil), tok.Response...)
		mutated[i] ^= 0x80
		if vt, err := s.Verify(mutated, data); err == nil && vt.SerialNumber.Cmp(tok.SerialNumber) != 0 {
			t.Fatalf("bit flip at %d produced a different accepted token", i)
		}
	}
}

func FuzzVerify(f *testing.F) {
	a := tsatest.New(f)
	req := mustRequest(f, []byte("seed"))
	seed, err := a.Issue(req, tsatest.TokenOptions{IncludeIntermediate: true})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0x30, 0x00})
	v, err := NewVerifier(context.Background(), &TSAConfig{TrustAnchorsPEM: a.RootPEM()}, WithLogger(discardLogger()))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, tsr []byte) {
		_, _ = v.Verify(tsr, []byte("seed"))
	})
}
