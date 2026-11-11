package tsaservice

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

// The fixture testdata/digitelts-2026-10-08.tsr is a real TimeStampResp issued
// by the DigitelTS TSA (TSU "DIGITEL TS QUALIFIED TSU 01 G3 EDCSA") for a test
// registration of a development environment. Only its SHA-512 imprint is
// known (testdata/*.imprint.hex); the timestamped data is not in the repository.
//
// It proves that the verifier accepts genuine provider tokens with the embedded
// trust store, which the previous implementation could not do (the token does
// not carry the intermediate CA, see trust/README.md).

func loadRealToken(t *testing.T) ([]byte, []byte) {
	t.Helper()
	tsr, err := os.ReadFile("testdata/digitelts-2026-10-08.tsr")
	if err != nil {
		t.Fatal(err)
	}
	h, err := os.ReadFile("testdata/digitelts-2026-10-08.imprint.hex")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(strings.TrimSpace(string(h)))
	if err != nil {
		t.Fatal(err)
	}
	return tsr, digest
}

func embeddedVerifier(t *testing.T, cfg TSAConfig) *Verifier {
	t.Helper()
	v, err := NewVerifier(context.Background(), &cfg, WithLogger(discardLogger()))
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestRealDigitelTSTokenVerifies(t *testing.T) {
	tsr, digest := loadRealToken(t)
	v := embeddedVerifier(t, TSAConfig{})

	vt, err := v.VerifyDigest(tsr, "sha512", digest)
	if err != nil {
		t.Fatalf("real DigitelTS token rejected: %v", err)
	}
	if vt.Policy != "0.4.0.2023.1.1" {
		t.Errorf("policy = %s", vt.Policy)
	}
	if got := vt.Signer.Subject.CommonName; got != "DIGITEL TS QUALIFIED TSU 01 G3 EDCSA" {
		t.Errorf("signer = %q", got)
	}
	if len(vt.Chain) != 3 {
		t.Errorf("chain length = %d, want 3 (TSU, CA TSA G1, root)", len(vt.Chain))
	}
	if vt.GenTime.Format("2006-01-02") != "2026-10-08" {
		t.Errorf("genTime = %s", vt.GenTime)
	}
}

func TestRealDigitelTSTokenPolicyPin(t *testing.T) {
	tsr, digest := loadRealToken(t)

	if _, err := embeddedVerifier(t, TSAConfig{PolicyOID: "0.4.0.2023.1.1"}).VerifyDigest(tsr, "sha512", digest); err != nil {
		t.Fatalf("expected policy to match: %v", err)
	}
	_, err := embeddedVerifier(t, TSAConfig{PolicyOID: "1.2.3.4"}).VerifyDigest(tsr, "sha512", digest)
	if reasonOf(err) != ReasonPolicy {
		t.Fatalf("expected policy failure, got %v", err)
	}
}

func TestRealDigitelTSTokenRejections(t *testing.T) {
	tsr, digest := loadRealToken(t)
	v := embeddedVerifier(t, TSAConfig{})

	t.Run("other data", func(t *testing.T) {
		bad := bytes.Clone(digest)
		bad[0] ^= 0xff
		if _, err := v.VerifyDigest(tsr, "sha512", bad); reasonOf(err) != ReasonImprint {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("flipped signature byte, imprint intact", func(t *testing.T) {
		// The ECDSA signature is the last OCTET STRING of the SignerInfo, close to the end.
		mutated := bytes.Clone(tsr)
		mutated[len(mutated)-10] ^= 0x01
		_, err := v.VerifyDigest(mutated, "sha512", digest)
		if err == nil {
			t.Fatal("token with a modified signature was accepted")
		}
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("unexpected error type: %v", err)
		}
	})

	t.Run("unrelated trust anchor", func(t *testing.T) {
		inter, err := os.ReadFile("trust/digitelts/qualified-ca-tsa-g1.pem")
		if err != nil {
			t.Fatal(err)
		}
		// The intermediate alone as a root does validate (it is a CA). Pinning a
		// different fingerprint must make loading fail.
		_, err = NewVerifier(context.Background(), &TSAConfig{TrustAnchorsPEM: string(inter), TrustAnchorSHA256: []string{EmbeddedRootSHA256}}, WithLogger(discardLogger()))
		if !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("expected pin mismatch, got %v", err)
		}
	})
}

func TestEmbeddedTrustStoreFingerprint(t *testing.T) {
	data, err := embeddedTrust.ReadFile(embeddedRootFile)
	if err != nil {
		t.Fatal(err)
	}
	certs, err := parseCertificates(data)
	if err != nil || len(certs) != 1 {
		t.Fatalf("embedded root: %v", err)
	}
	if got := certFingerprint(certs[0]); got != EmbeddedRootSHA256 {
		t.Fatalf("embedded root fingerprint changed: %s", got)
	}
}

// FuzzVerifyRealToken mutates the genuine DigitelTS token and verifies it with
// an external (root-only) trust store. Besides never panicking, any input that
// verifies must carry exactly the signed content of the original token: a
// mutation may only touch unsigned parts of the CMS structure.
func FuzzVerifyRealToken(f *testing.F) {
	tsr, err := os.ReadFile("testdata/digitelts-2026-10-08.tsr")
	if err != nil {
		f.Fatal(err)
	}
	h, _ := os.ReadFile("testdata/digitelts-2026-10-08.imprint.hex")
	digest, _ := hex.DecodeString(strings.TrimSpace(string(h)))
	root, _ := embeddedTrust.ReadFile(embeddedRootFile)
	v, err := NewVerifier(context.Background(), &TSAConfig{TrustAnchorsPEM: string(root)}, WithLogger(discardLogger()))
	if err != nil {
		f.Fatal(err)
	}
	want, err := v.VerifyDigest(tsr, "sha512", digest)
	if err != nil {
		f.Fatalf("seed rejected: %v", err)
	}
	f.Add(tsr)
	f.Add(tsr[:len(tsr)/2])
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := v.VerifyDigest(in, "sha512", digest)
		if err != nil {
			return
		}
		if !got.GenTime.Equal(want.GenTime) || got.SerialNumber.Cmp(want.SerialNumber) != 0 ||
			got.Policy != want.Policy || !got.Signer.Equal(want.Signer) || len(got.Chain) != 3 {
			t.Fatalf("mutated token accepted with different signed content")
		}
	})
}
