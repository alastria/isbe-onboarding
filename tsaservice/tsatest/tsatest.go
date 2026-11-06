// Package tsatest provides an in-process RFC 3161 Time Stamping Authority for
// tests. It issues tokens signed by a throw-away PKI (root -> intermediate ->
// TSU) and can produce deliberately broken tokens to exercise the verifier.
//
// It must only be imported from tests.
package tsatest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrAlgProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1              = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidECDSAWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSHA256WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}

	// DefaultPolicy is the ETSI EN 319 421 best-practices policy, the one DigitelTS uses.
	DefaultPolicy = asn1.ObjectIdentifier{0, 4, 0, 2023, 1, 1}
)

// Credentials accepted by the test server.
const (
	User     = "test-user"
	Password = "test-password-not-a-secret"
)

// Identity is a certificate with its private key.
type Identity struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Authority is a test PKI plus a TSA.
type Authority struct {
	Root         Identity
	Intermediate Identity
	TSU          Identity

	serial int64
	mu     sync.Mutex
}

// CertOptions customise the TSU certificate.
type CertOptions struct {
	// ExtKeyUsage defaults to {TimeStamping}.
	ExtKeyUsage []x509.ExtKeyUsage
	// NonCriticalEKU makes the EKU extension non-critical.
	NonCriticalEKU bool
	NotBefore      time.Time
	NotAfter       time.Time
	// RSA uses an RSA-2048 key instead of ECDSA P-256.
	RSA bool
	// CRLURL is written in the CRL distribution points.
	CRLURL string
}

// Options customise the PKI created by NewWithOptions.
type Options struct {
	// CRLBaseURL, when set, adds CRL distribution points to the intermediate
	// (CRLBaseURL+"/root.crl") and to the TSU (CRLBaseURL+"/intermediate.crl").
	CRLBaseURL string
}

// New creates a root, an intermediate and a TSU certificate.
func New(t testing.TB) *Authority { return NewWithOptions(t, Options{}) }

// NewWithOptions creates a root, an intermediate and a TSU certificate.
func NewWithOptions(t testing.TB, o Options) *Authority {
	t.Helper()
	a := &Authority{}
	var interCRL []string
	if o.CRLBaseURL != "" {
		interCRL = []string{o.CRLBaseURL + "/root.crl"}
	}
	a.Root = newIdentity(t, nil, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test TSA Root", Organization: []string{"tsatest"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, false)
	a.Intermediate = newIdentity(t, &a.Root, &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Test TSA Intermediate", Organization: []string{"tsatest"}},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		CRLDistributionPoints: interCRL,
	}, false)
	tsuOpts := CertOptions{}
	if o.CRLBaseURL != "" {
		tsuOpts.CRLURL = o.CRLBaseURL + "/intermediate.crl"
	}
	a.TSU = a.NewTSU(t, tsuOpts)
	return a
}

// NewTSU issues a TSA unit certificate from the intermediate.
func (a *Authority) NewTSU(t testing.TB, o CertOptions) Identity {
	t.Helper()
	eku := o.ExtKeyUsage
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	ski := make([]byte, 20)
	_, _ = rand.Read(ski)
	tmpl := &x509.Certificate{
		SubjectKeyId: ski,
		Subject:      pkix.Name{CommonName: "Test TSU", Organization: []string{"tsatest"}},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
		NotBefore:    o.NotBefore,
		NotAfter:     o.NotAfter,
	}
	if o.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{o.CRLURL}
	}
	id := newIdentity(t, &a.Intermediate, tmpl, o.RSA)
	// crypto/x509 always encodes the EKU extension as non-critical; RFC 3161
	// requires it to be critical, so the certificate is re-issued unless the
	// test asks for the non-compliant variant.
	if !o.NonCriticalEKU {
		id = reissueWithCriticalEKU(t, &a.Intermediate, id)
	}
	return id
}

var serialCounter atomic.Int64

func newIdentity(t testing.TB, issuer *Identity, tmpl *x509.Certificate, useRSA bool) Identity {
	t.Helper()
	var key crypto.Signer
	var err error
	if useRSA {
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	tmpl.SerialNumber = big.NewInt(1000 + serialCounter.Add(1))
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-24 * time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	parent, parentKey := tmpl, key
	if issuer != nil {
		parent, parentKey = issuer.Cert, issuer.Key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Cert: cert, Key: key}
}

// reissueWithCriticalEKU re-signs the certificate with its EKU extension marked critical.
func reissueWithCriticalEKU(t testing.TB, issuer *Identity, id Identity) Identity {
	t.Helper()
	tmpl := *id.Cert
	var exts []pkix.Extension
	for _, e := range id.Cert.Extensions {
		if e.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			e.Critical = true
		}
		exts = append(exts, e)
	}
	tmpl.ExtraExtensions = exts
	tmpl.Extensions = nil
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, issuer.Cert, id.Key.Public(), issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return Identity{Cert: cert, Key: id.Key}
}

// RootPEM returns the root certificate in PEM.
func (a *Authority) RootPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Root.Cert.Raw}))
}

// IntermediatePEM returns the intermediate certificate in PEM.
func (a *Authority) IntermediatePEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Intermediate.Cert.Raw}))
}

// RootSHA256 returns the hex SHA-256 fingerprint of the root.
func (a *Authority) RootSHA256() string {
	sum := sha256.Sum256(a.Root.Cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// Request is a parsed TimeStampReq.
type Request struct {
	HashOID asn1.ObjectIdentifier
	Digest  []byte
	Policy  asn1.ObjectIdentifier
	Nonce   *big.Int
	CertReq bool
}

// ParseRequest decodes a DER TimeStampReq.
func ParseRequest(der []byte) (*Request, error) {
	in := cryptobyte.String(der)
	var seq, mi, alg, digest cryptobyte.String
	var version int
	r := &Request{}
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() || !seq.ReadASN1Integer(&version) || version != 1 ||
		!seq.ReadASN1(&mi, cbasn1.SEQUENCE) || !mi.ReadASN1(&alg, cbasn1.SEQUENCE) || !alg.ReadASN1ObjectIdentifier(&r.HashOID) ||
		!mi.ReadASN1(&digest, cbasn1.OCTET_STRING) {
		return nil, fmt.Errorf("malformed TimeStampReq")
	}
	r.Digest = digest
	if seq.PeekASN1Tag(cbasn1.OBJECT_IDENTIFIER) && !seq.ReadASN1ObjectIdentifier(&r.Policy) {
		return nil, fmt.Errorf("malformed reqPolicy")
	}
	if seq.PeekASN1Tag(cbasn1.INTEGER) {
		r.Nonce = new(big.Int)
		if !seq.ReadASN1Integer(r.Nonce) {
			return nil, fmt.Errorf("malformed nonce")
		}
	}
	if seq.PeekASN1Tag(cbasn1.BOOLEAN) && !seq.ReadASN1Boolean(&r.CertReq) {
		return nil, fmt.Errorf("malformed certReq")
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("unexpected fields in TimeStampReq")
	}
	return r, nil
}

// TokenOptions control how a token is built. The zero value produces a valid token.
type TokenOptions struct {
	// Status, when non-zero, produces a response without token and this PKIStatus.
	Status     int
	StatusText string

	GenTime time.Time
	Policy  asn1.ObjectIdentifier

	// Nonce handling: by default the request nonce is echoed.
	OmitNonce bool
	Nonce     *big.Int

	// Imprint overrides the request digest.
	Imprint []byte
	// ImprintOID overrides the request hash algorithm.
	ImprintOID asn1.ObjectIdentifier

	// DigestHash is the CMS digest algorithm (default SHA-256).
	DigestHash crypto.Hash

	// Signer overrides the TSU identity used to sign.
	Signer *Identity
	// EmbeddedCert overrides the certificate placed in the token (default: the signer's).
	EmbeddedCert *x509.Certificate
	// IncludeIntermediate adds the intermediate CA to the token certificates.
	IncludeIntermediate bool
	// OmitCertificates leaves the certificates field out.
	OmitCertificates bool

	// OmitESS leaves out the signing-certificate-v2 attribute.
	OmitESS bool
	// WrongESSHash puts a wrong certificate hash in the ESS attribute.
	WrongESSHash bool
	// TamperSignedAttrs changes a signed attribute after signing.
	TamperSignedAttrs bool
	// TamperSignature flips a bit of the signature.
	TamperSignature bool
	// TamperTSTInfo changes the TSTInfo (serial number) after signing and
	// updates the message-digest attribute accordingly, without re-signing: a
	// coherent forgery that only the signature check can detect.
	TamperTSTInfo bool
	// CriticalExtension adds an unknown critical TSTInfo extension.
	CriticalExtension bool
	// ExtraSigner adds a second SignerInfo.
	ExtraSigner bool

	// GrantedWithMods returns PKIStatus 1 (grantedWithMods) with a valid token.
	GrantedWithMods bool
	// TSAName adds TSTInfo.tsa as a directoryName with this raw DER Name.
	TSAName []byte

	// Signed attribute variants.
	OmitContentType        bool
	WrongContentType       bool
	OmitMessageDigest      bool
	DuplicateMessageDigest bool
	// NoSignedAttrs signs the TSTInfo directly, without signed attributes.
	NoSignedAttrs bool
	// ESSv1 uses signing-certificate (ESSCertID, SHA-1) instead of v2.
	ESSv1 bool
	// WrongESSSerial puts another serial number in the ESS IssuerSerial.
	WrongESSSerial bool
	// AlgProtection adds a CMSAlgorithmProtection attribute; AlgProtectionMismatch makes it wrong.
	AlgProtection         bool
	AlgProtectionMismatch bool

	// UseSKI identifies the signer by subjectKeyIdentifier (SignerInfo v3).
	UseSKI bool
	// SignerInfoVersion overrides the SignerInfo version.
	SignerInfoVersion int
}

// Issue builds a DER TimeStampResp for a request.
func (a *Authority) Issue(req *Request, o TokenOptions) ([]byte, error) {
	if o.Status != 0 {
		var b cryptobyte.Builder
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(int64(o.Status))
				if o.StatusText != "" {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte(o.StatusText)) })
					})
				}
			})
		})
		return b.Bytes()
	}

	signer := a.TSU
	if o.Signer != nil {
		signer = *o.Signer
	}
	embedded := signer.Cert
	if o.EmbeddedCert != nil {
		embedded = o.EmbeddedCert
	}
	genTime := o.GenTime
	if genTime.IsZero() {
		genTime = time.Now().UTC().Truncate(time.Millisecond)
	}
	policy := o.Policy
	if policy == nil {
		policy = DefaultPolicy
	}
	if req.Policy != nil && o.Policy == nil {
		policy = req.Policy
	}
	nonce := req.Nonce
	if o.Nonce != nil {
		nonce = o.Nonce
	}
	if o.OmitNonce {
		nonce = nil
	}
	imprint, imprintOID := req.Digest, req.HashOID
	if o.Imprint != nil {
		imprint = o.Imprint
	}
	if o.ImprintOID != nil {
		imprintOID = o.ImprintOID
	}
	digestHash := o.DigestHash
	if digestHash == 0 {
		digestHash = crypto.SHA256
	}

	a.mu.Lock()
	a.serial++
	serial := a.serial
	a.mu.Unlock()

	tst, err := buildTSTInfo(policy, imprintOID, imprint, serial, genTime, nonce, o.CriticalExtension, o.TSAName)
	if err != nil {
		return nil, err
	}

	encodedTST := tst
	if o.TamperTSTInfo {
		encodedTST, err = buildTSTInfo(policy, imprintOID, imprint, serial+1000, genTime, nonce, o.CriticalExtension, o.TSAName)
		if err != nil {
			return nil, err
		}
	}

	signerInfo, err := buildSignerInfo(signer, tst, encodedTST, digestHash, o)
	if err != nil {
		return nil, err
	}
	tst = encodedTST

	var extra []byte
	if o.ExtraSigner {
		if extra, err = buildSignerInfo(signer, tst, tst, digestHash, TokenOptions{}); err != nil {
			return nil, err
		}
	}

	var certs [][]byte
	if !o.OmitCertificates {
		certs = append(certs, embedded.Raw)
		if o.IncludeIntermediate {
			certs = append(certs, a.Intermediate.Cert.Raw)
		}
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			if o.GrantedWithMods {
				b.AddASN1Int64(1)
			} else {
				b.AddASN1Int64(0)
			}
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.UTF8String, func(b *cryptobyte.Builder) { b.AddBytes([]byte("Operation Okay")) })
			})
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ContentInfo
			b.AddASN1ObjectIdentifier(oidSignedData)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SignedData
					b.AddASN1Int64(3)
					b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { addHashAlg(b, digestHash) })
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1ObjectIdentifier(oidTSTInfo)
						b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddASN1OctetString(tst)
						})
					})
					if len(certs) > 0 {
						b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							for _, c := range certs {
								b.AddBytes(c)
							}
						})
					}
					b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
						b.AddBytes(signerInfo)
						if extra != nil {
							b.AddBytes(extra)
						}
					})
				})
			})
		})
	})
	return b.Bytes()
}

func hashOID(h crypto.Hash) asn1.ObjectIdentifier {
	switch h {
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	case crypto.SHA1:
		return oidSHA1
	default:
		return oidSHA256
	}
}

func addHashAlg(b *cryptobyte.Builder, h crypto.Hash) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(hashOID(h))
		b.AddASN1NULL()
	})
}

func buildTSTInfo(policy, imprintOID asn1.ObjectIdentifier, imprint []byte, serial int64, genTime time.Time, nonce *big.Int, criticalExt bool, tsaName []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(1)
		b.AddASN1ObjectIdentifier(policy)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(imprintOID)
				b.AddASN1NULL()
			})
			b.AddASN1OctetString(imprint)
		})
		b.AddASN1Int64(serial)
		b.AddASN1(cbasn1.GeneralizedTime, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(formatGeneralizedTime(genTime)))
		})
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { b.AddASN1Int64(1) }) // accuracy 1s
		if nonce != nil {
			b.AddASN1BigInt(nonce)
		}
		if tsaName != nil {
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(4).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(tsaName) })
			})
		}
		if criticalExt {
			b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1})
					b.AddASN1Boolean(true)
					b.AddASN1OctetString([]byte{0x05, 0x00})
				})
			})
		}
	})
	return b.Bytes()
}

// formatGeneralizedTime writes YYYYMMDDhhmmss[.fff]Z without trailing zeros.
func formatGeneralizedTime(t time.Time) string {
	s := t.UTC().Format("20060102150405.000")
	s = string(bytes.TrimRight([]byte(s), "0"))
	s = string(bytes.TrimSuffix([]byte(s), []byte(".")))
	return s + "Z"
}

// buildSignerInfo signs attributes computed over signedTST but encodes the
// message-digest of encodedTST (they differ only for TamperTSTInfo).
func buildSignerInfo(signer Identity, signedTST, encodedTST []byte, digestHash crypto.Hash, o TokenOptions) ([]byte, error) {
	digestOf := func(b []byte) []byte {
		h := digestHash.New()
		h.Write(b)
		return h.Sum(nil)
	}
	signedDigest, encodedDigest := digestOf(signedTST), digestOf(encodedTST)

	var sigOID asn1.ObjectIdentifier
	switch signer.Key.(type) {
	case *rsa.PrivateKey:
		sigOID = map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSHA256WithRSA, crypto.SHA384: oidSHA384WithRSA, crypto.SHA512: oidSHA512WithRSA}[digestHash]
	default:
		sigOID = map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidECDSAWithSHA256, crypto.SHA384: oidECDSAWithSHA384, crypto.SHA512: oidECDSAWithSHA512}[digestHash]
	}
	if sigOID == nil {
		sigOID = oidECDSAWithSHA256
	}

	var certHash []byte
	if o.ESSv1 {
		h := sha1.Sum(signer.Cert.Raw)
		certHash = h[:]
	} else {
		h := sha256.Sum256(signer.Cert.Raw)
		certHash = h[:]
	}
	if o.WrongESSHash {
		certHash[0] ^= 0xff
	}
	essSerial := signer.Cert.SerialNumber
	if o.WrongESSSerial {
		essSerial = new(big.Int).Add(essSerial, big.NewInt(1))
	}

	attrs := func(b *cryptobyte.Builder, tstDigest []byte, tampered bool) {
		if !o.OmitContentType {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAttrContentType)
				ct := oidTSTInfo
				if o.WrongContentType {
					ct = oidData
				}
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(ct) })
			})
		}
		mdAttr := func() {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAttrMessageDigest)
				d := tstDigest
				if tampered {
					d = bytes.Clone(tstDigest)
					d[0] ^= 0x01
				}
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddASN1OctetString(d) })
			})
		}
		if !o.OmitMessageDigest {
			mdAttr()
			if o.DuplicateMessageDigest {
				mdAttr()
			}
		}
		if o.AlgProtection {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(oidAttrAlgProtection)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						addHashAlg(b, digestHash)
						b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
							oid := sigOID
							if o.AlgProtectionMismatch {
								oid = oidSHA512WithRSA
								if sigOID.Equal(oidSHA512WithRSA) {
									oid = oidECDSAWithSHA256
								}
							}
							b.AddASN1ObjectIdentifier(oid)
						})
					})
				})
			})
		}
		if !o.OmitESS {
			attrOID := oidAttrSigningCertV2
			if o.ESSv1 {
				attrOID = oidAttrSigningCert
			}
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(attrOID)
				b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificate(V2)
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // certs
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertID(v2), v2 with default sha256
								b.AddASN1OctetString(certHash)
								b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // IssuerSerial
									b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
										b.AddASN1(cbasn1.Tag(4).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
											b.AddBytes(signer.Cert.RawIssuer)
										})
									})
									b.AddASN1BigInt(essSerial)
								})
							})
						})
					})
				})
			})
		}
	}

	// What is signed: the DER SET of signed attributes, or the TSTInfo itself
	// when there are no signed attributes.
	toSign := signedTST
	if !o.NoSignedAttrs {
		var sb cryptobyte.Builder
		sb.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { attrs(b, signedDigest, false) })
		var err error
		if toSign, err = sb.Bytes(); err != nil {
			return nil, err
		}
	}
	sh := digestHash.New()
	sh.Write(toSign)
	signature, err := signer.Key.Sign(rand.Reader, sh.Sum(nil), digestHash)
	if err != nil {
		return nil, err
	}
	if o.TamperSignature {
		signature[len(signature)/2] ^= 0x01
	}

	var signedAttrs []byte
	if !o.NoSignedAttrs {
		var ab cryptobyte.Builder
		ab.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) { attrs(b, encodedDigest, o.TamperSignedAttrs) })
		if signedAttrs, err = ab.Bytes(); err != nil {
			return nil, err
		}
	}

	version := int64(1)
	if o.UseSKI {
		version = 3
	}
	if o.SignerInfoVersion != 0 {
		version = int64(o.SignerInfoVersion)
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(version)
		if o.UseSKI {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(signer.Cert.SubjectKeyId) })
		} else {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddBytes(signer.Cert.RawIssuer)
				b.AddASN1BigInt(signer.Cert.SerialNumber)
			})
		}
		addHashAlg(b, digestHash)
		b.AddBytes(signedAttrs)
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(sigOID)
			if _, ok := signer.Key.(*rsa.PrivateKey); ok {
				b.AddASN1NULL()
			}
		})
		b.AddASN1OctetString(signature)
	})
	return b.Bytes()
}

// Server is an httptest TSA endpoint.
type Server struct {
	*httptest.Server
	Authority *Authority

	mu       sync.Mutex
	options  TokenOptions
	handler  http.HandlerFunc
	requests []*Request
	path     string
	headers  http.Header
}

// NewServer starts a plain-HTTP TSA. Tests must set AllowInsecure on the client config.
func (a *Authority) NewServer(t testing.TB) *Server {
	t.Helper()
	s := &Server{Authority: a}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// SetOptions sets the options for the next tokens.
func (s *Server) SetOptions(o TokenOptions) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.options = o
}

// SetHandler replaces the TSA behaviour entirely (for HTTP-level tests).
func (s *Server) SetHandler(h http.HandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handler = h
}

// Requests returns the parsed requests received so far.
func (s *Server) Requests() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*Request(nil), s.requests...)
}

// LastPath returns the URL path of the last request.
func (s *Server) LastPath() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// LastHeaders returns the headers of the last request.
func (s *Server) LastHeaders() http.Header {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.headers.Clone()
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.headers = r.Header.Clone()
	s.path = r.URL.Path
	handler, opts := s.handler, s.options
	s.mu.Unlock()

	if handler != nil {
		handler(w, r)
		return
	}
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/timestamp-query" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	user, pass, ok := r.BasicAuth()
	if !ok || user != User || pass != Password {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	req, err := ParseRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, req)
	s.mu.Unlock()

	resp, err := s.Authority.Issue(req, opts)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/timestamp-reply")
	_, _ = w.Write(resp)
}

// CRL returns a DER CRL issued by the intermediate that revokes the given certificates.
func (a *Authority) CRL(t testing.TB, now time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	return a.crl(t, a.Intermediate, now, revoked...)
}

// RootCRL returns a DER CRL issued by the root that revokes the given certificates.
func (a *Authority) RootCRL(t testing.TB, now time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	return a.crl(t, a.Root, now, revoked...)
}

func (a *Authority) crl(t testing.TB, issuer Identity, now time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	var entries []x509.RevocationListEntry
	for _, c := range revoked {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: c.SerialNumber, RevocationTime: now.Add(-time.Hour)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now.Add(-time.Minute),
		NextUpdate:                now.Add(24 * time.Hour),
		RevokedCertificateEntries: entries,
	}, issuer.Cert, issuer.Key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
