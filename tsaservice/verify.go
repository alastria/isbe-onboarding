package tsaservice

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// VerifiedToken is the result of a successful verification. Only tokens that
// passed every mandatory check are ever returned.
type VerifiedToken struct {
	// GenTime is the time asserted by the TSA.
	GenTime time.Time
	// Accuracy is the accuracy declared by the TSA (zero when absent).
	Accuracy time.Duration
	// SerialNumber is the TSA-assigned serial number of the token.
	SerialNumber *big.Int
	// Policy is the TSA policy OID under which the token was issued.
	Policy string
	// HashAlgorithm is the MessageImprint algorithm (sha256, sha384 or sha512).
	HashAlgorithm string
	// Nonce is the nonce echoed by the TSA, if any.
	Nonce *big.Int
	// Signer is the TSA (TSU) certificate that signed the token.
	Signer *x509.Certificate
	// Chain is the validated chain, from Signer to the trust anchor.
	Chain []*x509.Certificate
	// RevocationChecked reports whether the revocation status of the chain was checked.
	RevocationChecked bool
}

// imprintMatcher checks a MessageImprint against the data the caller expects to be timestamped.
type imprintMatcher func(alg hashAlgorithm, hashed []byte) error

// matchData accepts any allowed hash algorithm and recomputes the digest of data.
func matchData(data []byte) imprintMatcher {
	return func(alg hashAlgorithm, hashed []byte) error {
		if subtle.ConstantTimeCompare(alg.sum(data), hashed) != 1 {
			return verificationErrorf(ReasonImprint, "message imprint does not match the timestamped data")
		}
		return nil
	}
}

// matchDigest requires a specific algorithm and digest.
func matchDigest(want hashAlgorithm, digest []byte) imprintMatcher {
	return func(alg hashAlgorithm, hashed []byte) error {
		if !alg.oid.Equal(want.oid) {
			return verificationErrorf(ReasonImprint, "message imprint uses %s, requested %s", alg.name, want.name)
		}
		if subtle.ConstantTimeCompare(digest, hashed) != 1 {
			return verificationErrorf(ReasonImprint, "message imprint does not match the timestamped data")
		}
		return nil
	}
}

// verifyParams are the per-call checks that depend on how the token was obtained.
type verifyParams struct {
	imprint imprintMatcher

	// nonce is the nonce sent in the request. When non-nil, the response must echo it.
	nonce *big.Int

	// notBefore/notAfter bound genTime for freshly requested tokens (replay protection).
	// Zero values disable the check, which is what historical verification does.
	notBefore, notAfter time.Time

	// checkRevocation enables the configured revocation checker.
	checkRevocation bool
}

// verifyResponse runs every mandatory check on a DER TimeStampResp. It is the
// only code path that produces a VerifiedToken, and it fails closed: any
// parse error or failed check returns an error and no token.
func (v *Verifier) verifyResponse(ctx context.Context, tsr []byte, p verifyParams) (*VerifiedToken, error) {
	if p.imprint == nil {
		return nil, verificationErrorf(ReasonImprint, "no data to check the message imprint against")
	}

	resp, err := parseTimeStampResp(tsr)
	if err != nil {
		return nil, err
	}
	if s := resp.Status.Status; s != pkiStatusGranted && s != pkiStatusGrantedWithMods {
		return nil, &VerificationError{Reason: ReasonStatus, Err: rejectedError(resp.Status)}
	}
	if len(resp.Token) == 0 {
		return nil, malformedf("granted response without TimeStampToken")
	}
	return v.verifyToken(ctx, resp.Token, p)
}

func (v *Verifier) verifyToken(ctx context.Context, token []byte, p verifyParams) (*VerifiedToken, error) {
	sd, err := parseSignedDataToken(token)
	if err != nil {
		return nil, err
	}
	if sd.Version != 3 {
		return nil, malformedf("SignedData version %d, want 3", sd.Version)
	}
	if !sd.EContentType.Equal(oidContentTypeTST) {
		return nil, malformedf("encapsulated content type %s is not id-ct-TSTInfo", sd.EContentType)
	}
	// RFC 3161 2.4.2: the token MUST NOT contain any signature other than the TSA's.
	if len(sd.SignerInfos) != 1 {
		return nil, verificationErrorf(ReasonSigner, "token has %d signers, want exactly 1", len(sd.SignerInfos))
	}
	si := &sd.SignerInfos[0]

	tst, err := parseTSTInfo(sd.EContent)
	if err != nil {
		return nil, err
	}
	if tst.Version != 1 {
		return nil, malformedf("TSTInfo version %d, want 1", tst.Version)
	}

	// MessageImprint: allowed algorithm and digest of the expected data.
	imprintAlg, ok := hashAlgorithmByOID(tst.HashAlgorithm.OID)
	if !ok || !tst.HashAlgorithm.paramsAbsentOrNull() {
		return nil, verificationErrorf(ReasonAlgorithm, "message imprint algorithm %s is not allowed", tst.HashAlgorithm.OID)
	}
	if err := p.imprint(imprintAlg, tst.HashedMessage); err != nil {
		return nil, err
	}

	// Nonce (RFC 3161 2.4.2: it MUST be present and equal when the request carried one).
	if p.nonce != nil {
		if tst.Nonce == nil {
			return nil, verificationErrorf(ReasonNonce, "response has no nonce but the request carried one")
		}
		if tst.Nonce.Cmp(p.nonce) != 0 {
			return nil, verificationErrorf(ReasonNonce, "response nonce does not match the request nonce")
		}
	}

	if v.policy != nil && !tst.Policy.Equal(v.policy) {
		return nil, verificationErrorf(ReasonPolicy, "token policy %s, want %s", tst.Policy, v.policy)
	}

	for _, ext := range tst.Extensions {
		if ext.Critical {
			return nil, verificationErrorf(ReasonExtension, "unsupported critical TSTInfo extension %s", ext.OID)
		}
	}

	// Signer certificate and identifier binding.
	signer, err := findSigner(si, sd.Certificates)
	if err != nil {
		return nil, err
	}

	// Signed attributes: mandatory for RFC 3161 because of the ESS attribute.
	digestAlg, ok := hashAlgorithmByOID(si.DigestAlgorithm.OID)
	if !ok || !si.DigestAlgorithm.paramsAbsentOrNull() {
		return nil, verificationErrorf(ReasonAlgorithm, "signer digest algorithm %s is not allowed", si.DigestAlgorithm.OID)
	}
	if err := checkSignedAttributes(si, sd.EContent, digestAlg, signer); err != nil {
		return nil, err
	}

	// CMS signature over the signed attributes exactly as received.
	if err := checkSignature(signer, si, digestAlg); err != nil {
		return nil, err
	}

	// Certificate path to a configured trust anchor, evaluated at genTime.
	chain, err := v.verifyChain(signer, sd.Certificates, tst.GenTime)
	if err != nil {
		return nil, err
	}
	if err := checkTimeStampingCertificate(signer); err != nil {
		return nil, err
	}
	if err := checkTSAName(tst.TSAName, signer); err != nil {
		return nil, err
	}

	// Freshness of newly requested tokens.
	if !p.notBefore.IsZero() && tst.GenTime.Before(p.notBefore) {
		return nil, verificationErrorf(ReasonTime, "genTime %s is before the request window", tst.GenTime.Format(time.RFC3339))
	}
	if !p.notAfter.IsZero() && tst.GenTime.After(p.notAfter) {
		return nil, verificationErrorf(ReasonTime, "genTime %s is in the future", tst.GenTime.Format(time.RFC3339))
	}

	revocationChecked := false
	if p.checkRevocation && v.revocation != nil {
		if err := v.revocation.check(ctx, chain); err != nil {
			return nil, err
		}
		// A chain made only of the trust anchor has nothing to check.
		revocationChecked = len(chain) > 1
	}

	vt := &VerifiedToken{
		GenTime:           tst.GenTime,
		SerialNumber:      tst.SerialNumber,
		Policy:            tst.Policy.String(),
		HashAlgorithm:     imprintAlg.name,
		Nonce:             tst.Nonce,
		Signer:            signer,
		Chain:             chain,
		RevocationChecked: revocationChecked,
	}
	if tst.Accuracy != nil {
		vt.Accuracy = tst.Accuracy.duration()
	}
	return vt, nil
}

// rejectedError builds a safe description of a non-granted PKIStatusInfo.
func rejectedError(st pkiStatusInfo) error {
	text := sanitizeText(strings.Join(st.StatusString, "; "), 200)
	failBits := []int{}
	for i := 0; i < st.FailInfo.BitLength; i++ {
		if st.FailInfo.At(i) == 1 {
			failBits = append(failBits, i)
		}
	}
	return &rejection{status: st.Status, text: text, failInfo: failBits}
}

type rejection struct {
	status   int
	text     string
	failInfo []int
}

func (r *rejection) Error() string {
	return fmt.Sprintf("TSA rejected the timestamp request: status=%d failInfo=%v text=%q", r.status, r.failInfo, r.text)
}

func (r *rejection) Unwrap() error { return ErrTimestampRejected }

// sanitizeText keeps printable characters only and truncates the result, so
// that provider-supplied text can be logged safely.
func sanitizeText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func findSigner(si *signerInfo, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case si.IssuerRaw != nil:
		if si.Version != 1 {
			return nil, verificationErrorf(ReasonSigner, "SignerInfo version %d with issuerAndSerialNumber, want 1", si.Version)
		}
		for _, c := range certs {
			if c.SerialNumber.Cmp(si.SerialNumber) == 0 && bytes.Equal(c.RawIssuer, si.IssuerRaw) {
				return c, nil
			}
		}
	case si.SubjectKeyID != nil:
		if si.Version != 3 {
			return nil, verificationErrorf(ReasonSigner, "SignerInfo version %d with subjectKeyIdentifier, want 3", si.Version)
		}
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, si.SubjectKeyID) {
				return c, nil
			}
		}
	}
	return nil, verificationErrorf(ReasonSigner, "signer certificate not found in the token (was certReq honoured?)")
}

// checkSignedAttributes enforces RFC 5652 5.3/11 and RFC 3161 2.4.1 / RFC 5816:
// content-type, message-digest and an ESS signing-certificate attribute that
// identifies the signer certificate.
func checkSignedAttributes(si *signerInfo, eContent []byte, digestAlg hashAlgorithm, signer *x509.Certificate) error {
	if len(si.SignedAttrsRaw) == 0 {
		return verificationErrorf(ReasonSignedAttributes, "token has no signed attributes")
	}

	single := func(oid asn1.ObjectIdentifier) ([]byte, bool, error) {
		for _, a := range si.SignedAttrs {
			if a.Type.Equal(oid) {
				if len(a.Values) != 1 {
					return nil, true, verificationErrorf(ReasonSignedAttributes, "attribute %s must have exactly one value", oid)
				}
				return a.Values[0], true, nil
			}
		}
		return nil, false, nil
	}

	ct, ok, err := single(oidAttrContentType)
	if err != nil {
		return err
	}
	var ctOID asn1.ObjectIdentifier
	ctStr := cryptobyte.String(ct)
	if !ok || !ctStr.ReadASN1ObjectIdentifier(&ctOID) || !ctStr.Empty() || !ctOID.Equal(oidContentTypeTST) {
		return verificationErrorf(ReasonSignedAttributes, "content-type attribute missing or not id-ct-TSTInfo")
	}

	md, ok, err := single(oidAttrMessageDigest)
	if err != nil {
		return err
	}
	var digest cryptobyte.String
	mdStr := cryptobyte.String(md)
	if !ok || !mdStr.ReadASN1(&digest, cbasn1.OCTET_STRING) || !mdStr.Empty() {
		return verificationErrorf(ReasonSignedAttributes, "message-digest attribute missing or malformed")
	}
	if subtle.ConstantTimeCompare(digestAlg.sum(eContent), digest) != 1 {
		return verificationErrorf(ReasonSignedAttributes, "message-digest attribute does not match the TSTInfo")
	}

	if alg, ok, err := single(oidAttrCMSAlgProtection); err != nil {
		return err
	} else if ok {
		if err := checkAlgorithmProtection(alg, si); err != nil {
			return err
		}
	}

	v2, hasV2, err := single(oidAttrSigningCertificateV2)
	if err != nil {
		return err
	}
	v1, hasV1, err := single(oidAttrSigningCertificate)
	if err != nil {
		return err
	}
	if !hasV1 && !hasV2 {
		return verificationErrorf(ReasonESS, "no ESS signing-certificate attribute")
	}
	if hasV2 {
		if err := checkESSSigningCertificate(v2, true, signer); err != nil {
			return err
		}
	}
	if hasV1 {
		if err := checkESSSigningCertificate(v1, false, signer); err != nil {
			return err
		}
	}
	return nil
}

// checkESSSigningCertificate verifies that the first ESSCertID(v2) identifies
// the signer certificate (RFC 5035 section 5.4).
func checkESSSigningCertificate(value []byte, v2 bool, signer *x509.Certificate) error {
	in := cryptobyte.String(value)
	var sc, certIDs, certID cryptobyte.String
	if !in.ReadASN1(&sc, cbasn1.SEQUENCE) || !in.Empty() ||
		!sc.ReadASN1(&certIDs, cbasn1.SEQUENCE) || !certIDs.ReadASN1(&certID, cbasn1.SEQUENCE) {
		return verificationErrorf(ReasonESS, "malformed signing-certificate attribute")
	}

	var certHash []byte
	if v2 {
		alg := hashAlgorithm{name: "sha256", oid: oidSHA256, hash: crypto.SHA256}
		if certID.PeekASN1Tag(cbasn1.SEQUENCE) {
			ai, ok := readAlgorithmIdentifier(&certID)
			if !ok {
				return verificationErrorf(ReasonESS, "malformed ESSCertIDv2 hashAlgorithm")
			}
			if alg, ok = hashAlgorithmByOID(ai.OID); !ok {
				return verificationErrorf(ReasonESS, "ESSCertIDv2 hash algorithm %s is not allowed", ai.OID)
			}
		}
		certHash = alg.sum(signer.Raw)
	} else {
		// ESSCertID (v1) is defined with SHA-1. It is used here only as a
		// certificate identifier, never to protect the signature itself.
		sum := sha1.Sum(signer.Raw)
		certHash = sum[:]
	}

	var got cryptobyte.String
	if !certID.ReadASN1(&got, cbasn1.OCTET_STRING) {
		return verificationErrorf(ReasonESS, "malformed ESSCertID certHash")
	}
	if subtle.ConstantTimeCompare(got, certHash) != 1 {
		return verificationErrorf(ReasonESS, "ESS signing-certificate does not identify the signer certificate")
	}

	if certID.PeekASN1Tag(cbasn1.SEQUENCE) {
		var issuerSerial cryptobyte.String
		if !certID.ReadASN1(&issuerSerial, cbasn1.SEQUENCE) {
			return verificationErrorf(ReasonESS, "malformed ESS IssuerSerial")
		}
		if err := checkIssuerSerial(issuerSerial, signer); err != nil {
			return err
		}
	}
	if !certID.Empty() {
		return verificationErrorf(ReasonESS, "trailing data in ESSCertID")
	}
	return nil
}

func checkIssuerSerial(s cryptobyte.String, signer *x509.Certificate) error {
	var names cryptobyte.String
	serial := new(big.Int)
	if !s.ReadASN1(&names, cbasn1.SEQUENCE) || !s.ReadASN1Integer(serial) || !s.Empty() {
		return verificationErrorf(ReasonESS, "malformed ESS IssuerSerial")
	}
	if serial.Cmp(signer.SerialNumber) != 0 {
		return verificationErrorf(ReasonESS, "ESS IssuerSerial serial number does not match the signer certificate")
	}
	matched := false
	for !names.Empty() {
		var gn cryptobyte.String
		var tag cbasn1.Tag
		if !names.ReadAnyASN1(&gn, &tag) {
			return verificationErrorf(ReasonESS, "malformed ESS IssuerSerial GeneralName")
		}
		if tag == tagContext4Constructed && bytes.Equal(gn, signer.RawIssuer) {
			matched = true
		}
	}
	if !matched {
		return verificationErrorf(ReasonESS, "ESS IssuerSerial issuer does not match the signer certificate")
	}
	return nil
}

// checkAlgorithmProtection enforces RFC 6211 when the attribute is present.
func checkAlgorithmProtection(value []byte, si *signerInfo) error {
	in := cryptobyte.String(value)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return verificationErrorf(ReasonSignedAttributes, "malformed CMSAlgorithmProtection")
	}
	digest, ok := readAlgorithmIdentifier(&seq)
	if !ok || !digest.OID.Equal(si.DigestAlgorithm.OID) {
		return verificationErrorf(ReasonSignedAttributes, "CMSAlgorithmProtection digest algorithm mismatch")
	}
	if seq.PeekASN1Tag(tagContext1Constructed) {
		var sig cryptobyte.String
		var oid asn1.ObjectIdentifier
		if !seq.ReadASN1(&sig, tagContext1Constructed) || !sig.ReadASN1ObjectIdentifier(&oid) || !oid.Equal(si.SignatureAlgorithm.OID) {
			return verificationErrorf(ReasonSignedAttributes, "CMSAlgorithmProtection signature algorithm mismatch")
		}
	}
	if !seq.Empty() {
		return verificationErrorf(ReasonSignedAttributes, "CMSAlgorithmProtection must not carry a MAC algorithm")
	}
	return nil
}

// signedAttributesForSignature returns the DER that the signature covers: the
// received signedAttrs with the [0] IMPLICIT tag replaced by the SET tag
// (RFC 5652 section 5.4). Only the identifier octet changes; the length and the
// content are kept byte for byte.
func signedAttributesForSignature(raw []byte) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	out[0] = 0x31
	return out
}

func checkSignature(signer *x509.Certificate, si *signerInfo, digestAlg hashAlgorithm) error {
	digest := digestAlg.sum(signedAttributesForSignature(si.SignedAttrsRaw))
	sigOID := si.SignatureAlgorithm.OID

	// For algorithms that name their own hash, it must agree with digestAlgorithm.
	requireHash := func(h crypto.Hash) error {
		if h != digestAlg.hash {
			return verificationErrorf(ReasonAlgorithm, "signature algorithm %s does not match digest algorithm %s", sigOID, digestAlg.name)
		}
		return nil
	}

	switch pub := signer.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return verificationErrorf(ReasonAlgorithm, "RSA key of %d bits is too small", pub.N.BitLen())
		}
		switch {
		case sigOID.Equal(oidRSAEncryption):
		case sigOID.Equal(oidSHA256WithRSA):
			if err := requireHash(crypto.SHA256); err != nil {
				return err
			}
		case sigOID.Equal(oidSHA384WithRSA):
			if err := requireHash(crypto.SHA384); err != nil {
				return err
			}
		case sigOID.Equal(oidSHA512WithRSA):
			if err := requireHash(crypto.SHA512); err != nil {
				return err
			}
		case sigOID.Equal(oidRSASSAPSS):
			h, salt, err := parsePSSParams(si.SignatureAlgorithm.Params)
			if err != nil {
				return err
			}
			if err := requireHash(h); err != nil {
				return err
			}
			if err := rsa.VerifyPSS(pub, h, digest, si.Signature, &rsa.PSSOptions{SaltLength: salt, Hash: h}); err != nil {
				return verificationErrorf(ReasonSignature, "RSA-PSS signature is invalid")
			}
			return nil
		default:
			return verificationErrorf(ReasonAlgorithm, "signature algorithm %s is not allowed for RSA keys", sigOID)
		}
		if !si.SignatureAlgorithm.paramsAbsentOrNull() {
			return verificationErrorf(ReasonAlgorithm, "unexpected RSA signature parameters")
		}
		if err := rsa.VerifyPKCS1v15(pub, digestAlg.hash, digest, si.Signature); err != nil {
			return verificationErrorf(ReasonSignature, "RSA signature is invalid")
		}
		return nil

	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
		default:
			return verificationErrorf(ReasonAlgorithm, "elliptic curve is not allowed")
		}
		switch {
		case sigOID.Equal(oidECPublicKey):
		case sigOID.Equal(oidECDSAWithSHA256):
			if err := requireHash(crypto.SHA256); err != nil {
				return err
			}
		case sigOID.Equal(oidECDSAWithSHA384):
			if err := requireHash(crypto.SHA384); err != nil {
				return err
			}
		case sigOID.Equal(oidECDSAWithSHA512):
			if err := requireHash(crypto.SHA512); err != nil {
				return err
			}
		default:
			return verificationErrorf(ReasonAlgorithm, "signature algorithm %s is not allowed for ECDSA keys", sigOID)
		}
		if !ecdsa.VerifyASN1(pub, digest, si.Signature) {
			return verificationErrorf(ReasonSignature, "ECDSA signature is invalid")
		}
		return nil

	default:
		return verificationErrorf(ReasonAlgorithm, "unsupported signer public key type %T", signer.PublicKey)
	}
}

// parsePSSParams parses RSASSA-PSS-params (RFC 4055) and only accepts an
// allowed hash with MGF1 over the same hash and the standard trailer field.
func parsePSSParams(params []byte) (crypto.Hash, int, error) {
	bad := func(what string) (crypto.Hash, int, error) {
		return 0, 0, verificationErrorf(ReasonAlgorithm, "unsupported RSA-PSS parameters: %s", what)
	}
	in := cryptobyte.String(params)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return bad("not a SEQUENCE")
	}

	hash, mgfHash, salt, trailer := crypto.SHA1, crypto.SHA1, 20, 1
	if seq.PeekASN1Tag(tagContext0Constructed) {
		var h cryptobyte.String
		if !seq.ReadASN1(&h, tagContext0Constructed) {
			return bad("hashAlgorithm")
		}
		ai, ok := readAlgorithmIdentifier(&h)
		if !ok || !h.Empty() {
			return bad("hashAlgorithm")
		}
		alg, ok := hashAlgorithmByOID(ai.OID)
		if !ok {
			return bad("hash algorithm not allowed")
		}
		hash = alg.hash
	}
	if seq.PeekASN1Tag(tagContext1Constructed) {
		var m cryptobyte.String
		if !seq.ReadASN1(&m, tagContext1Constructed) {
			return bad("maskGenAlgorithm")
		}
		mgf, ok := readAlgorithmIdentifier(&m)
		if !ok || !m.Empty() || !mgf.OID.Equal(oidMGF1) {
			return bad("maskGenAlgorithm must be MGF1")
		}
		inner := cryptobyte.String(mgf.Params)
		ai, ok := readAlgorithmIdentifier(&inner)
		if !ok || !inner.Empty() {
			return bad("MGF1 hash")
		}
		alg, ok := hashAlgorithmByOID(ai.OID)
		if !ok {
			return bad("MGF1 hash not allowed")
		}
		mgfHash = alg.hash
	}
	if seq.PeekASN1Tag(tagContext2Constructed) {
		var sl cryptobyte.String
		if !seq.ReadASN1(&sl, tagContext2Constructed) || !sl.ReadASN1Integer(&salt) || !sl.Empty() {
			return bad("saltLength")
		}
	}
	if seq.PeekASN1Tag(tagContext3Constructed) {
		var tf cryptobyte.String
		if !seq.ReadASN1(&tf, tagContext3Constructed) || !tf.ReadASN1Integer(&trailer) || !tf.Empty() {
			return bad("trailerField")
		}
	}
	if !seq.Empty() || trailer != 1 || salt < 0 {
		return bad("trailing data, trailer field or salt")
	}
	if hash == crypto.SHA1 || mgfHash != hash {
		return bad("hash must be SHA-256 or stronger and match MGF1")
	}
	return hash, salt, nil
}

func (v *Verifier) verifyChain(signer *x509.Certificate, tokenCerts []*x509.Certificate, at time.Time) ([]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for _, c := range tokenCerts {
		intermediates.AddCert(c)
	}
	for _, c := range v.intermediates {
		intermediates.AddCert(c)
	}
	chains, err := signer.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		// Enforces that every CA in the path is allowed to issue time-stamping certificates.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return nil, verificationErrorf(ReasonChain, "TSA certificate does not chain to a configured trust anchor at genTime: %v", err)
	}
	return chains[0], nil
}

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// checkTimeStampingCertificate enforces RFC 3161 section 2.3: the TSA
// certificate MUST contain exactly one, critical, extended key usage: id-kp-timeStamping.
func checkTimeStampingCertificate(c *x509.Certificate) error {
	if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(c.UnknownExtKeyUsage) != 0 {
		return verificationErrorf(ReasonEKU, "TSA certificate extended key usage must be exactly id-kp-timeStamping")
	}
	critical := false
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			critical = e.Critical
		}
	}
	if !critical {
		return verificationErrorf(ReasonEKU, "TSA certificate extended key usage extension must be critical")
	}
	if c.KeyUsage != 0 && c.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return verificationErrorf(ReasonEKU, "TSA certificate key usage does not allow digital signatures")
	}
	return nil
}

// checkTSAName enforces that, when TSTInfo.tsa is a directoryName, it names the signer.
func checkTSAName(tsaName []byte, signer *x509.Certificate) error {
	if len(tsaName) == 0 {
		return nil
	}
	in := cryptobyte.String(tsaName)
	var name cryptobyte.String
	var tag cbasn1.Tag
	if !in.ReadAnyASN1(&name, &tag) || !in.Empty() {
		return malformedf("TSTInfo tsa GeneralName")
	}
	if tag != tagContext4Constructed {
		return nil // Other GeneralName forms cannot be compared reliably with the certificate.
	}
	if !bytes.Equal(name, signer.RawSubject) {
		return verificationErrorf(ReasonSigner, "TSTInfo tsa name does not match the signer certificate subject")
	}
	return nil
}

// certFingerprint returns the hex SHA-256 of a certificate, used in logs.
func certFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}
