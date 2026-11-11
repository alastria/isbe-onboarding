package tsaservice

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// This file contains a strict DER parser for the subset of RFC 3161 / RFC 5652
// structures that a time-stamp token uses. It is written with cryptobyte, which
// rejects non-minimal lengths and trailing data, and it keeps the exact bytes
// of every element that takes part in a signature or a hash so that
// verification never works on re-encoded data.

var (
	tagContext0Constructed = cbasn1.Tag(0).Constructed().ContextSpecific()
	tagContext1Constructed = cbasn1.Tag(1).Constructed().ContextSpecific()
	tagContext2Constructed = cbasn1.Tag(2).Constructed().ContextSpecific()
	tagContext3Constructed = cbasn1.Tag(3).Constructed().ContextSpecific()
	tagContext4Constructed = cbasn1.Tag(4).Constructed().ContextSpecific()
	tagContext0Primitive   = cbasn1.Tag(0).ContextSpecific()
	tagContext1Primitive   = cbasn1.Tag(1).ContextSpecific()
)

// PKIStatus values (RFC 3161 section 2.4.2).
const (
	pkiStatusGranted         = 0
	pkiStatusGrantedWithMods = 1
)

type algorithmIdentifier struct {
	OID    asn1.ObjectIdentifier
	Params []byte // full DER of the parameters element, nil when absent
}

// paramsAbsentOrNull reports whether the parameters are absent or an ASN.1 NULL,
// which are the two encodings allowed for the digest algorithms we accept.
func (a algorithmIdentifier) paramsAbsentOrNull() bool {
	return len(a.Params) == 0 || (len(a.Params) == 2 && a.Params[0] == 0x05 && a.Params[1] == 0x00)
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string
	FailInfo     asn1.BitString
}

type timeStampResp struct {
	Status pkiStatusInfo
	Token  []byte // full DER of the TimeStampToken (a CMS ContentInfo), nil when absent
}

type signedData struct {
	Version          int
	DigestAlgorithms []algorithmIdentifier
	EContentType     asn1.ObjectIdentifier
	EContent         []byte // content octets of the eContent OCTET STRING (DER TSTInfo)
	Certificates     []*x509.Certificate
	SignerInfos      []signerInfo
}

type signerInfo struct {
	Version int

	// SignerIdentifier: either IssuerAndSerialNumber or SubjectKeyIdentifier.
	IssuerRaw    []byte
	SerialNumber *big.Int
	SubjectKeyID []byte

	DigestAlgorithm algorithmIdentifier

	// SignedAttrsRaw holds the signedAttrs element exactly as received,
	// including its [0] IMPLICIT tag. The signature is computed over these
	// bytes with the tag replaced by the universal SET tag (RFC 5652, 5.4).
	SignedAttrsRaw []byte
	SignedAttrs    []attribute

	SignatureAlgorithm algorithmIdentifier
	Signature          []byte
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte // full DER of each AttributeValue
}

type accuracy struct {
	Seconds, Millis, Micros int64
}

func (a accuracy) duration() time.Duration {
	return time.Duration(a.Seconds)*time.Second + time.Duration(a.Millis)*time.Millisecond + time.Duration(a.Micros)*time.Microsecond
}

type extension struct {
	OID      asn1.ObjectIdentifier
	Critical bool
	Value    []byte
}

type tstInfo struct {
	Version       int
	Policy        asn1.ObjectIdentifier
	HashAlgorithm algorithmIdentifier
	HashedMessage []byte
	SerialNumber  *big.Int
	GenTime       time.Time
	Accuracy      *accuracy
	Ordering      bool
	Nonce         *big.Int
	TSAName       []byte // full DER of the GeneralName, nil when absent
	Extensions    []extension
}

func malformedf(format string, args ...any) error {
	return &VerificationError{Reason: ReasonMalformed, Err: fmt.Errorf("%w: "+format, append([]any{ErrMalformedResponse}, args...)...)}
}

func readAlgorithmIdentifier(s *cryptobyte.String) (algorithmIdentifier, bool) {
	var seq cryptobyte.String
	var alg algorithmIdentifier
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&alg.OID) {
		return alg, false
	}
	if !seq.Empty() {
		var params cryptobyte.String
		var tag cbasn1.Tag
		if !seq.ReadAnyASN1Element(&params, &tag) || !seq.Empty() {
			return alg, false
		}
		alg.Params = params
	}
	return alg, true
}

// parseTimeStampResp parses a DER TimeStampResp (RFC 3161, section 2.4.2).
func parseTimeStampResp(der []byte) (*timeStampResp, error) {
	input := cryptobyte.String(der)
	var seq, statusSeq cryptobyte.String
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, malformedf("TimeStampResp is not a single DER SEQUENCE")
	}
	if !seq.ReadASN1(&statusSeq, cbasn1.SEQUENCE) {
		return nil, malformedf("PKIStatusInfo")
	}

	resp := &timeStampResp{}
	if !statusSeq.ReadASN1Integer(&resp.Status.Status) {
		return nil, malformedf("PKIStatus")
	}
	if statusSeq.PeekASN1Tag(cbasn1.SEQUENCE) {
		var texts cryptobyte.String
		if !statusSeq.ReadASN1(&texts, cbasn1.SEQUENCE) {
			return nil, malformedf("PKIFreeText")
		}
		for !texts.Empty() {
			var text cryptobyte.String
			if !texts.ReadASN1(&text, cbasn1.UTF8String) {
				return nil, malformedf("PKIFreeText element")
			}
			resp.Status.StatusString = append(resp.Status.StatusString, string(text))
		}
	}
	if statusSeq.PeekASN1Tag(cbasn1.BIT_STRING) {
		if !statusSeq.ReadASN1BitString(&resp.Status.FailInfo) {
			return nil, malformedf("PKIFailureInfo")
		}
	}
	if !statusSeq.Empty() {
		return nil, malformedf("trailing data in PKIStatusInfo")
	}

	if !seq.Empty() {
		var token cryptobyte.String
		if !seq.ReadASN1Element(&token, cbasn1.SEQUENCE) {
			return nil, malformedf("TimeStampToken")
		}
		resp.Token = token
	}
	if !seq.Empty() {
		return nil, malformedf("trailing data in TimeStampResp")
	}
	return resp, nil
}

// parseSignedDataToken parses a CMS ContentInfo that must wrap a SignedData.
func parseSignedDataToken(token []byte) (*signedData, error) {
	input := cryptobyte.String(token)
	var ci, content, sdSeq cryptobyte.String
	var contentType asn1.ObjectIdentifier
	if !input.ReadASN1(&ci, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, malformedf("ContentInfo")
	}
	if !ci.ReadASN1ObjectIdentifier(&contentType) {
		return nil, malformedf("ContentInfo contentType")
	}
	if !contentType.Equal(oidSignedData) {
		return nil, malformedf("TimeStampToken content type is %s, want id-signedData", contentType)
	}
	if !ci.ReadASN1(&content, tagContext0Constructed) || !ci.Empty() {
		return nil, malformedf("ContentInfo content")
	}
	if !content.ReadASN1(&sdSeq, cbasn1.SEQUENCE) || !content.Empty() {
		return nil, malformedf("SignedData")
	}

	sd := &signedData{}
	if !sdSeq.ReadASN1Integer(&sd.Version) {
		return nil, malformedf("SignedData version")
	}

	var digestAlgs cryptobyte.String
	if !sdSeq.ReadASN1(&digestAlgs, cbasn1.SET) {
		return nil, malformedf("SignedData digestAlgorithms")
	}
	for !digestAlgs.Empty() {
		alg, ok := readAlgorithmIdentifier(&digestAlgs)
		if !ok {
			return nil, malformedf("SignedData digestAlgorithm")
		}
		sd.DigestAlgorithms = append(sd.DigestAlgorithms, alg)
	}

	var eci, eContentExplicit, eContent cryptobyte.String
	var hasEContent bool
	if !sdSeq.ReadASN1(&eci, cbasn1.SEQUENCE) || !eci.ReadASN1ObjectIdentifier(&sd.EContentType) {
		return nil, malformedf("EncapsulatedContentInfo")
	}
	if !eci.ReadOptionalASN1(&eContentExplicit, &hasEContent, tagContext0Constructed) || !eci.Empty() {
		return nil, malformedf("EncapsulatedContentInfo eContent")
	}
	if !hasEContent {
		return nil, malformedf("TimeStampToken has no encapsulated TSTInfo")
	}
	if !eContentExplicit.ReadASN1(&eContent, cbasn1.OCTET_STRING) || !eContentExplicit.Empty() {
		return nil, malformedf("eContent is not a single OCTET STRING")
	}
	sd.EContent = eContent

	var certs cryptobyte.String
	var hasCerts bool
	if !sdSeq.ReadOptionalASN1(&certs, &hasCerts, tagContext0Constructed) {
		return nil, malformedf("SignedData certificates")
	}
	for hasCerts && !certs.Empty() {
		var el cryptobyte.String
		var tag cbasn1.Tag
		if !certs.ReadAnyASN1Element(&el, &tag) {
			return nil, malformedf("CertificateChoices")
		}
		if tag != cbasn1.SEQUENCE {
			// Attribute certificates and other formats are not used by RFC 3161 and are ignored.
			continue
		}
		cert, err := x509.ParseCertificate(el)
		if err != nil {
			return nil, malformedf("certificate in SignedData: %v", err)
		}
		sd.Certificates = append(sd.Certificates, cert)
	}

	var crls cryptobyte.String
	var hasCRLs bool
	if !sdSeq.ReadOptionalASN1(&crls, &hasCRLs, tagContext1Constructed) {
		return nil, malformedf("SignedData crls")
	}

	var signerInfos cryptobyte.String
	if !sdSeq.ReadASN1(&signerInfos, cbasn1.SET) || !sdSeq.Empty() {
		return nil, malformedf("SignedData signerInfos")
	}
	for !signerInfos.Empty() {
		si, err := parseSignerInfo(&signerInfos)
		if err != nil {
			return nil, err
		}
		sd.SignerInfos = append(sd.SignerInfos, *si)
	}
	return sd, nil
}

func parseSignerInfo(input *cryptobyte.String) (*signerInfo, error) {
	var s cryptobyte.String
	if !input.ReadASN1(&s, cbasn1.SEQUENCE) {
		return nil, malformedf("SignerInfo")
	}
	si := &signerInfo{}
	if !s.ReadASN1Integer(&si.Version) {
		return nil, malformedf("SignerInfo version")
	}

	switch {
	case s.PeekASN1Tag(cbasn1.SEQUENCE):
		var ias, issuer cryptobyte.String
		si.SerialNumber = new(big.Int)
		if !s.ReadASN1(&ias, cbasn1.SEQUENCE) ||
			!ias.ReadASN1Element(&issuer, cbasn1.SEQUENCE) ||
			!ias.ReadASN1Integer(si.SerialNumber) || !ias.Empty() {
			return nil, malformedf("SignerInfo issuerAndSerialNumber")
		}
		si.IssuerRaw = issuer
	case s.PeekASN1Tag(tagContext0Primitive):
		var ski cryptobyte.String
		if !s.ReadASN1(&ski, tagContext0Primitive) || len(ski) == 0 {
			return nil, malformedf("SignerInfo subjectKeyIdentifier")
		}
		si.SubjectKeyID = ski
	default:
		return nil, malformedf("SignerInfo sid")
	}

	var ok bool
	if si.DigestAlgorithm, ok = readAlgorithmIdentifier(&s); !ok {
		return nil, malformedf("SignerInfo digestAlgorithm")
	}

	if s.PeekASN1Tag(tagContext0Constructed) {
		var el cryptobyte.String
		if !s.ReadASN1Element(&el, tagContext0Constructed) {
			return nil, malformedf("SignerInfo signedAttrs")
		}
		si.SignedAttrsRaw = el
		attrs, err := parseAttributes(el)
		if err != nil {
			return nil, err
		}
		si.SignedAttrs = attrs
	}

	if si.SignatureAlgorithm, ok = readAlgorithmIdentifier(&s); !ok {
		return nil, malformedf("SignerInfo signatureAlgorithm")
	}
	var sig cryptobyte.String
	if !s.ReadASN1(&sig, cbasn1.OCTET_STRING) || len(sig) == 0 {
		return nil, malformedf("SignerInfo signature")
	}
	si.Signature = sig

	if s.PeekASN1Tag(tagContext1Constructed) {
		var unsigned cryptobyte.String
		if !s.ReadASN1(&unsigned, tagContext1Constructed) {
			return nil, malformedf("SignerInfo unsignedAttrs")
		}
	}
	if !s.Empty() {
		return nil, malformedf("trailing data in SignerInfo")
	}
	return si, nil
}

// parseAttributes parses a full [0] IMPLICIT SET OF Attribute element.
func parseAttributes(element []byte) ([]attribute, error) {
	input := cryptobyte.String(element)
	var set cryptobyte.String
	if !input.ReadASN1(&set, tagContext0Constructed) || !input.Empty() {
		return nil, malformedf("signedAttrs")
	}
	var attrs []attribute
	seen := map[string]bool{}
	for !set.Empty() {
		var a, values cryptobyte.String
		var attr attribute
		if !set.ReadASN1(&a, cbasn1.SEQUENCE) || !a.ReadASN1ObjectIdentifier(&attr.Type) ||
			!a.ReadASN1(&values, cbasn1.SET) || !a.Empty() {
			return nil, malformedf("signed attribute")
		}
		for !values.Empty() {
			var v cryptobyte.String
			var tag cbasn1.Tag
			if !values.ReadAnyASN1Element(&v, &tag) {
				return nil, malformedf("signed attribute value")
			}
			attr.Values = append(attr.Values, v)
		}
		if len(attr.Values) == 0 {
			return nil, malformedf("signed attribute %s has no values", attr.Type)
		}
		key := attr.Type.String()
		if seen[key] {
			return nil, malformedf("duplicate signed attribute %s", attr.Type)
		}
		seen[key] = true
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

// parseTSTInfo parses a DER TSTInfo (RFC 3161, section 2.4.2).
func parseTSTInfo(der []byte) (*tstInfo, error) {
	input := cryptobyte.String(der)
	var s cryptobyte.String
	if !input.ReadASN1(&s, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, malformedf("TSTInfo is not a single DER SEQUENCE")
	}

	t := &tstInfo{}
	if !s.ReadASN1Integer(&t.Version) || !s.ReadASN1ObjectIdentifier(&t.Policy) {
		return nil, malformedf("TSTInfo version or policy")
	}

	var mi, hashed cryptobyte.String
	var ok bool
	if !s.ReadASN1(&mi, cbasn1.SEQUENCE) {
		return nil, malformedf("TSTInfo messageImprint")
	}
	if t.HashAlgorithm, ok = readAlgorithmIdentifier(&mi); !ok {
		return nil, malformedf("messageImprint hashAlgorithm")
	}
	if !mi.ReadASN1(&hashed, cbasn1.OCTET_STRING) || !mi.Empty() {
		return nil, malformedf("messageImprint hashedMessage")
	}
	t.HashedMessage = hashed

	t.SerialNumber = new(big.Int)
	if !s.ReadASN1Integer(t.SerialNumber) {
		return nil, malformedf("TSTInfo serialNumber")
	}

	var genTime cryptobyte.String
	if !s.ReadASN1(&genTime, cbasn1.GeneralizedTime) {
		return nil, malformedf("TSTInfo genTime")
	}
	gt, err := parseGeneralizedTime(string(genTime))
	if err != nil {
		return nil, malformedf("TSTInfo genTime: %v", err)
	}
	t.GenTime = gt

	if s.PeekASN1Tag(cbasn1.SEQUENCE) {
		var acc cryptobyte.String
		a := &accuracy{}
		if !s.ReadASN1(&acc, cbasn1.SEQUENCE) {
			return nil, malformedf("TSTInfo accuracy")
		}
		if acc.PeekASN1Tag(cbasn1.INTEGER) && !acc.ReadASN1Integer(&a.Seconds) {
			return nil, malformedf("accuracy seconds")
		}
		if !acc.ReadOptionalASN1Integer(&a.Millis, tagContext0Primitive, int64(0)) ||
			!acc.ReadOptionalASN1Integer(&a.Micros, tagContext1Primitive, int64(0)) || !acc.Empty() {
			return nil, malformedf("accuracy millis or micros")
		}
		// Accuracy is informational; bound it so the duration cannot overflow.
		if a.Seconds < 0 || a.Seconds > 86400 || a.Millis < 0 || a.Millis > 999 || a.Micros < 0 || a.Micros > 999 {
			return nil, malformedf("accuracy out of range")
		}
		t.Accuracy = a
	}

	if s.PeekASN1Tag(cbasn1.BOOLEAN) && !s.ReadASN1Boolean(&t.Ordering) {
		return nil, malformedf("TSTInfo ordering")
	}

	if s.PeekASN1Tag(cbasn1.INTEGER) {
		t.Nonce = new(big.Int)
		if !s.ReadASN1Integer(t.Nonce) {
			return nil, malformedf("TSTInfo nonce")
		}
	}

	if s.PeekASN1Tag(tagContext0Constructed) {
		var tsa cryptobyte.String
		if !s.ReadASN1(&tsa, tagContext0Constructed) {
			return nil, malformedf("TSTInfo tsa")
		}
		t.TSAName = tsa
	}

	if s.PeekASN1Tag(tagContext1Constructed) {
		var exts cryptobyte.String
		if !s.ReadASN1(&exts, tagContext1Constructed) {
			return nil, malformedf("TSTInfo extensions")
		}
		for !exts.Empty() {
			var e, value cryptobyte.String
			var ext extension
			if !exts.ReadASN1(&e, cbasn1.SEQUENCE) || !e.ReadASN1ObjectIdentifier(&ext.OID) {
				return nil, malformedf("TSTInfo extension")
			}
			if e.PeekASN1Tag(cbasn1.BOOLEAN) && !e.ReadASN1Boolean(&ext.Critical) {
				return nil, malformedf("TSTInfo extension critical flag")
			}
			if !e.ReadASN1(&value, cbasn1.OCTET_STRING) || !e.Empty() {
				return nil, malformedf("TSTInfo extension value")
			}
			ext.Value = value
			t.Extensions = append(t.Extensions, ext)
		}
	}

	if !s.Empty() {
		return nil, malformedf("trailing data in TSTInfo")
	}
	return t, nil
}

// parseGeneralizedTime parses the GeneralizedTime profile used by RFC 3161:
// YYYYMMDDhhmmss[.s...]Z, always UTC, with no trailing zeros in the fraction.
// cryptobyte's own parser does not accept fractional seconds.
func parseGeneralizedTime(s string) (time.Time, error) {
	if len(s) < 15 || s[len(s)-1] != 'Z' {
		return time.Time{}, fmt.Errorf("invalid GeneralizedTime %q", s)
	}
	base, frac := s[:14], s[14:len(s)-1]
	t, err := time.Parse("20060102150405", base)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid GeneralizedTime %q", s)
	}
	if frac != "" {
		digits := strings.TrimPrefix(frac, ".")
		if digits == frac || digits == "" || len(digits) > 9 || strings.HasSuffix(digits, "0") {
			return time.Time{}, fmt.Errorf("invalid GeneralizedTime fraction %q", s)
		}
		ns := 0
		for i := 0; i < 9; i++ {
			ns *= 10
			if i < len(digits) {
				c := digits[i]
				if c < '0' || c > '9' {
					return time.Time{}, fmt.Errorf("invalid GeneralizedTime fraction %q", s)
				}
				ns += int(c - '0')
			}
		}
		t = t.Add(time.Duration(ns))
	}
	return t.UTC(), nil
}
