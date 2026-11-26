package tsaservice

import (
	"crypto"
	"encoding/asn1"
)

// Object identifiers used by RFC 3161 (Time-Stamp Protocol), RFC 5652 (CMS),
// RFC 5035/5816 (ESS signing-certificate) and RFC 6211 (CMS algorithm protection).
var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentTypeTST = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // id-ct-TSTInfo

	oidAttrContentType          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCertificate   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidAttrCMSAlgProtection     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// hashAlgorithm describes a digest algorithm that this package is willing to use.
type hashAlgorithm struct {
	name string
	oid  asn1.ObjectIdentifier
	hash crypto.Hash
}

// allowedHashes is the closed list of digest algorithms accepted both for the
// MessageImprint and for the CMS signature. SHA-1 is deliberately absent: it is
// only recognised to produce a clear error message.
var allowedHashes = []hashAlgorithm{
	{name: "sha256", oid: oidSHA256, hash: crypto.SHA256},
	{name: "sha384", oid: oidSHA384, hash: crypto.SHA384},
	{name: "sha512", oid: oidSHA512, hash: crypto.SHA512},
}

func hashAlgorithmByName(name string) (hashAlgorithm, bool) {
	for _, h := range allowedHashes {
		if h.name == name {
			return h, true
		}
	}
	return hashAlgorithm{}, false
}

func hashAlgorithmByOID(oid asn1.ObjectIdentifier) (hashAlgorithm, bool) {
	for _, h := range allowedHashes {
		if h.oid.Equal(oid) {
			return h, true
		}
	}
	return hashAlgorithm{}, false
}

func (h hashAlgorithm) sum(data []byte) []byte {
	d := h.hash.New()
	d.Write(data)
	return d.Sum(nil)
}
