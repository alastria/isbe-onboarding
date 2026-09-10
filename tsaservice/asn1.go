package tsaservice

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// OIDs
var (
	oidSignedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentTypeTST = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4} // id-ct-TSTInfo
	oidSHA512         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA256         = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA1           = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
)

// TimeStampResp
type TimeStampResp struct {
	Status         PKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"` // This is a ContentInfo
}

type PKIStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// ContentInfo (PKCS#7)
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// SignedData
type SignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"` // IMPLICIT SET OF Certificate
	CRLs             []asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []SignerInfo    `asn1:"set"`
}

type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"` // This contains the OCTET STRING which is the TSTInfo (DER encapsulated)
}

// SignerInfo
type SignerInfo struct {
	Version                   int
	IssuerAndSerial           IssuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttrs        []Attribute `asn1:"optional,tag:0"` // IMPLICIT SET OF Attribute
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttrs      []Attribute `asn1:"optional,tag:1"`
}

// IssuerAndSerial
type IssuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// Attribute
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// TSTInfo as per RFC 3161
type TSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	Tsa            asn1.RawValue    `asn1:"optional,tag:0"` // GeneralName
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"optional,tag:0"`
	Micros  int `asn1:"optional,tag:1"`
}
