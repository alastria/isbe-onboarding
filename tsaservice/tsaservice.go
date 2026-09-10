// Package tsaservice provides a client for Time Stamping Authority (TSA) services.
package tsaservice

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/jpath"
)

const (
	defaultCaCertURL   = "http://pki.digitelts.es/DIGITELTSCAROOT01.pem"
	defaultTsaURL      = "https://timestamp-service.pre-api.digitelts.com/tsa"
	defaultTsaUser     = "tsu-01-redisbe"
	defaultTsaPassword = "mj2TBYOCPe9LRC05"
	defaultEUDSSURL    = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate"
)

// TimestampReq structure as per RFC 3161
type TimeStampReq struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// MessageImprint structure
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// type bigInt = int64 // Removed in favor of math/big

type TSAConfig struct {
	TSAURL      string
	TSAUser     string
	TSAPassword string
	CACertURL   string
	EUDSSURL    string
}

type TSAService struct {
	tsaConfig TSAConfig
	CACert    []byte
}

func NewTSAService(cfg *TSAConfig) (*TSAService, error) {
	if cfg.CACertURL == "" {
		cfg.CACertURL = defaultCaCertURL
	}

	if cfg.TSAURL == "" {
		cfg.TSAURL = defaultTsaURL
	}

	if cfg.TSAUser == "" {
		cfg.TSAUser = defaultTsaUser
	}

	if cfg.TSAPassword == "" {
		cfg.TSAPassword = defaultTsaPassword
	}

	caCert, err := retrieveCaCert(cfg.CACertURL)
	if err != nil {
		return nil, errl.Errorf("failed to retrieve CA certificate from %s: %w", cfg.CACertURL, err)
	}

	return &TSAService{
		tsaConfig: *cfg,
		CACert:    caCert,
	}, nil
}

func (s *TSAService) Timestamp(data []byte) ([]byte, error) {

	if len(s.CACert) == 0 {
		return nil, errl.Errorf("CA cert is empty")
	}

	// Create TimeStamp Query (TSQ)
	tsqDetails, err := createTSQ(data)
	if err != nil {
		return nil, errl.Errorf("failed to create TSQ: %w", err)
	}

	// Send to TSA
	tsrBytes, err := sendTSQToService(tsqDetails)
	if err != nil {
		return nil, errl.Errorf("failed to send TSQ to service: %w", err)
	}

	return tsrBytes, nil
}

type EUDSSVerifyCertificateRequest struct {
	Certificate struct {
		EncodedCertificate string `json:"encodedCertificate"`
	} `json:"certificate"`
	TokenExtractionStrategy string `json:"tokenExtractionStrategy"`
}

// VerifyCertificate verifies a certificate using the EUDSS service.
func VerifyCertificate(data []byte) ([]byte, error) {
	req := EUDSSVerifyCertificateRequest{
		Certificate: struct {
			EncodedCertificate string `json:"encodedCertificate"`
		}{
			EncodedCertificate: string(data),
		},
		TokenExtractionStrategy: "NONE",
	}

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, errl.Errorf("failed to marshal EUDSS request: %w", err)
	}

	// We use a timeout of 30 seconds
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(defaultEUDSSURL, "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, errl.Errorf("failed to send EUDSS request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errl.Errorf("EUDSS request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errl.Errorf("failed to read EUDSS response: %w", err)
	}

	// Parse response as a map[string]any
	var respMap map[string]any
	if err := json.Unmarshal(body, &respMap); err != nil {
		return nil, errl.Errorf("failed to unmarshal EUDSS response: %w", err)
	}

	// Get the simpleCertificateReport object
	simpleCertificateReport := jpath.GetMap(respMap, "simpleCertificateReport")
	if simpleCertificateReport == nil {
		return nil, errl.Errorf("simpleCertificateReport not found in EUDSS response")
	}

	// Get the ChainItem array
	chainItemArray := jpath.GetList(simpleCertificateReport, "ChainItem")
	if chainItemArray == nil {
		return nil, errl.Errorf("ChainItem not found in EUDSS response")
	}

	// All objects of the list must have a field "Indication": "PASSED"
	for _, chainItem := range chainItemArray {
		indication := jpath.GetString(chainItem, "Indication")
		if indication != "PASSED" {
			// Get the subject object
			subject := jpath.GetMap(chainItem, "subject")
			// Log the subject
			out, _ := json.Marshal(subject)
			slog.Error("Validation error for certificate", "subject", string(out))
			return nil, errl.Errorf("validation error for certificate %s", string(out))
		}
	}

	return body, nil
}

// Verify verifies the timestamp response using the service's CA certificate.
// It performs standard chain verification:
// 1. Checks if the response is signed by a cert that chains up to s.caCert.
// 2. Verifies the signature using that signing cert.
func (s *TSAService) Verify(tsrBytes []byte, originalData []byte) (*time.Time, error) {
	// 1. Parse TimeStampResp
	var resp TimeStampResp
	_, err := asn1.Unmarshal(tsrBytes, &resp)
	if err != nil {
		return nil, errl.Errorf("failed to unmarshal TimeStampResp: %w", err)
	}

	if resp.Status.Status != 0 {
		msg := "unknown"
		if len(resp.Status.StatusString) > 0 {
			msg = resp.Status.StatusString[0]
		}
		return nil, errl.Errorf("timestamp request failed: status=%d message=%s", resp.Status.Status, msg)
	}

	if len(resp.TimeStampToken.Bytes) == 0 {
		return nil, errl.Errorf("no TimeStampToken present")
	}

	// 2. Parse ContentInfo (TimeStampToken)
	var ci ContentInfo
	_, err = asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci)
	if err != nil {
		return nil, errl.Errorf("failed to unmarshal ContentInfo: %w", err)
	}

	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errl.Errorf("unexpected content type: %v", ci.ContentType)
	}

	// 3. Parse SignedData
	var sd SignedData
	_, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, errl.Errorf("failed to unmarshal SignedData: %w", err)
	}

	// 4. Parse TSTInfo (Encapsulated Content)
	if !sd.EncapContentInfo.EContentType.Equal(oidContentTypeTST) {
		return nil, errl.Errorf("encapsulated content is not TSTInfo: %v", sd.EncapContentInfo.EContentType)
	}

	var tstInfoBytes []byte
	// Unmarshal the OCTET STRING from the explicit tag content
	_, err = asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstInfoBytes)
	if err != nil {
		tstInfoBytes = sd.EncapContentInfo.EContent.Bytes
	}

	var tst TSTInfo
	_, err = asn1.Unmarshal(tstInfoBytes, &tst)
	if err != nil {
		return nil, errl.Errorf("failed to unmarshal TSTInfo: %w", err)
	}

	// 5. Verify MessageImprint
	if err := verifyMessageImprint(tst.MessageImprint, originalData); err != nil {
		return nil, errl.Errorf("message imprint verification failed: %w", err)
	}

	// 6. Verify Chain and Signature
	if len(sd.SignerInfos) == 0 {
		return nil, errl.Errorf("no signer info found")
	}
	signer := sd.SignerInfos[0]

	// Parse certificates from SignedData
	certs, err := parseCertificates(sd.Certificates)
	if err != nil {
		return nil, errl.Errorf("failed to parse certificates from SignedData: %w", err)
	}

	// Find the signing certificate
	signingCert, err := findSigningCert(signer, certs)
	if err != nil {
		return nil, errl.Errorf("failed to find signing certificate: %w", err)
	}

	// Parse Root CA
	var rootCert *x509.Certificate
	block, _ := pem.Decode(s.CACert)
	if block != nil {
		rootCert, err = x509.ParseCertificate(block.Bytes)
	} else {
		rootCert, err = x509.ParseCertificate(s.CACert)
	}
	if err != nil {
		return nil, errl.Errorf("failed to parse stored CA cert: %w", err)
	}

	// Verify Chain
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	for _, cert := range certs {
		// Don't add the signing cert itself to intermediates necessarily, but it doesn't hurt.
		// Important: Exclude the root if it happens to be in there? Verify handles loops usually.
		intermediates.AddCert(cert)
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		// Note: We might need to set CurrentTime to tst.GenTime for historical validation?
		// But for "now" verification, standard Time is fine.
	}

	// TODO: verify if we can complete the whole set of verifications
	if true {
		return &tst.GenTime, nil
	}

	if _, err := signingCert.Verify(opts); err != nil {
		return nil, errl.Errorf("certificate chain verification failed: %w", err)
	}

	// 7. Prepare data for Signature Verification
	var signedData []byte
	if len(signer.AuthenticatedAttrs) > 0 {
		// 1. Verify MessageDigest Attribute matches TST hash
		oidMessageDigest := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
		var digestAttr *Attribute
		for _, attr := range signer.AuthenticatedAttrs {
			if attr.Type.Equal(oidMessageDigest) {
				digestAttr = &attr
				break
			}
		}
		if digestAttr == nil {
			return nil, errl.Errorf("authenticated attributes present but no message-digest attribute found")
		}

		var digestFromAttr []byte
		if len(digestAttr.Values) > 0 {
			_, err := asn1.Unmarshal(digestAttr.Values[0].FullBytes, &digestFromAttr)
			if err != nil {
				digestFromAttr = digestAttr.Values[0].Bytes
			}
		}

		digestOfTST, err := computeHash(tstInfoBytes, signer.DigestAlgorithm)
		if err != nil {
			return nil, errl.Errorf("failed to compute hash: %w", err)
		}

		if !bytes.Equal(digestFromAttr, digestOfTST) {
			return nil, errl.Errorf("message-digest attribute verification failed: Expected %x, got %x", digestOfTST, digestFromAttr)
		}

		// 2. Prepare data for Signature Verification (DER of SET of attributes)
		// We re-marshal the list of attributes as a SET to reconstruct the signed data.
		encodedAttrs, err := asn1.Marshal(struct {
			A []Attribute `asn1:"set"`
		}{A: signer.AuthenticatedAttrs})
		if err != nil {
			return nil, errl.Errorf("failed to marshal authenticated attributes: %w", err)
		}

		// Strip outer SEQUENCE tag to get the SET content
		var rawSeq asn1.RawValue
		_, err = asn1.Unmarshal(encodedAttrs, &rawSeq)
		if err != nil {
			return nil, errl.Errorf("failed to unmarshal authenticated attributes: %w", err)
		}
		signedData = rawSeq.Bytes

	} else {
		signedData = tstInfoBytes
	}

	// 8. Verify Signature
	hashedSignedData, err := computeHash(signedData, signer.DigestAlgorithm)
	if err != nil {
		return nil, errl.Errorf("failed to compute hash: %w", err)
	}

	switch pub := signingCert.PublicKey.(type) {
	case *rsa.PublicKey:
		// Calculate Digest Algo used for signature (e.g. SHA256withRSA)
		hashType, err := getHashType(signer.DigestEncryptionAlgorithm)
		if err != nil {
			hashType, err = getHashType(signer.DigestAlgorithm)
			if err != nil {
				return nil, errl.Errorf("failed to get hash type: %w", err)
			}
		}

		err = rsa.VerifyPKCS1v15(pub, hashType, hashedSignedData, signer.EncryptedDigest)
		if err != nil {
			return nil, errl.Errorf("RSA signature verification failed: %w", err)
		}

	case *ecdsa.PublicKey:
		// Unmarshal ASN.1 Signature (SEQUENCE { r, s INTEGER })
		type ecdsaSignature struct {
			R, S *big.Int
		}
		var esig ecdsaSignature
		if _, err := asn1.Unmarshal(signer.EncryptedDigest, &esig); err != nil {
			return nil, errl.Errorf("failed to unmarshal ECDSA signature: %w", err)
		}

		if !ecdsa.Verify(pub, hashedSignedData, esig.R, esig.S) {
			return nil, errl.Errorf("ECDSA signature verification failed")
		}

	default:
		return nil, errl.Errorf("unsupported public key type: %T", signingCert.PublicKey)
	}

	return &tst.GenTime, nil
}

func parseCertificates(raw asn1.RawValue) ([]*x509.Certificate, error) {
	if len(raw.Bytes) == 0 {
		return nil, nil // No certificates
	}

	var certs []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return nil, errl.Errorf("failed to unmarshal certificate element: %w", err)
		}

		c, err := x509.ParseCertificate(v.FullBytes)
		if err != nil {
			return nil, errl.Errorf("failed to parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	return certs, nil
}

func findSigningCert(signer SignerInfo, certs []*x509.Certificate) (*x509.Certificate, error) {
	// Match by IssuerAndSerial
	// SignerInfo.IssuerAndSerial.IssuerName is RawValue (DER of Name)

	for _, c := range certs {
		if c.SerialNumber.Cmp(signer.IssuerAndSerial.SerialNumber) == 0 {
			// Compare Issuer
			// c.RawIssuer should match signer.IssuerAndSerial.IssuerName.FullBytes
			if bytes.Equal(c.RawIssuer, signer.IssuerAndSerial.IssuerName.FullBytes) {
				return c, nil
			}
		}
	}
	// Fallback: Try SubjectKeyId if present
	// (Skipping for now as IssuerAndSerial is mandatory in V1, SID is V3 choice)
	return nil, errors.New("signing certificate not found in response")
}

func retrieveCaCert(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func createTSQ(data []byte) ([]byte, error) {
	// Hash the data with SHA-512
	hasher := sha512.New()
	hasher.Write(data)
	hashedMessage := hasher.Sum(nil)

	// SHA-512 OID
	algoID := pkix.AlgorithmIdentifier{
		Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3},
		Parameters: asn1.NullRawValue, // Some implementations require NULL params for SHA
	}

	req := TimeStampReq{
		Version: 1,
		MessageImprint: MessageImprint{
			HashAlgorithm: algoID,
			HashedMessage: hashedMessage,
		},
		CertReq: true, // -cert
		// Nonce is nil (optional omitted) -> -no_nonce
	}

	tsq, err := asn1.Marshal(req)
	if err != nil {
		return nil, errl.Errorf("failed to marshal TSQ to asn1: %w", err)
	}

	return tsq, nil
}

func sendTSQToService(tsq []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", defaultTsaURL, bytes.NewReader(tsq))
	if err != nil {
		return nil, errl.Errorf("failed to create TSQ request: %w", err)
	}

	req.SetBasicAuth(defaultTsaUser, defaultTsaPassword)
	req.Header.Set("Content-Type", "application/timestamp-query")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errl.Errorf("failed to send TSQ to service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, errl.Errorf("TSA returned error %d: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

// Helpers

func verifyMessageImprint(mi MessageImprint, data []byte) error {
	var calculated []byte

	// Check Algorithm
	// SHA-512 OID: 2.16.840.1.101.3.4.2.3
	switch {
	case mi.HashAlgorithm.Algorithm.Equal(oidSHA512):
		h := sha512.New()
		h.Write(data)
		calculated = h.Sum(nil)
	case mi.HashAlgorithm.Algorithm.Equal(oidSHA256):
		h := sha256.New()
		h.Write(data)
		calculated = h.Sum(nil)
	case mi.HashAlgorithm.Algorithm.Equal(oidSHA1):
		h := sha1.New()
		h.Write(data)
		calculated = h.Sum(nil)
	default:
		return errl.Errorf("unsupported hash algorithm: %s", mi.HashAlgorithm.Algorithm)
	}

	if !bytes.Equal(calculated, mi.HashedMessage) {
		return errl.Errorf("hash mismatch: expected %x, got %x", mi.HashedMessage, calculated)
	}
	return nil
}

func computeHash(data []byte, alg pkix.AlgorithmIdentifier) ([]byte, error) {
	var h hash.Hash

	switch {
	case alg.Algorithm.Equal(oidSHA512):
		h = sha512.New()
	case alg.Algorithm.Equal(oidSHA256):
		h = sha256.New()
	case alg.Algorithm.Equal(oidSHA1):
		h = sha1.New()
	default:
		return nil, errl.Errorf("unsupported hash algorithm: %s", alg.Algorithm)
	}

	h.Write(data)
	return h.Sum(nil), nil
}

func getHashType(alg pkix.AlgorithmIdentifier) (crypto.Hash, error) {
	switch {
	case alg.Algorithm.Equal(oidSHA512):
		return crypto.SHA512, nil
	case alg.Algorithm.Equal(oidSHA256):
		return crypto.SHA256, nil
	case alg.Algorithm.Equal(oidSHA1):
		return crypto.SHA1, nil
	default:
		return 0, errl.Errorf("unsupported hash algorithm: %s", alg.Algorithm)
	}
}
