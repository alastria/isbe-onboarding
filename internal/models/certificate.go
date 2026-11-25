package models

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/alastria/isbe-onboarding/internal/util/x509util"
)

// CertificateData represents certificate information for exchange between services
type CertificateData struct {
	EIDASCertificate bool               `json:"eidas_certificate"`
	OrganizationID   string             `json:"organization_identifier"`
	Subject          *x509util.ELSIName `json:"subject"` // Already processed from Certificate for convenience
	Issuer           *x509util.ELSIName `json:"issuer"`  // Already processed from Certificate for convenience
	ValidFrom        time.Time          `json:"valid_from"`
	ValidTo          time.Time          `json:"valid_to"`
	CertificateType  string             `json:"certificate_type"` // "organizational" or "personal"
	Certificate      *x509.Certificate  `json:"certificate"`
	CertificateDER   string             `json:"certificate_der"`
}

// Reasons why CertSec rejects a client certificate. They are wrapped in the error that CertSec
// hands to CertAuth, which shows the user a message for each one (the details go to the logs).
var (
	// ErrCertificateNotApproved: no organizationIdentifier nor Subject serialNumber, and not in the whitelist.
	ErrCertificateNotApproved = errors.New("the certificate has no organization identifier and has not been approved")
	// ErrCertificateNotValidNow: the certificate is expired or not yet valid.
	ErrCertificateNotValidNow = errors.New("the certificate is expired or not yet valid")
	// ErrCertificateUnreadable: no client certificate was received, or it could not be parsed.
	ErrCertificateUnreadable = errors.New("no valid client certificate was received")
)

// CertificateFingerprint returns the SHA-256 fingerprint of the DER encoding of the certificate,
// in lowercase hexadecimal without separators. It is the key of the approved_certificates table.
func CertificateFingerprint(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
}
