package models

import (
	"crypto/x509"
	"errors"
	"time"

	"github.com/alastria/isbe-onboarding/internal/util/x509util"
)

// ErrCertificateNotAuthorized marks a certificate that has neither the identifiers required by ISBE
// nor a manual approval. The user sees a generic message; the details stay in the server logs.
var ErrCertificateNotAuthorized = errors.New("certificate not authorized")

// CertificateData represents certificate information for exchange between services
type CertificateData struct {
	EIDASCertificate bool               `json:"eidas_certificate"`
	ManuallyApproved bool               `json:"manually_approved,omitempty"` // Accepted through approved_certificates, never implies EIDASCertificate
	OrganizationID   string             `json:"organization_identifier"`
	Subject          *x509util.ELSIName `json:"subject"` // Already processed from Certificate for convenience
	Issuer           *x509util.ELSIName `json:"issuer"`  // Already processed from Certificate for convenience
	ValidFrom        time.Time          `json:"valid_from"`
	ValidTo          time.Time          `json:"valid_to"`
	CertificateType  string             `json:"certificate_type"` // "organizational" or "personal"
	Certificate      *x509.Certificate  `json:"certificate"`
	CertificateDER   string             `json:"certificate_der"`
}
