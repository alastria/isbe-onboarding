package models

import (
	"crypto/x509"
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
