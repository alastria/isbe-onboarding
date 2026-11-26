package database

import (
	"database/sql"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
)

// The approved_certificates table holds the certificates that ISBE has manually approved to act on
// behalf of an organization. An approved certificate is trusted instead of being validated as eIDAS:
// it is not checked by EU DSS (chain, qualification or revocation), so ISBE revokes it manually by
// deleting its row. It is never marked as an eIDAS certificate. Certificates without a row follow
// the eIDAS validation.
//
// certificate_sha256: the SHA-256 fingerprint of the DER certificate, in lowercase hex without separators
// organization_identifier: the organization it is approved for (e.g. 'NTRNL-12345678'); it must match
// the organizationIdentifier of the certificate, if the certificate has one
// comment: free text for the approval (who approved it, when, how it was verified, ...)
// serial_number, given_name, surname: optional personal attributes of the certificate holder, as
// verified by ISBE during the approval. They only complete the attributes the certificate does not
// have: the values of the certificate are always kept, and an approval with a different value for an
// attribute the certificate has is rejected. They are used as entered, without any format or
// normalization (serialNumber values in use have very different formats).
//
// Approvals are added manually, for example:
//
//	INSERT INTO approved_certificates (certificate_sha256, organization_identifier, comment,
//	    serial_number, given_name, surname)
//	VALUES ('<fingerprint>', 'NTRNL-12345678', 'KvK and passport checked by ...',
//	    '<verified identifier>', '<given name>', '<surname>');
//
// Rows added before CS-407 only assigned an organization identifier and the certificate was still
// validated by EU DSS: they must be reviewed and approved again before deploying CS-407 (see README).

// ApprovedCertificate is a row of approved_certificates. The personal attributes are empty when
// the approval does not set them.
type ApprovedCertificate struct {
	OrganizationIdentifier string
	SerialNumber           string
	GivenName              string
	Surname                string
}

// CompleteSubject fills the personal attributes that the certificate subject does not have with the
// values of the approval, as entered. It fails if the certificate and the approval have different
// values for the same attribute.
func (a *ApprovedCertificate) CompleteSubject(subject *x509util.ELSIName) error {
	for _, attr := range []struct {
		name     string
		subject  *string
		approved string
	}{
		{"serialNumber", &subject.SerialNumber, a.SerialNumber},
		{"givenName", &subject.GivenName, a.GivenName},
		{"surname", &subject.Surname, a.Surname},
	} {
		switch {
		case *attr.subject == "":
			*attr.subject = attr.approved
		case attr.approved != "" && attr.approved != *attr.subject:
			return errl.Errorf("%s of the certificate does not match the approved one", attr.name)
		}
	}
	return nil
}

// GetApprovedCertificate returns the approval of the certificate with the given SHA-256
// fingerprint, or nil if the certificate has not been approved.
func (d *Database) GetApprovedCertificate(certificateSHA256 string) (*ApprovedCertificate, error) {
	var approved ApprovedCertificate
	var serialNumber, givenName, surname sql.NullString
	err := d.db.QueryRow(
		`SELECT organization_identifier, serial_number, given_name, surname FROM approved_certificates WHERE certificate_sha256 = ?`,
		certificateSHA256,
	).Scan(&approved.OrganizationIdentifier, &serialNumber, &givenName, &surname)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errl.Errorf("failed to get approved certificate: %w", err)
	}

	approved.SerialNumber = serialNumber.String
	approved.GivenName = givenName.String
	approved.Surname = surname.String
	return &approved, nil
}

// GetApprovedOrganizationIdentifier returns the organization identifier assigned to the certificate
// with the given SHA-256 fingerprint, or an empty string if the certificate has not been approved.
func (d *Database) GetApprovedOrganizationIdentifier(certificateSHA256 string) (string, error) {
	approved, err := d.GetApprovedCertificate(certificateSHA256)
	if err != nil || approved == nil {
		return "", err
	}
	return approved.OrganizationIdentifier, nil
}
