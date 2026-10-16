package database

import (
	"database/sql"

	"github.com/alastria/isbe-onboarding/internal/errl"
)

// The approved_certificates table holds the certificates without organizationIdentifier (OID 2.5.4.97)
// that have been manually approved to act on behalf of an organization.
//
// certificate_sha256: the SHA-256 fingerprint of the DER certificate, in lowercase hex without separators
// organization_identifier: the identifier assigned to the organization (e.g. 'NTRNL-12345678')
// comment: free text for the approval (who approved it, how it was verified, ...)
//
// Approvals are added manually, for example:
//
//	INSERT INTO approved_certificates (certificate_sha256, organization_identifier, comment)
//	VALUES ('<fingerprint>', 'NTRNL-12345678', 'KvK checked by ...');

// GetApprovedOrganizationIdentifier returns the organization identifier assigned to the certificate
// with the given SHA-256 fingerprint, or an empty string if the certificate has not been approved.
func (d *Database) GetApprovedOrganizationIdentifier(certificateSHA256 string) (string, error) {
	var organizationIdentifier string
	err := d.db.QueryRow(
		`SELECT organization_identifier FROM approved_certificates WHERE certificate_sha256 = ?`,
		certificateSHA256,
	).Scan(&organizationIdentifier)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", errl.Errorf("failed to get approved certificate: %w", err)
	}

	return organizationIdentifier, nil
}
