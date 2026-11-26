package database

import (
	"database/sql"

	"github.com/alastria/isbe-onboarding/internal/errl"
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
//
// Approvals are added manually, for example:
//
//	INSERT INTO approved_certificates (certificate_sha256, organization_identifier, comment)
//	VALUES ('<fingerprint>', 'NTRNL-12345678', 'KvK checked by ...');
//
// Rows added before CS-407 only assigned an organization identifier and the certificate was still
// validated by EU DSS: they must be reviewed and approved again before deploying CS-407 (see README).

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
