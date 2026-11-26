package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alastria/isbe-onboarding/contract"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/tsaservice"
)

// CreateRegistration timestamps the evidence of a new registration and stores it.
//
// The registration is only written after the TSA token has passed full
// verification (tsaservice.TSAService.Timestamp never returns an unverified
// token). If timestamping fails, nothing is written: no file and no row.
func (d *Database) CreateRegistration(ctx context.Context, tsaService *tsaservice.TSAService, certificateData *models.CertificateData, email string, formData *models.ContractForm, contractDocument []byte) error {

	// Convert form data into JSON, which will be stored in the database
	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return errl.Errorf("failed to marshal form data: %w", err)
	}

	// Timestamp the evidence (contract document + representative certificate)
	// with the configured TSA. The token is returned only after verification.
	token, err := tsaService.Timestamp(ctx, TimestampedEvidence(contractDocument, certificateData.CertificateDER))
	if err != nil {
		return errl.Errorf("failed to timestamp registration evidence: %w", err)
	}
	timestamp := token.Response
	// The TSA time is the official time that we record, instead of our own time
	genTime := token.GenTime

	// Save the contract in a file in the /data/contracts directory
	// First we assign a unique name based in the date and the organization id
	contractFileName := fmt.Sprintf("%s_%s.pdf", time.Now().Format("20060102150405"), formData.OrganizationNif)
	contractFilePath := fmt.Sprintf("data/contracts/%s", contractFileName)
	if err := os.WriteFile(contractFilePath, contractDocument, 0644); err != nil {
		err = errl.Errorf("writing contract file: %w", err)
		slog.Error(err.Error())
		return err
	}

	// This is the data model for the registration table:
	//
	// organization_identifier TEXT UNIQUE NOT NULL,
	// organization TEXT,
	// email TEXT,
	// country TEXT,
	// contract_form BLOB,
	// eidas_cert TEXT,
	// timestamp BLOB,
	// contract_document TEXT,
	// created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	// updated_at DATETIME DEFAULT CURRENT_TIMESTAMP

	query := `
		INSERT INTO registrations (
			organization_identifier,
			organization,
			email,
			country,
			contract_form,
			contract_document,
			eidas_cert,
			timestamp,
			created_at,
			updated_at
		) VALUES (?, ?, ?, ?, jsonb(?), ?, ?, ?, ?, ?)
	`

	if certificateData.OrganizationID == "VATES-12345678J" {
		query += `
			ON CONFLICT(organization_identifier) DO UPDATE SET
				organization = excluded.organization,
				email = excluded.email,
				country = excluded.country,
				contract_form = excluded.contract_form,
				contract_document = excluded.contract_document,
				eidas_cert = excluded.eidas_cert,
				timestamp = excluded.timestamp,
				updated_at = excluded.updated_at
		`
	}

	// Create a new registration
	_, err = d.db.Exec(query,
		certificateData.OrganizationID,
		certificateData.Subject.Organization,
		email,
		certificateData.Subject.Country,
		formDataJSON,
		contractFilePath,
		certificateData.CertificateDER,
		timestamp,
		genTime,
		genTime,
	)

	if err != nil {
		// Delete the file
		if err := os.Remove(contractFilePath); err != nil {
			err = errl.Errorf("removing contract file: %w", err)
			slog.Error(err.Error())
		}

		return errl.Errorf("failed to create registration for %s: %w", email, err)
	}

	slog.Info("Created registration", "email", email, "org_id", certificateData.OrganizationID)
	return nil
}

// UpdateRegistration generates the contract document for the registration identified by organizationIdentifier
// (the organization_identifier column, which comes from the certificate) and stores it with its timestamp.
// It returns an error if no registration was updated.
func (d *Database) UpdateRegistration(ctx context.Context, tsaService *tsaservice.TSAService, organizationIdentifier string, certificateDER string, formData *models.ContractForm, certUrl string) error {
	// For a registration with a contract_document fiels empty, we generate the document and set the field

	// Generate the PDF contract in memory
	contractDocument, err := contract.Generate(formData, d.profile, certUrl, false)
	if err != nil {
		err = errl.Errorf("generating contract: %w", err)
		slog.Error(err.Error())
		return err
	}

	// Timestamp the evidence with the configured TSA (verified before returning)
	token, err := tsaService.Timestamp(ctx, TimestampedEvidence(contractDocument, certificateDER))
	if err != nil {
		return errl.Errorf("failed to timestamp registration evidence: %w", err)
	}
	timestamp := token.Response

	// Save the contract in a file in the /data/contracts directory
	// First we assign a unique name based in the date and the organization id
	contractFileName := fmt.Sprintf("%s_%s.pdf", time.Now().Format("20060102150405"), formData.OrganizationNif)
	contractFilePath := fmt.Sprintf("data/contracts/%s", contractFileName)
	if err := os.WriteFile(contractFilePath, contractDocument, 0644); err != nil {
		err = errl.Errorf("writing contract file: %w", err)
		slog.Error(err.Error())
		return err
	}

	// Update the registration
	if err := d.setContractDocument(organizationIdentifier, contractFilePath, timestamp); err != nil {
		// Delete the file, as it does not belong to any registration
		if err := os.Remove(contractFilePath); err != nil {
			err = errl.Errorf("removing contract file: %w", err)
			slog.Error(err.Error())
		}

		return err
	}

	return nil

}

// setContractDocument sets the contract document and timestamp of the registration identified by
// organizationIdentifier. It returns an error if no registration was updated.
func (d *Database) setContractDocument(organizationIdentifier string, contractFilePath string, timestamp []byte) error {
	updateQuery := `
		UPDATE registrations 
		SET contract_document = ?,
			timestamp = ?
		WHERE organization_identifier = ?
	`

	result, err := d.db.Exec(updateQuery, contractFilePath, timestamp, organizationIdentifier)
	if err != nil {
		return errl.Errorf("failed to update registration for %s: %w", organizationIdentifier, err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return errl.Errorf("failed to get rows affected updating registration for %s: %w", organizationIdentifier, err)
	}
	if rowsAffected == 0 {
		return errl.Errorf("failed to update registration for %s: registration not found", organizationIdentifier)
	}

	return nil
}

type Registration struct {
	OrganizationIdentifier string
	Email                  string
	ContractForm           *models.ContractForm
	EidasCert              string
	ContractDocumentName   string
}

// GetRegistration retrieves a registration by organization identifier.
// Returns the email, form data, and contract document name.
func (d *Database) GetRegistration(organizationIdentifier string) (string, *models.ContractForm, string, error) {
	query := `
		SELECT email, json(contract_form), eidas_cert, contract_document
		FROM registrations
		WHERE organization_identifier = ? 
	`

	var email, formData, eidasCert string
	var contractDocumentName []byte
	err := d.db.QueryRow(query, organizationIdentifier).Scan(
		&email,
		&formData,
		&eidasCert,
		&contractDocumentName,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil, "", nil
		}
		return "", nil, "", errl.Errorf("failed to get registration: %w", err)
	}

	var form models.ContractForm
	if err := json.Unmarshal([]byte(formData), &form); err != nil {
		return "", nil, "", errl.Errorf("failed to unmarshal form data: %w", err)
	}

	if len(contractDocumentName) == 0 {
		slog.Warn("Contract document name is empty", "email", email, "org_id", organizationIdentifier)
	}

	return email, &form, string(contractDocumentName), nil
}

func (d *Database) GetRegistrations() ([]Registration, error) {
	query := `
		SELECT organization_identifier, email, json(contract_form), eidas_cert, contract_document
		FROM registrations 
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, errl.Errorf("failed to get registrations: %w", err)
	}
	defer rows.Close()

	var registrations []Registration
	for rows.Next() {
		var email, formData, eidasCert string
		var contractDocumentName []byte
		var organizationIdentifier string
		if err := rows.Scan(
			&organizationIdentifier,
			&email,
			&formData,
			&eidasCert,
			&contractDocumentName,
		); err != nil {
			return nil, errl.Errorf("failed to scan registration: %w", err)
		}

		var contractForm models.ContractForm
		if err := json.Unmarshal([]byte(formData), &contractForm); err != nil {
			return nil, errl.Errorf("failed to unmarshal form data: %w", err)
		}

		if len(contractDocumentName) == 0 {
			slog.Warn("Contract document name is empty", "email", email, "org_id", contractForm.OrganizationNif)
		}
		registrations = append(registrations, Registration{
			OrganizationIdentifier: organizationIdentifier,
			Email:                  email,
			ContractForm:           &contractForm,
			EidasCert:              eidasCert,
			ContractDocumentName:   string(contractDocumentName),
		})
	}

	if err := rows.Err(); err != nil {
		return nil, errl.Errorf("failed to iterate registrations: %w", err)
	}

	return registrations, nil
}

func (d *Database) GetRegistrationContract(contractDocumentName string) ([]byte, error) {
	// Read the contract document from the file system
	contractDocument, err := os.ReadFile(contractDocumentName)
	if err != nil {
		return nil, errl.Errorf("failed to read contract document: %w", err)
	}

	return contractDocument, nil
}

// TimestampedEvidence returns the exact bytes that are timestamped for a
// registration: the contract PDF immediately followed by the representative's
// certificate as stored in the eidas_cert column (base64 DER text).
//
// This is the only evidence format used so far ("legacy v0"); every token in
// the registrations table was issued over it. It is not self-delimiting, but
// both parts are stored separately (the PDF file in contract_document and the
// certificate in eidas_cert), so it can be rebuilt for verification. Changing
// it would break the verification of historical tokens: a new format must be
// versioned and stored alongside the token (see tsaservice/README.md).
func TimestampedEvidence(contractDocument []byte, certificateDER string) []byte {
	out := make([]byte, 0, len(contractDocument)+len(certificateDER))
	out = append(out, contractDocument...)
	return append(out, certificateDER...)
}

// RegistrationEvidence is the stored evidence of a registration.
type RegistrationEvidence struct {
	OrganizationIdentifier string
	ContractDocumentPath   string
	CertificateDER         string
	Timestamp              []byte
}

// GetRegistrationEvidence reads the stored evidence of a registration.
func (d *Database) GetRegistrationEvidence(organizationIdentifier string) (*RegistrationEvidence, error) {
	ev := &RegistrationEvidence{OrganizationIdentifier: organizationIdentifier}
	var contractPath, cert sql.NullString
	err := d.db.QueryRow(`SELECT contract_document, eidas_cert, timestamp FROM registrations WHERE organization_identifier = ?`, organizationIdentifier).
		Scan(&contractPath, &cert, &ev.Timestamp)
	if err != nil {
		return nil, errl.Errorf("reading evidence of %s: %w", organizationIdentifier, err)
	}
	ev.ContractDocumentPath, ev.CertificateDER = contractPath.String, cert.String
	return ev, nil
}

// VerifyRegistrationEvidence rebuilds the timestamped data of a registration
// from its stored contract file and certificate and verifies the stored token.
// It does not contact the TSA and never modifies the registration.
func (d *Database) VerifyRegistrationEvidence(verifier *tsaservice.Verifier, organizationIdentifier string) (*tsaservice.VerifiedToken, error) {
	ev, err := d.GetRegistrationEvidence(organizationIdentifier)
	if err != nil {
		return nil, err
	}
	if len(ev.Timestamp) == 0 || ev.ContractDocumentPath == "" {
		return nil, errl.Errorf("registration %s has no timestamped evidence", organizationIdentifier)
	}
	contract, err := os.ReadFile(ev.ContractDocumentPath)
	if err != nil {
		return nil, errl.Errorf("reading contract document of %s: %w", organizationIdentifier, err)
	}
	vt, err := verifier.Verify(ev.Timestamp, TimestampedEvidence(contract, ev.CertificateDER))
	if err != nil {
		return nil, errl.Errorf("evidence of %s does not verify: %w", organizationIdentifier, err)
	}
	return vt, nil
}
