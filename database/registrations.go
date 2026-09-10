package database

import (
	"bytes"
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

// CreateRegistration creates a new registration in the database.
func (d *Database) CreateRegistration(tsaService *tsaservice.TSAService, certificateData *models.CertificateData, email string, formData *models.ContractForm, contractDocument []byte) error {

	// Convert form data into JSON, which will be stored in the database
	formDataJSON, err := json.Marshal(formData)
	if err != nil {
		return errl.Errorf("failed to marshal form data: %w", err)
	}

	// Create a timestamp using the configured TSA Trust Service Provider
	// The data to be timestamped is the contract document and the certificate
	buf := bytes.Buffer{}
	buf.Write(contractDocument)
	buf.WriteString(certificateData.CertificateDER)
	tstDataToTimestamp := buf.Bytes()

	timestamp, err := tsaService.Timestamp(tstDataToTimestamp)
	if err != nil {
		return errl.Errorf("failed to timestamp data: %w", err)
	}

	// Verify the timestamp and retrieve the actual time according to the TSA Service Provider
	// This is the official time that we will record, instead of our own time
	genTime, err := tsaService.Verify(timestamp, tstDataToTimestamp)
	if err != nil {
		return errl.Errorf("failed to verify timestamp: %w", err)
	}

	slog.Info("Timestamp verified", "genTime", genTime)

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

func (d *Database) UpdateRegistration(tsaService *tsaservice.TSAService, certificateDER string, formData *models.ContractForm, certUrl string) error {
	// For a registration with a contract_document fiels empty, we generate the document and set the field

	// Generate the PDF contract in memory
	contractDocument, err := contract.Generate(formData, d.profile, certUrl, false)
	if err != nil {
		err = errl.Errorf("generating contract: %w", err)
		slog.Error(err.Error())
		return err
	}

	// Create a timestamp using the configured TSA Trust Service Provider
	// The data to be timestamped is the contract document and the certificate
	buf := bytes.Buffer{}
	buf.Write(contractDocument)
	buf.WriteString(certificateDER)
	tstDataToTimestamp := buf.Bytes()

	timestamp, err := tsaService.Timestamp(tstDataToTimestamp)
	if err != nil {
		return errl.Errorf("failed to timestamp data: %w", err)
	}

	// Verify the timestamp and retrieve the actual time according to the TSA Service Provider
	// This is the official time that we will record, instead of our own time
	genTime, err := tsaService.Verify(timestamp, tstDataToTimestamp)
	if err != nil {
		return errl.Errorf("failed to verify timestamp: %w", err)
	}

	slog.Info("Timestamp verified", "genTime", genTime)

	// Save the contract in a file in the /data/contracts directory
	// First we assign a unique name based in the date and the organization id
	contractFileName := fmt.Sprintf("%s_%s.pdf", time.Now().Format("20060102150405"), formData.OrganizationNif)
	contractFilePath := fmt.Sprintf("data/contracts/%s", contractFileName)
	if err := os.WriteFile(contractFilePath, contractDocument, 0644); err != nil {
		err = errl.Errorf("writing contract file: %w", err)
		slog.Error(err.Error())
		return err
	}

	updateQuery := `
		UPDATE registrations 
		SET contract_document = ?,
			timestamp = ?
		WHERE organization_identifier = ?
	`

	// Update the registration
	_, err = d.db.Exec(updateQuery, contractFilePath, timestamp, formData.OrganizationNif)
	if err != nil {
		return errl.Errorf("failed to update registration for %s: %w", formData.OrganizationNif, err)
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
