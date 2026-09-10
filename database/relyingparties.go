package database

import (
	"database/sql"
	"log/slog"
	"net/url"
	"strings"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// GetRelyingParty retrieves a relying party by client ID
// If the relying party is not found, it returns nil, nil
func (d *Database) GetRelyingParty(clientID string) (*models.RelyingParty, error) {
	query := `
		SELECT id, name, description, client_id, client_secret_hash, 
		       redirect_url, scopes, token_expiry, 
		       created_at, updated_at
		FROM relying_parties 
		WHERE client_id = ?
	`

	var rp models.RelyingParty
	err := d.db.QueryRow(query, clientID).Scan(
		&rp.ID, &rp.Name, &rp.Description, &rp.ClientID, &rp.ClientSecretHash,
		&rp.RedirectURL, &rp.Scopes, &rp.TokenExpiry,
		&rp.CreatedAt, &rp.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, errl.Errorf("failed to get relying party: %w", err)
	}

	return &rp, nil
}

// ListRelyingParties retrieves all relying parties
// If no relying parties are found, it returns an empty slice, nil
func (d *Database) ListRelyingParties() ([]models.RelyingParty, error) {
	query := `
		SELECT id, name, description, client_id, redirect_url, 
		       scopes, token_expiry, created_at, updated_at
		FROM relying_parties 
		ORDER BY name
	`

	rows, err := d.db.Query(query)
	if err != nil {
		return nil, errl.Errorf("failed to list relying parties: %w", err)
	}
	defer rows.Close()

	var rps []models.RelyingParty
	for rows.Next() {
		var rp models.RelyingParty
		err := rows.Scan(
			&rp.ID, &rp.Name, &rp.Description, &rp.ClientID,
			&rp.RedirectURL, &rp.Scopes, &rp.TokenExpiry,
			&rp.CreatedAt, &rp.UpdatedAt,
		)
		if err != nil {
			return nil, errl.Errorf("failed to scan relying party: %w", err)
		}
		rps = append(rps, rp)
	}

	return rps, nil
}

// CreateRelyingParty creates a new relying party
func (d *Database) CreateRelyingParty(rp *models.RelyingParty, clientSecret string) error {

	// client secret maybe empty if PKCE is used or bigger than 8 characters
	if len(clientSecret) > 0 && len(clientSecret) < 8 {
		return errl.Errorf("client secret must be at least 8 characters long")
	}

	// Hash the client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return errl.Errorf("failed to hash client secret: %w", err)
	}

	// Check that name, client_id, redirect_url and scopes are not empty
	if rp.Name == "" || rp.ClientID == "" || rp.RedirectURL == "" || rp.Scopes == "" {
		return errl.Errorf("name, client_id, redirect_url, and scopes must not be empty")
	}

	// Check that redirect_url is a valid URL
	if _, err := url.ParseRequestURI(rp.RedirectURL); err != nil {
		return errl.Errorf("redirect_url must be a valid URL: %w", err)
	}

	// Parse the scopes as a slice of strings separated by one or more space characters
	scopes := strings.Fields(rp.Scopes)
	if len(scopes) == 0 {
		return errl.Errorf("scopes must not be empty")
	}

	// Set default token_expiry if not provided
	if rp.TokenExpiry <= 0 {
		rp.TokenExpiry = 3600
	}

	query := `
		INSERT INTO relying_parties (
			name, description, client_id, client_secret_hash, 
			redirect_url, scopes, token_expiry
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err = d.db.Exec(query,
		rp.Name, rp.Description, rp.ClientID, hashedSecret,
		rp.RedirectURL, strings.Join(scopes, " "), rp.TokenExpiry,
	)

	if err != nil {
		return errl.Errorf("failed to create relying party: %w", err)
	}

	slog.Info("Created relying party", "client_id", rp.ClientID, "name", rp.Name)
	return nil
}

// UpsertRelyingParty inserts or updates a relying party
func (d *Database) UpsertRelyingParty(rp *models.RelyingParty, clientSecret string) error {

	// client secret maybe empty if PKCE is used or bigger than 8 characters
	if len(clientSecret) > 0 && len(clientSecret) < 8 {
		return errl.Errorf("client secret must be at least 8 characters long")
	}

	// Hash the client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return errl.Errorf("failed to hash client secret: %w", err)
	}

	// Check that name, client_id, redirect_url and scopes are not empty
	if rp.Name == "" || rp.ClientID == "" || rp.RedirectURL == "" || rp.Scopes == "" {
		return errl.Errorf("name, client_id, redirect_url, and scopes must not be empty")
	}

	// Check that redirect_url is a valid URL
	if _, err := url.ParseRequestURI(rp.RedirectURL); err != nil {
		return errl.Errorf("redirect_url must be a valid URL: %w", err)
	}

	// Parse the scopes as a slice of strings separated by one or more space characters
	scopes := strings.Fields(rp.Scopes)
	if len(scopes) == 0 {
		return errl.Errorf("scopes must not be empty")
	}

	// Set default token_expiry if not provided
	if rp.TokenExpiry <= 0 {
		rp.TokenExpiry = 3600
	}

	query := `
		INSERT INTO relying_parties (
			name, description, client_id, client_secret_hash, 
			redirect_url, scopes, token_expiry
		) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (client_id) DO UPDATE
		SET name = ?, description = ?, client_secret_hash = ?, 
		    redirect_url = ?, scopes = ?, token_expiry = ?
	`

	_, err = d.db.Exec(query,
		rp.Name, rp.Description, rp.ClientID, hashedSecret,
		rp.RedirectURL, rp.Scopes, rp.TokenExpiry,
		rp.Name, rp.Description, hashedSecret,
		rp.RedirectURL, rp.Scopes, rp.TokenExpiry,
	)

	if err != nil {
		return errl.Errorf("failed to create or update relying party: %w", err)
	}

	slog.Info("Created or updated relying party", "client_id", rp.ClientID, "name", rp.Name)
	return nil
}

// UpdateRelyingParty updates an existing relying party
func (d *Database) UpdateRelyingParty(rp *models.RelyingParty, clientSecret string) error {
	var query string
	var args []any

	// Check that name, client_id, redirect_url and scopes are not empty
	if rp.Name == "" || rp.ClientID == "" || rp.RedirectURL == "" || rp.Scopes == "" {
		return errl.Errorf("name, client_id, redirect_url, and scopes must not be empty")
	}

	// Check that redirect_url is a valid URL
	if _, err := url.ParseRequestURI(rp.RedirectURL); err != nil {
		return errl.Errorf("redirect_url must be a valid URL: %w", err)
	}

	// Parse the scopes as a slice of strings separated by one or more space characters
	scopes := strings.Fields(rp.Scopes)
	if len(scopes) == 0 {
		return errl.Errorf("scopes must not be empty")
	}

	// Set default token_expiry if not provided
	if rp.TokenExpiry <= 0 {
		rp.TokenExpiry = 3600
	}

	if clientSecret != "" {

		// client secret maybe empty if PKCE is used or bigger than 8 characters
		if len(clientSecret) < 8 {
			return errl.Errorf("client secret must be at least 8 characters long")
		}

		// Hash the new client secret
		hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
		if err != nil {
			return errl.Errorf("failed to hash client secret: %w", err)
		}

		query = `
			UPDATE relying_parties 
			SET name = ?, description = ?, redirect_url = ?, 
			    scopes = ?, token_expiry = ?, client_secret_hash = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`
		args = []any{
			rp.Name, rp.Description, rp.RedirectURL,
			rp.Scopes, rp.TokenExpiry, hashedSecret, rp.ID,
		}
	} else {
		query = `
			UPDATE relying_parties 
			SET name = ?, description = ?, redirect_url = ?, 
			    scopes = ?, token_expiry = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`
		args = []any{
			rp.Name, rp.Description, rp.RedirectURL,
			rp.Scopes, rp.TokenExpiry, rp.ID,
		}
	}

	_, err := d.db.Exec(query, args...)
	if err != nil {
		return errl.Errorf("failed to update relying party: %w", err)
	}

	slog.Info("Updated relying party", "client_id", rp.ClientID, "name", rp.Name)
	return nil
}

// DeleteRelyingParty deletes a relying party
// If the relying party is not found, it returns an error
func (d *Database) DeleteRelyingParty(id int) error {
	query := `DELETE FROM relying_parties WHERE id = ?`

	_, err := d.db.Exec(query, id)
	if err != nil {
		return errl.Errorf("failed to delete relying party: %w", err)
	}

	slog.Info("Deleted relying party", "id", id)
	return nil
}

// ValidateClientSecret validates a client secret against the stored hash
func (d *Database) ValidateClientSecret(clientID, clientSecret string) (bool, error) {
	rp, err := d.GetRelyingParty(clientID)
	if err != nil {
		return false, err
	}
	if rp == nil {
		return false, nil
	}

	err = bcrypt.CompareHashAndPassword([]byte(rp.ClientSecretHash), []byte(clientSecret))
	return err == nil, nil
}
