// Package database provides an interface for interacting with the SQLite database used by the application.
package database

import (
	"database/sql"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/types"
	_ "github.com/mattn/go-sqlite3"
)

// Database manages SQLite operations
type Database struct {
	db      *sql.DB
	profile types.Profile
}

// This is the data model for the registration table:
//
// organization_identifier: the unique identifier of the organization
// organization: the name of the organization
// email: the contact email of the organization
// country: the two letter code of the country of the organization
// contract_form: the contract form filled by the organization, in JSON format
// eidas_cert: the eIDAS certificate of the organization, in DER format
// timestamp: the timestamp of the registration, obtained from a QTSA service provider
// contract_document: the contract document of the organization, as a BLOB
// created_at: the creation timestamp of the registration
// updated_at: the update timestamp of the registration

var tableCreateQueries = []string{
	`CREATE TABLE IF NOT EXISTS relying_parties (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		client_id TEXT UNIQUE NOT NULL,
		client_secret_hash TEXT NOT NULL,
		redirect_url TEXT NOT NULL,
		scopes TEXT DEFAULT 'openid eidas',
		token_expiry INTEGER DEFAULT 3600,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,
	`CREATE TABLE IF NOT EXISTS registrations (
	    organization_identifier TEXT UNIQUE NOT NULL,
		organization TEXT,
		email TEXT,
		country TEXT,
		contract_form BLOB,
		eidas_cert TEXT,
		signed_annex TEXT,
		timestamp BLOB,
		contract_document TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`,
}

// New creates a new database instance
func New(dbname string, profile types.Profile) (*Database, error) {
	d := &Database{}
	d.profile = profile

	if dbname == "" {
		dbname = "./data/onboard.db"
	}

	db, err := sql.Open("sqlite3", dbname)
	if err != nil {
		return nil, errl.Errorf("failed to open database: %w", err)
	}
	d.db = db

	// Create tables
	for _, query := range tableCreateQueries {
		if _, err := d.db.Exec(query); err != nil {
			return nil, errl.Errorf("failed to execute query: %w", err)
		}
	}

	// Run the migrations
	if err := d.RunMigrationsUp(); err != nil {
		return nil, errl.Errorf("failed to run migrations: %w", err)
	}

	// // Initialize with test data if empty
	// if err := d.initializePredefinedRPs(); err != nil {
	// 	return nil, errl.Errorf("failed to initialize test data: %w", err)
	// }

	return d, nil
}

// Close closes the database connection
func (d *Database) Close() error {
	if d.db != nil {
		return d.db.Close()
	}
	return nil
}
