package database

import (
	"database/sql"

	"github.com/alastria/isbe-onboarding/internal/errl"
)

func init() {
	RegisterMigration("20261126T150000", migration_up_20261126T150000, nil)
}

// migration_up_20261126T150000 adds the optional personal attributes of an approved certificate
// (see approved_certificates.go). Existing rows keep NULL and behave as before.
func migration_up_20261126T150000(d *Database, tx *sql.Tx) error {
	for _, column := range []string{"serial_number", "given_name", "surname"} {
		if _, err := tx.Exec(`ALTER TABLE approved_certificates ADD COLUMN ` + column + ` TEXT`); err != nil {
			return errl.Errorf("adding column %s to approved_certificates: %w", column, err)
		}
	}
	return nil
}
