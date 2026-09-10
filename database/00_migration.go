package database

import (
	"database/sql"
)

func init() {
	RegisterMigration("20251209T091700", migration_up_20251209T091700, nil)
}

func migration_up_20251209T091700(d *Database, x *sql.Tx) error {

	// This is an example migration, which does nothing.
	// For new migrations, copy this file and replace the name and the content.
	// The migration is already running in the context of a transaction, so there is no need to start a new one.

	return nil
}
