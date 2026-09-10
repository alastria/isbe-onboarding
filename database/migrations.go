package database

import (
	"database/sql"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
)

const createMigrationsTableSQL = `CREATE TABLE IF NOT EXISTS migrations (
    version TEXT NOT NULL,
	"created_at" INTEGER
);`

type migrationfun func(d *Database, tx *sql.Tx) error

type oneMigration struct {
	version string
	up      migrationfun
	down    migrationfun
}

var migrations = map[string]oneMigration{}
var migrationMutex sync.Mutex

// RegisterMigration is called by the migration functions in their init() to register a migration.
// version must be a timestamp in the format YYYYMMDDTHHMMSS (YearMonthDayTHoursMinutesSeconds),
// like '20251102T203201'.
// The migrations are ordered by timestamp before being applied. This guarantees that migrations are
// applied in the correct order, independent from the order in which the init() functions have run.
// For the moment, only UP migration are implemented.
// If a registered migration function returns an error, it is slogged and the transaction is rolled back.
// Each migration and the corresponding version record are wrapped in a single database transaction.
func RegisterMigration(version string, up migrationfun, down migrationfun) {
	migrationMutex.Lock()
	defer migrationMutex.Unlock()
	migrations[version] = oneMigration{
		version: version,
		up:      up,
		down:    down,
	}
}

// RunMigrationsUp ensures the database migrations table exists and applies any pending UP migrations.
//
// Notes and expectations:
//   - Version comparison is lexicographical string comparison; migration version keys must be
//     chosen so that lexicographical order corresponds to the intended application order.
//   - Recommended version format is a timestamp in the format YYYYMMDDTHHMMSS (YearMonthDayTHoursMinutesSeconds),
//     like '20251102T203201'.
func (d *Database) RunMigrationsUp() error {

	slog.Info("Running migrations")
	defer slog.Info("Migrations done")

	// Create the migrations table if it doesn't exist
	if _, err := d.db.Exec(createMigrationsTableSQL); err != nil {
		return errl.Errorf("failed to create migrations table: %w", err)
	}

	// Read the version of the last applied migration
	var lastAppliedVersion string
	err := d.db.QueryRow("SELECT version FROM migrations ORDER BY version DESC LIMIT 1").Scan(&lastAppliedVersion)
	if err != nil && err != sql.ErrNoRows {
		return errl.Errorf("failed to read last applied migration version: %w", err)
	}
	slog.Debug("Last applied migration version", slog.String("version", lastAppliedVersion))

	// lastAppliedVersion is either "" (no migrations applied yet) or a valid version string
	// The empty string is lexicographically less than any valid version string, so this is OK

	if len(migrations) == 0 {
		slog.Info("There are no registered migrations")
		return nil
	}

	// Order registered migrations to apply by version lexicographically
	keys := make([]string, 0, len(migrations))
	for k := range migrations {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	// Loop the keys for applying the migration or not
	for _, currentMigrationVersion := range keys {
		if currentMigrationVersion <= lastAppliedVersion {
			slog.Debug("Skipping migration", slog.String("version", currentMigrationVersion))
			continue
		}
		migration := migrations[currentMigrationVersion]

		if err := d.applyMigration(migration); err != nil {
			return errl.Errorf("failed to apply migration %s: %w", migration.version, err)
		}

	}

	return nil

}

// applyMigration runs a single migration inside a database transaction.
// A deferred rollback is always registered first; if the function returns
// without having committed the transaction (including in the event of a
// panic), the rollback fires automatically.
func (d *Database) applyMigration(migration oneMigration) (err error) {
	tx, err := d.db.Begin()
	if err != nil {
		return errl.Errorf("failed to begin transaction for migration %s: %w", migration.version, err)
	}

	// committed is set to true only after a successful tx.Commit().
	// The deferred function uses it to decide whether a rollback is still needed.
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err = migration.up(d, tx); err != nil {
		return errl.Errorf("migration %s failed: %w", migration.version, err)
	}

	// Mark the migration as applied, in the same transaction
	_, err = tx.Exec("INSERT INTO migrations (version, created_at) VALUES (?, ?)", migration.version, time.Now().Unix())
	if err != nil {
		return errl.Error(err)
	}

	if err = tx.Commit(); err != nil {
		return errl.Errorf("failed to commit migration %s: %w", migration.version, err)
	}
	committed = true

	return nil
}
