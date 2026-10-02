package database

import (
	"path/filepath"
	"testing"

	"github.com/alastria/isbe-onboarding/types"
)

func newTestDatabase(t *testing.T) *Database {
	t.Helper()

	d, err := New(filepath.Join(t.TempDir(), "test.db"), types.PROFILE_ISBE_DEV)
	if err != nil {
		t.Fatalf("creating test database: %v", err)
	}
	t.Cleanup(func() { d.Close() })

	return d
}

func TestSetContractDocument(t *testing.T) {
	d := newTestDatabase(t)

	// A registration with a non-VAT organization identifier, as it comes from a Dutch certificate
	const orgID = "NTRNL-12345678"
	if _, err := d.db.Exec(`INSERT INTO registrations (organization_identifier, organization) VALUES (?, ?)`, orgID, "Test BV"); err != nil {
		t.Fatalf("inserting registration: %v", err)
	}

	t.Run("updates the registration by its organization identifier", func(t *testing.T) {
		if err := d.setContractDocument(orgID, "data/contracts/test.pdf", []byte("timestamp")); err != nil {
			t.Fatalf("setContractDocument: %v", err)
		}

		var contractDocument string
		if err := d.db.QueryRow(`SELECT contract_document FROM registrations WHERE organization_identifier = ?`, orgID).Scan(&contractDocument); err != nil {
			t.Fatalf("reading registration: %v", err)
		}
		if contractDocument != "data/contracts/test.pdf" {
			t.Errorf("contract_document = %q, want %q", contractDocument, "data/contracts/test.pdf")
		}
	})

	t.Run("fails when no registration matches", func(t *testing.T) {
		// This is the value the old code used in the WHERE clause for a non-VAT identifier
		if err := d.setContractDocument("VATNL-NTRNL-12345678", "data/contracts/test.pdf", []byte("timestamp")); err == nil {
			t.Fatal("expected an error when no registration is updated, got nil")
		}
	})
}
