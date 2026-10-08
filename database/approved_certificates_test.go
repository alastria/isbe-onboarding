package database

import "testing"

func TestGetApprovedOrganizationIdentifier(t *testing.T) {
	d := newTestDatabase(t)

	const fingerprint = "0000000000000000000000000000000000000000000000000000000000000001"
	if _, err := d.db.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES (?, ?)`, fingerprint, "NTRNL-12345678"); err != nil {
		t.Fatalf("inserting approved certificate: %v", err)
	}

	t.Run("returns the identifier of an approved certificate", func(t *testing.T) {
		got, err := d.GetApprovedOrganizationIdentifier(fingerprint)
		if err != nil {
			t.Fatalf("GetApprovedOrganizationIdentifier: %v", err)
		}
		if got != "NTRNL-12345678" {
			t.Errorf("got %q, want %q", got, "NTRNL-12345678")
		}
	})

	t.Run("returns empty for a certificate that is not approved", func(t *testing.T) {
		got, err := d.GetApprovedOrganizationIdentifier("unknown")
		if err != nil {
			t.Fatalf("GetApprovedOrganizationIdentifier: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}
