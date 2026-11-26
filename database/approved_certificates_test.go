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

func TestGetApprovedCertificatePersonalAttributes(t *testing.T) {
	d := newTestDatabase(t)

	if _, err := d.db.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier) VALUES ('a', 'NTRNL-1')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.db.Exec(`INSERT INTO approved_certificates (certificate_sha256, organization_identifier, serial_number, given_name, surname) VALUES ('b', 'NTRNL-2', ' 123 ', 'Ana', 'López')`); err != nil {
		t.Fatal(err)
	}

	got, err := d.GetApprovedCertificate("a")
	if err != nil || got == nil || *got != (ApprovedCertificate{OrganizationIdentifier: "NTRNL-1"}) {
		t.Errorf("row without personal attributes: got %+v, %v", got, err)
	}
	got, err = d.GetApprovedCertificate("b")
	if err != nil || got == nil || *got != (ApprovedCertificate{OrganizationIdentifier: "NTRNL-2", SerialNumber: " 123 ", GivenName: "Ana", Surname: "López"}) {
		t.Errorf("row with personal attributes, as entered: got %+v, %v", got, err)
	}
	if got, err := d.GetApprovedCertificate("unknown"); err != nil || got != nil {
		t.Errorf("not approved: got %+v, %v", got, err)
	}
}
