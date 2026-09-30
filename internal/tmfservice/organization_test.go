package tmfservice

import "testing"

func TestBuildTMFOrganizationFromRequest_OrganizationIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		vatId   string
		country string
		want    string
	}{
		{"non-VAT identifier (NL KvK) is kept as-is", "NTRNL-12345678", "NL", "NTRNL-12345678"},
		{"VAT identifier is unchanged", "VATES-B12345678", "ES", "VATES-B12345678"},
		{"bare NIF gets VAT prefix", "B12345678", "ES", "VATES-B12345678"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := RegistrationRequest{
				CompanyName: "Test Company",
				Country:     tt.country,
				VatId:       tt.vatId,
				Email:       "test@example.com",
			}

			org := BuildTMFOrganizationFromRequest(request, "fake-der-certificate")

			if len(org.OrganizationIdentification) != 1 {
				t.Fatalf("expected 1 organizationIdentification, got %d", len(org.OrganizationIdentification))
			}
			if got, want := org.OrganizationIdentification[0].IdentificationID, "did:elsi:"+tt.want; got != want {
				t.Errorf("identificationId = %q, want %q", got, want)
			}

			if len(org.ExternalReference) != 1 {
				t.Fatalf("expected 1 externalReference, got %d", len(org.ExternalReference))
			}
			if got := org.ExternalReference[0].Name; got != tt.want {
				t.Errorf("externalReference.name = %q, want %q", got, tt.want)
			}
		})
	}
}
