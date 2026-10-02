package orgid

import "testing"

func TestNormalizeOrganizationIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		country string
		want    string
	}{
		{"VAT with prefix is unchanged", "VATES-B12345678", "ES", "VATES-B12345678"},
		{"bare NIF gets VAT prefix", "B12345678", "ES", "VATES-B12345678"},
		{"bare NIF with lower case country", "B12345678", "es", "VATES-B12345678"},
		{"NTR (KvK) is unchanged", "NTRNL-12345678", "NL", "NTRNL-12345678"},
		{"NTR with extra hyphens is unchanged", "NTRNL-KVK-12345678", "NL", "NTRNL-KVK-12345678"},
		{"PSD is unchanged", "PSDES-BDE-3DFD21", "ES", "PSDES-BDE-3DFD21"},
		{"LEI is unchanged, country not needed", "LEIXG-529900T8BM49AURSDO55", "", "LEIXG-529900T8BM49AURSDO55"},
		{"LEI is unchanged even with another country", "LEIXG-529900T8BM49AURSDO55", "ES", "LEIXG-529900T8BM49AURSDO55"},
		{"national scheme prefix is unchanged", "NL:KVK-12345678", "NL", "NL:KVK-12345678"},
		{"surrounding spaces are removed", "  VATES-B1  ", "ES", "VATES-B1"},
		{"surrounding spaces are removed from bare NIF", "  B1  ", "ES", "VATES-B1"},
		{"lower case prefix is upper-cased, rest untouched", "vates-b12345678", "ES", "VATES-b12345678"},
		{"lower case national scheme country is upper-cased", "nl:kvk-12345678", "NL", "NL:kvk-12345678"},
		{"wildcard test certificate is unchanged", "VATES-12345678J", "ES", "VATES-12345678J"},
		{"empty stays empty", "", "ES", ""},
		{"only spaces stays empty", "   ", "ES", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeOrganizationIdentifier(tt.id, tt.country)
			if got != tt.want {
				t.Errorf("NormalizeOrganizationIdentifier(%q, %q) = %q, want %q", tt.id, tt.country, got, tt.want)
			}

			// The normalisation must be idempotent
			if again := NormalizeOrganizationIdentifier(got, tt.country); again != got {
				t.Errorf("not idempotent: NormalizeOrganizationIdentifier(%q, %q) = %q, want %q", got, tt.country, again, got)
			}
		})
	}
}
