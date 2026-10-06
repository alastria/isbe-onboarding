// Package orgid normalises organisation identifiers, so that the same organisation gets
// the same identifier in the registrations table, the tokens and the TMForum server.
package orgid

import (
	"regexp"
	"strings"
)

// etsiSemanticPrefix matches the semantic identifier prefixes defined in ETSI EN 319 412-1 §5.1.4
// for the organizationIdentifier attribute (OID 2.5.4.97):
//   - 3 character identity type reference + 2 character ISO 3166-1 country code + "-"
//     (e.g. "VATES-", "NTRNL-", "PSDES-", "LEIXG-")
//   - 2 character ISO 3166-1 country code + ":" + national scheme reference + "-"
//
// The match is case-insensitive, so values typed by hand in lower case are also recognised.
var etsiSemanticPrefix = regexp.MustCompile(`(?i)^(?:([A-Z]{3}[A-Z]{2})-|([A-Z]{2}):[A-Z0-9]+-)`)

// NormalizeOrganizationIdentifier returns the canonical identifier of an organisation.
//
// The canonical identifier is the organizationIdentifier of the eIDAS certificate, as defined in
// ETSI EN 319 412-1 §5.1.4. If the value already carries an ETSI semantic prefix
// (VATxx-, NTRxx-, PSDxx-, LEIxx-, xx:scheme-, ...) it is kept as-is. Otherwise it is considered
// a bare national tax identifier (e.g. a Spanish NIF typed by hand) and "VAT<COUNTRY>-" is prepended.
//
// Surrounding spaces are removed. When a semantic prefix is written in lower case, the prefix
// (the identity type and the country code) is converted to upper case, as the standard requires,
// and the rest of the value is left untouched. For values coming from a conformant certificate,
// which are already in upper case, the result is identical to the input.
//
// The function is idempotent, and for "VATxx-" identifiers it returns the same value as before.
// An empty value is returned as empty.
func NormalizeOrganizationIdentifier(id, country string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}

	m := etsiSemanticPrefix.FindStringSubmatchIndex(id)
	if m == nil {
		return "VAT" + strings.ToUpper(strings.TrimSpace(country)) + "-" + id
	}

	// Upper-case the identity type + country code ("NTRNL") or the country code ("NL" in "nl:scheme-")
	for _, group := range []int{1, 2} {
		start, end := m[2*group], m[2*group+1]
		if start >= 0 {
			return id[:start] + strings.ToUpper(id[start:end]) + id[end:]
		}
	}

	return id
}
