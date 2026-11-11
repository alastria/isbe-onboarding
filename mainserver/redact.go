package mainserver

import (
	"encoding/json"
	"regexp"
)

// sensitiveKey matches configuration keys whose values must never be logged:
// passwords, secrets, API keys, private keys, credentials and tokens (but not
// settings such as TokenExpiry). Matching is on the JSON key, so new fields
// with such names are redacted automatically.
var sensitiveKey = regexp.MustCompile(`(?i)(password|passwd|secret|api_?key|private_?key|credential|token$)`)

const redacted = "[REDACTED]"

// RedactedConfigJSON returns the configuration as indented JSON with every
// sensitive value replaced by "[REDACTED]" (or left empty when unset, so that
// a missing secret is still visible when diagnosing a deployment). Boolean
// values under sensitive keys, such as the TSA "password_set" flag, are kept.
func RedactedConfigJSON(cfg *Config) ([]byte, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var tree any
	if err := json.Unmarshal(raw, &tree); err != nil {
		return nil, err
	}
	return json.MarshalIndent(redactTree(tree), "", "  ")
}

func redactTree(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitiveKey.MatchString(k) {
				if s, ok := val.(string); ok && s == "" {
					continue
				}
				// A boolean cannot carry a secret: presence flags such as
				// "password_set" stay visible. Any other type (string,
				// number, object, array) under a sensitive key is redacted.
				if _, ok := val.(bool); ok {
					continue
				}
				if val != nil {
					t[k] = redacted
				}
				continue
			}
			t[k] = redactTree(val)
		}
		return t
	case []any:
		for i := range t {
			t[i] = redactTree(t[i])
		}
		return t
	default:
		return v
	}
}
