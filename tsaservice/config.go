package tsaservice

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Defaults for optional settings.
const (
	DefaultHashAlgorithm    = "sha512"
	DefaultTimeout          = 30 * time.Second
	DefaultMaxClockSkew     = 5 * time.Minute
	DefaultMaxResponseBytes = 1 << 20 // 1 MiB; real responses are a few KiB

	maxTimeout = 2 * time.Minute
)

// Revocation checking modes.
const (
	RevocationNone = "none"
	RevocationCRL  = "crl"
)

// TSAConfig is the configuration of the TSA client and token verifier.
//
// Credentials are never given default values: they must come from the
// deployment (environment variables, mounted files or secrets/config.yaml).
type TSAConfig struct {
	// TSAURL is the RFC 3161 HTTP endpoint of the TSA. Required.
	TSAURL string
	// TSAUser and TSAPassword are the HTTP Basic credentials. Required.
	TSAUser     string
	TSAPassword string

	// Trust anchors (root certificates) used to validate the TSA certificate.
	// At most one source is used, in this order of preference:
	//   TrustAnchorsFile > TrustAnchorsPEM > CACertURL > embedded DigitelTS bundle.
	TrustAnchorsFile string
	TrustAnchorsPEM  string
	// CACertURL is the legacy source: the certificate is downloaded at start-up.
	// A SHA-256 pin is mandatory with it unless AllowInsecure is set.
	CACertURL string
	// TrustAnchorSHA256 pins the trust anchors by SHA-256 fingerprint (hex,
	// colons optional). When set, every loaded anchor must match one of the pins.
	TrustAnchorSHA256 []string
	// IntermediatesFile is an optional PEM bundle of intermediate CA certificates
	// for TSAs whose tokens do not carry the full chain.
	IntermediatesFile string

	// HashAlgorithm is the MessageImprint algorithm for new requests: sha256, sha384 or sha512.
	HashAlgorithm string
	// PolicyOID, when set, is sent as reqPolicy and must be the policy of every accepted token.
	PolicyOID string
	// DisableNonce stops sending (and therefore requiring) a nonce. Only for TSAs that do not support it.
	DisableNonce bool
	// Timeout bounds every HTTP exchange with the TSA (and CRL/CA downloads).
	Timeout time.Duration
	// MaxClockSkew is the tolerance applied to genTime of freshly requested tokens.
	MaxClockSkew time.Duration
	// RevocationCheck is "none" (default) or "crl".
	RevocationCheck string

	// AllowInsecure relaxes the rules that only make sense in production-like
	// environments: plain-HTTP endpoints and unpinned CA downloads. It must
	// only be set for the local development profile.
	AllowInsecure bool

	// Environment is a label (the profile name) included in logs.
	Environment string

	// EUDSSURL is kept for compatibility with the existing configuration.
	EUDSSURL string
}

// String never prints the password.
func (c TSAConfig) String() string {
	return fmt.Sprintf("TSAConfig{url=%s user_set=%t password_set=%t}", redactURL(c.TSAURL), c.TSAUser != "", c.TSAPassword != "")
}

// GoString prevents %#v from printing the password.
func (c TSAConfig) GoString() string { return c.String() }

// MarshalJSON emits a redacted view. main.go dumps the whole server
// configuration as JSON at start-up, which would otherwise print the
// credentials in the container logs.
func (c TSAConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]any{
		"url":                 redactURL(c.TSAURL),
		"user_set":            c.TSAUser != "",
		"password_set":        c.TSAPassword != "",
		"trust_source":        c.trustSource(),
		"trust_anchor_sha256": c.TrustAnchorSHA256,
		"hash_algorithm":      c.HashAlgorithm,
		"policy_oid":          c.PolicyOID,
		"nonce":               !c.DisableNonce,
		"timeout":             c.Timeout.String(),
		"revocation_check":    c.RevocationCheck,
		"environment":         c.Environment,
	})
}

// LogValue makes slog print a redacted view of the configuration.
func (c TSAConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("url", redactURL(c.TSAURL)),
		slog.Bool("user_set", c.TSAUser != ""),
		slog.Bool("password_set", c.TSAPassword != ""),
		slog.String("hash_algorithm", c.HashAlgorithm),
		slog.String("policy_oid", c.PolicyOID),
		slog.Bool("nonce", !c.DisableNonce),
		slog.Duration("timeout", c.Timeout),
		slog.String("revocation_check", c.RevocationCheck),
		slog.String("trust_source", c.trustSource()),
	)
}

func (c *TSAConfig) trustSource() string {
	switch {
	case c.TrustAnchorsFile != "":
		return "file"
	case c.TrustAnchorsPEM != "":
		return "pem"
	case c.CACertURL != "":
		return "url"
	default:
		return "embedded"
	}
}

func (c *TSAConfig) applyDefaults() {
	if c.HashAlgorithm == "" {
		c.HashAlgorithm = DefaultHashAlgorithm
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.MaxClockSkew == 0 {
		c.MaxClockSkew = DefaultMaxClockSkew
	}
	if c.RevocationCheck == "" {
		c.RevocationCheck = RevocationNone
	}
}

func configErrorf(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidConfig}, args...)...)
}

// validateVerification checks the settings needed to verify tokens.
func (c *TSAConfig) validateVerification() error {
	if _, ok := hashAlgorithmByName(c.HashAlgorithm); !ok {
		return configErrorf("TSA_HASH_ALGORITHM must be one of sha256, sha384, sha512 (got %q)", c.HashAlgorithm)
	}
	if c.PolicyOID != "" {
		if _, err := parseOID(c.PolicyOID); err != nil {
			return configErrorf("TSA_POLICY_OID: %v", err)
		}
	}
	if c.Timeout < 0 || c.Timeout > maxTimeout {
		return configErrorf("TSA_TIMEOUT must be between 1s and %s", maxTimeout)
	}
	if c.MaxClockSkew < 0 || c.MaxClockSkew > time.Hour {
		return configErrorf("max clock skew must be between 0 and 1h")
	}
	if c.RevocationCheck != RevocationNone && c.RevocationCheck != RevocationCRL {
		return configErrorf("TSA_REVOCATION_CHECK must be %q or %q", RevocationNone, RevocationCRL)
	}
	for _, p := range c.TrustAnchorSHA256 {
		if _, err := normalizeFingerprint(p); err != nil {
			return configErrorf("TSA_TRUST_ANCHOR_SHA256: %v", err)
		}
	}
	if c.CACertURL != "" {
		if err := validateEndpoint(c.CACertURL, true); err != nil {
			return configErrorf("TSA_CA_CERT_URL: %v", err)
		}
		if len(c.TrustAnchorSHA256) == 0 && !c.AllowInsecure {
			return configErrorf("TSA_CA_CERT_URL requires TSA_TRUST_ANCHOR_SHA256: a downloaded CA must be pinned")
		}
	}
	return nil
}

// validate checks the full configuration needed to request timestamps.
func (c *TSAConfig) validate() error {
	if strings.TrimSpace(c.TSAURL) == "" {
		return configErrorf("TSA_URL is required")
	}
	if err := validateEndpoint(c.TSAURL, c.AllowInsecure); err != nil {
		return configErrorf("TSA_URL: %v", err)
	}
	if c.TSAUser == "" || c.TSAPassword == "" {
		return configErrorf("TSA_USER and TSA_PASSWORD are required")
	}
	if strings.ContainsAny(c.TSAUser, ":\r\n") {
		return configErrorf("TSA_USER must not contain ':' or line breaks")
	}
	return c.validateVerification()
}

// validateEndpoint accepts absolute http(s) URLs without embedded credentials.
// Plain HTTP is only accepted when allowHTTP is true.
func validateEndpoint(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL")
	}
	if u.User != nil {
		return fmt.Errorf("credentials must not be embedded in the URL")
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("URL has no host")
	}
	if u.Fragment != "" {
		return fmt.Errorf("URL must not have a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return fmt.Errorf("HTTPS is required")
		}
	default:
		return fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return nil
}

// redactURL returns scheme://host/path without user info or query, for logs.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<invalid>"
	}
	return u.Scheme + "://" + u.Host + u.EscapedPath()
}

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid[i] = n
	}
	if oid[0] > 2 || (oid[0] < 2 && oid[1] > 39) {
		return nil, fmt.Errorf("invalid OID %q", s)
	}
	return oid, nil
}

func normalizeFingerprint(s string) (string, error) {
	f := strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(strings.TrimSpace(s)))
	if b, err := hex.DecodeString(f); err != nil || len(b) != 32 {
		return "", fmt.Errorf("%q is not a hex SHA-256 fingerprint", s)
	}
	return f, nil
}

// Environment variable names understood by ApplyEnv.
const (
	EnvURL               = "TSA_URL"
	EnvUser              = "TSA_USER"
	EnvUserFile          = "TSA_USER_FILE"
	EnvPassword          = "TSA_PASSWORD"
	EnvPasswordFile      = "TSA_PASSWORD_FILE"
	EnvCACertURL         = "TSA_CA_CERT_URL"
	EnvTrustAnchorsFile  = "TSA_TRUST_ANCHORS_FILE"
	EnvTrustAnchorsPEM   = "TSA_TRUST_ANCHORS_PEM"
	EnvTrustAnchorSHA256 = "TSA_TRUST_ANCHOR_SHA256"
	EnvIntermediatesFile = "TSA_INTERMEDIATES_FILE"
	EnvHashAlgorithm     = "TSA_HASH_ALGORITHM"
	EnvPolicyOID         = "TSA_POLICY_OID"
	EnvNonce             = "TSA_NONCE"
	EnvTimeout           = "TSA_TIMEOUT"
	EnvRevocationCheck   = "TSA_REVOCATION_CHECK"
)

// ApplyEnv overrides cfg with the TSA_* environment variables that are set.
// getenv is usually os.Getenv and readFile os.ReadFile; they are parameters so
// that tests do not depend on the process environment.
//
// TSA_USER_FILE / TSA_PASSWORD_FILE read the secret from a mounted file
// (Docker/Coolify secrets); setting both the variable and its _FILE variant is
// an error, to avoid ambiguity about which credential is in use.
func ApplyEnv(cfg *TSAConfig, getenv func(string) string, readFile func(string) ([]byte, error)) error {
	if getenv == nil {
		getenv = os.Getenv
	}
	if readFile == nil {
		readFile = os.ReadFile
	}

	set := func(dst *string, name string) {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			*dst = v
		}
	}
	secret := func(dst *string, name, fileName string) error {
		value, file := getenv(name), strings.TrimSpace(getenv(fileName))
		if value != "" && file != "" {
			return configErrorf("set only one of %s and %s", name, fileName)
		}
		if value != "" {
			*dst = value
		}
		if file != "" {
			b, err := readFile(file)
			if err != nil {
				return configErrorf("%s: cannot read the file", fileName)
			}
			*dst = strings.TrimRight(string(b), "\r\n")
		}
		return nil
	}

	set(&cfg.TSAURL, EnvURL)
	if err := secret(&cfg.TSAUser, EnvUser, EnvUserFile); err != nil {
		return err
	}
	if err := secret(&cfg.TSAPassword, EnvPassword, EnvPasswordFile); err != nil {
		return err
	}
	set(&cfg.CACertURL, EnvCACertURL)
	set(&cfg.TrustAnchorsFile, EnvTrustAnchorsFile)
	if v := getenv(EnvTrustAnchorsPEM); strings.TrimSpace(v) != "" {
		cfg.TrustAnchorsPEM = v
	}
	if v := strings.TrimSpace(getenv(EnvTrustAnchorSHA256)); v != "" {
		cfg.TrustAnchorSHA256 = nil
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				cfg.TrustAnchorSHA256 = append(cfg.TrustAnchorSHA256, p)
			}
		}
	}
	set(&cfg.IntermediatesFile, EnvIntermediatesFile)
	set(&cfg.HashAlgorithm, EnvHashAlgorithm)
	cfg.HashAlgorithm = strings.ToLower(cfg.HashAlgorithm)
	set(&cfg.PolicyOID, EnvPolicyOID)
	set(&cfg.RevocationCheck, EnvRevocationCheck)
	cfg.RevocationCheck = strings.ToLower(cfg.RevocationCheck)

	if v := strings.TrimSpace(getenv(EnvNonce)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return configErrorf("%s must be true or false", EnvNonce)
		}
		cfg.DisableNonce = !b
	}
	if v := strings.TrimSpace(getenv(EnvTimeout)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return configErrorf("%s must be a positive duration such as 30s", EnvTimeout)
		}
		cfg.Timeout = d
	}
	return nil
}
