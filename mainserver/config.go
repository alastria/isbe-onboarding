package mainserver

import (
	"flag"
	"log/slog"
	"os"
	"strings"

	certauth "github.com/alastria/isbe-onboarding/certauthserver"
	"github.com/alastria/isbe-onboarding/internal/email"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/types"
	"github.com/goccy/go-yaml"
)

// Default Configuration Constants
const (
	defaultCaCertURL     = "http://pki.digitelts.es/DIGITELTSCAROOT01.pem"
	defaultTsaURL        = "https://timestamp-service.pre-api.digitelts.com/tsa"
	defaultEUDSSURL      = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate"
	defaultManagementURL = "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements"
)

// --- Secret Configuration Structures ---

type SecretConfig struct {
	AgeRecipient string     `yaml:"age_recipient"`
	TSACreds     TSACreds   `yaml:"tsa"`
	EmailCreds   EmailCreds `yaml:"email"`
}

type TSACreds struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type EmailCreds struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

// --- Predefined Configurations ---

// Config is the configuration for the server.
// It contains the configuration for CertAuth, CertSec and Onboard servers.
type Config struct {
	Profile        types.Profile
	OnboardURL     string
	OnboardPort    string
	PrivateArea    string
	TMFServerURL   string
	CertAuthConfig *certauth.ConfigCertAuth
	PredefinedRPs  []PredefinedRP
}

type PredefinedRP struct {
	RelyingParty *models.RelyingParty
	ClientSecret string
}

var defaultTsaConfig = &tsaservice.TSAConfig{
	TSAURL:    defaultTsaURL,
	CACertURL: defaultCaCertURL,
	EUDSSURL:  defaultEUDSSURL,
}

var defaultEmailConfig = &email.EmailConfig{
	IMAP:     "imap.serviciodecorreo.es",
	SMTP:     "smtp.serviciodecorreo.es",
	SMTPPort: "465",
}

// LoadConfig parses flags, environment variables, and config files to return the server configuration.
func LoadConfig() (*Config, string, error) {
	var adminPassword string
	var profilestr string

	// Parse flags
	flag.StringVar(&profilestr, "profile", string(types.PROFILE_LOCAL), "Profile to use: local, isbe-dev, isbe-pre or isbe-pro")
	flag.StringVar(&profilestr, "p", string(types.PROFILE_LOCAL), "Profile to use (shorthand): local, isbe-dev, isbe-pre or isbe-pro")
	flag.StringVar(&adminPassword, "admin-password", "", "Admin password for the server")

	flag.Parse()

	// Determine the configuration to use depending on the profile specified in the environment variable PROFILE
	// If no profile specified, we use the LOCAL development profile
	profilestr = GetStringEnvOrDefault("PROFILE", profilestr)
	profile := types.ProfileFromString(profilestr)

	// Local VPS development environment, which uses the domain mycredential.eu
	const localDomain = "mycredential.eu"

	var LOCAL_CFG = Config{
		OnboardURL:   "https://onboard." + localDomain,
		OnboardPort:  "8012",
		PrivateArea:  "/",
		TMFServerURL: "https://tmf.portal.redisbe.com/",
		CertAuthConfig: &certauth.ConfigCertAuth{
			Profile:       types.PROFILE_LOCAL,
			CertAuthURL:   "https://certauth." + localDomain,
			CertAuthPort:  "8010",
			CertSecURL:    "https://certsec." + localDomain,
			CertSecPort:   "8011",
			TSAConfig:     defaultTsaConfig,
			EmailConfig:   defaultEmailConfig,
			ManagementURL: defaultManagementURL,
			EUDSSURL:      defaultEUDSSURL,
		},
	}
	LOCAL_CFG.PredefinedRPs = []PredefinedRP{
		{
			RelyingParty: &models.RelyingParty{
				Name:        "Onboarding in local",
				Description: "The Onboarding Application in local",
				ClientID:    "isbeonboard",
				RedirectURL: LOCAL_CFG.OnboardURL + "/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Issuer for test",
				Description: "The ISBE Credential Issuer Application",
				ClientID:    "https://issuer.mycredential.eu",
				RedirectURL: "https://issuer.mycredential.eu/lear/auth/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
	}

	// ISBE Development environment
	var ISBE_DEV_CFG = Config{
		OnboardURL:   "https://onboard.dev.portal.redisbe.com",
		OnboardPort:  "8012",
		PrivateArea:  "https://poc-front.dev.cloud-w.envs.redisbe.com",
		TMFServerURL: "https://tmf.dev.portal.redisbe.com",
		CertAuthConfig: &certauth.ConfigCertAuth{
			Profile:       types.PROFILE_ISBE_DEV,
			CertAuthURL:   "https://certauth.dev.portal.redisbe.com",
			CertAuthPort:  "8010",
			CertSecURL:    "https://certsec.dev.portal.redisbe.com",
			CertSecPort:   "8011",
			TSAConfig:     defaultTsaConfig,
			EmailConfig:   defaultEmailConfig,
			ManagementURL: "https://poc-middleware-management.dev.cloud-w.envs.redisbe.com/api/managements",
			EUDSSURL:      defaultEUDSSURL,
		},
	}
	ISBE_DEV_CFG.PredefinedRPs = []PredefinedRP{
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Keycloak in DEV",
				Description: "The ISBE Keycloak in DEV application",
				ClientID:    "https://idp.dev.cloud-w.envs.redisbe.com",
				RedirectURL: "https://idp.dev.cloud-w.envs.redisbe.com/auth/realms/dev-isbe/broker/certificado-representante/endpoint",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Catalog DEV",
				Description: "The ISBE Catalog application in DEV",
				ClientID:    "https://catalog.isbeonboard.com",
				RedirectURL: "https://catalog.dev.cloud-w.envs.redisbe.com/",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding DEV",
				Description: "The ISBE Onboarding Application in DEV",
				ClientID:    "isbeonboard",
				RedirectURL: ISBE_DEV_CFG.OnboardURL + "/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding DEV in OVH",
				Description: "The ISBE Onboarding Application in DEV in OVH server",
				ClientID:    "https://onboard.dev.portal.redisbe.com",
				RedirectURL: "https://onboard.dev.portal.redisbe.com/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
	}

	// ISBE Pre-Production environment
	var ISBE_PRE_CFG = Config{
		OnboardURL:   "https://onboard.pre.portal.redisbe.com",
		OnboardPort:  "8012",
		PrivateArea:  "https://pre.portal.redisbe.com/",
		TMFServerURL: "https://tmf.pre.portal.redisbe.com",
		CertAuthConfig: &certauth.ConfigCertAuth{
			Profile:       types.PROFILE_ISBE_PRE,
			CertAuthURL:   "https://certauth.pre.portal.redisbe.com",
			CertAuthPort:  "8010",
			CertSecURL:    "https://certsec.pre.portal.redisbe.com",
			CertSecPort:   "8011",
			TSAConfig:     defaultTsaConfig,
			EmailConfig:   defaultEmailConfig,
			ManagementURL: "https://poc-middleware-management.pre.cloud-w.envs.redisbe.com/api/managements",
			EUDSSURL:      defaultEUDSSURL,
		},
	}
	ISBE_PRE_CFG.PredefinedRPs = []PredefinedRP{
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Keycloak in PRE",
				Description: "The ISBE Keycloak in PRE application",
				ClientID:    "https://idp.pre.portal.redisbe.com",
				RedirectURL: "https://idp.pre.portal.redisbe.com/auth/realms/pre-isbe/broker/certificado-representante/endpoint",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Catalog PRE",
				Description: "The ISBE Catalog application in PRE",
				ClientID:    "https://catalog.isbeonboard.com",
				RedirectURL: "https://pre.catalog.redisbe.com/",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding PRE",
				Description: "The ISBE Onboarding Application in PRE",
				ClientID:    "isbeonboard",
				RedirectURL: "https://onboard.pre.portal.redisbe.com/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding PRE in OVH",
				Description: "The ISBE Onboarding Application in PRE",
				ClientID:    "https://onboard.pre.portal.redisbe.com",
				RedirectURL: "https://onboard.pre.portal.redisbe.com/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
	}

	// ISBE PRODUCTION environment
	var ISBE_PRO_CFG = Config{
		OnboardURL:   "https://onboard.portal.redisbe.com",
		OnboardPort:  "8012",
		PrivateArea:  "https://portal.redisbe.com/",
		TMFServerURL: "https://tmf.portal.redisbe.com",
		CertAuthConfig: &certauth.ConfigCertAuth{
			Profile:       types.PROFILE_ISBE_PRO,
			CertAuthURL:   "https://certauth.portal.redisbe.com",
			CertAuthPort:  "8010",
			CertSecURL:    "https://certsec.portal.redisbe.com",
			CertSecPort:   "8011",
			TSAConfig:     defaultTsaConfig,
			EmailConfig:   defaultEmailConfig,
			ManagementURL: "https://poc-middleware-management.pro.cloud-w.envs.redisbe.com/api/managements",
			EUDSSURL:      defaultEUDSSURL,
		},
	}
	ISBE_PRO_CFG.PredefinedRPs = []PredefinedRP{
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Keycloak in PRO",
				Description: "The ISBE Keycloak in PRO application",
				ClientID:    "https://idp.portal.redisbe.com",
				RedirectURL: "https://idp.portal.redisbe.com/auth/realms/pro-isbe/broker/certificado-representante/endpoint",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Catalog PRO",
				Description: "The ISBE Catalog application in PRO",
				ClientID:    "https://catalog.isbeonboard.com",
				RedirectURL: "https://catalog.redisbe.com/",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding PRO",
				Description: "The ISBE Onboarding Application in PRO",
				ClientID:    "isbeonboard",
				RedirectURL: ISBE_PRO_CFG.OnboardURL + "/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
		{
			RelyingParty: &models.RelyingParty{
				Name:        "ISBE Onboarding PRO in OVH",
				Description: "The ISBE Onboarding Application in PRO",
				ClientID:    "https://onboard.portal.redisbe.com",
				RedirectURL: "https://onboard.portal.redisbe.com/callback",
				Scopes:      "openid eidas",
				TokenExpiry: 3600,
			},
			ClientSecret: "isbesecret",
		},
	}

	var cfg Config
	switch profile {
	case types.PROFILE_LOCAL:
		cfg = LOCAL_CFG
	case types.PROFILE_ISBE_DEV:
		cfg = ISBE_DEV_CFG
	case types.PROFILE_ISBE_PRE:
		cfg = ISBE_PRE_CFG
	case types.PROFILE_ISBE_PRO:
		cfg = ISBE_PRO_CFG
	default:
		return nil, "", errl.Errorf("unknown profile: %s", profile)
	}
	cfg.Profile = profile

	// Say in what environment we are running
	slog.Info("Running in " + string(cfg.Profile) + " mode")

	// Get admin password from command line or environment variable.
	// In any environment except LOCAL development, the admin password is required.
	// In LOCAL development, the admin password is optional, and if not provided, it will have a default value.
	adminPassword = GetStringEnvOrDefault("CERTAUTH_ADMIN_PASSWORD", adminPassword)
	if cfg.Profile == types.PROFILE_LOCAL && adminPassword == "" {
		adminPassword = "pepe"
	} else if adminPassword == "" {
		return nil, "", errl.Errorf("admin password required")
	}

	// Get the ISBETMF_ADMIN_TOKEN from environment variable. This is used to authenticate with the TMF server.
	// It is compulsory for any environment except LOCAL
	tmfAdminToken := GetStringEnvOrDefault("ISBETMF_ADMIN_TOKEN", "")
	if cfg.Profile == types.PROFILE_LOCAL && tmfAdminToken == "" {
		tmfAdminToken = "eyJhdWQiOiJodHRwczovL2NhdGFsb2cuaX"
	} else if tmfAdminToken == "" {
		return nil, "", errl.Errorf("ISBETMF_ADMIN_TOKEN required")
	}
	cfg.CertAuthConfig.TMFAdminToken = tmfAdminToken

	// Check for override of the CertAuth server URL and port
	cfg.CertAuthConfig.CertAuthURL = GetStringEnvOrDefault("CERTAUTH_URL", cfg.CertAuthConfig.CertAuthURL)
	cfg.CertAuthConfig.CertAuthPort = GetStringEnvOrDefault("CERTAUTH_PORT", cfg.CertAuthConfig.CertAuthPort)

	// Check for override of the CertSec server URL and port
	cfg.CertAuthConfig.CertSecURL = GetStringEnvOrDefault("CERTSEC_URL", cfg.CertAuthConfig.CertSecURL)
	cfg.CertAuthConfig.CertSecPort = GetStringEnvOrDefault("CERTSEC_PORT", cfg.CertAuthConfig.CertSecPort)

	// Check for override of the Onboard server URL and port
	cfg.OnboardURL = GetStringEnvOrDefault("ONBOARD_URL", cfg.OnboardURL)
	cfg.OnboardPort = GetStringEnvOrDefault("ONBOARD_PORT", cfg.OnboardPort)

	// Check for override of the TMF server URL
	cfg.TMFServerURL = GetStringEnvOrDefault("TMF_SERVER_URL", cfg.TMFServerURL)

	// Check for override of the TSA (Timestamping Authority) config
	cfg.CertAuthConfig.TSAConfig.TSAURL = GetStringEnvOrDefault("TSA_URL", cfg.CertAuthConfig.TSAConfig.TSAURL)
	cfg.CertAuthConfig.TSAConfig.CACertURL = GetStringEnvOrDefault("TSA_CA_CERT_URL", cfg.CertAuthConfig.TSAConfig.CACertURL)

	// Check for override of the DSS (Digital Signature Services) URL
	cfg.CertAuthConfig.EUDSSURL = GetStringEnvOrDefault("DSS_URL", cfg.CertAuthConfig.EUDSSURL)

	// Check for override of the email service config
	cfg.CertAuthConfig.EmailConfig.IMAP = GetStringEnvOrDefault("EMAIL_IMAP", cfg.CertAuthConfig.EmailConfig.IMAP)
	cfg.CertAuthConfig.EmailConfig.SMTP = GetStringEnvOrDefault("EMAIL_SMTP", cfg.CertAuthConfig.EmailConfig.SMTP)
	cfg.CertAuthConfig.EmailConfig.SMTPPort = GetStringEnvOrDefault("EMAIL_SMTP_PORT", cfg.CertAuthConfig.EmailConfig.SMTPPort)

	// Check for override of the management service URL
	cfg.CertAuthConfig.ManagementURL = GetStringEnvOrDefault("MANAGEMENT_URL", cfg.CertAuthConfig.ManagementURL)
	managementAPIKey := GetStringEnvOrDefault("MANAGEMENT_API_KEY", "")
	// It is compulsory for all environments except LOCAL, where we use a testing key
	if cfg.Profile == types.PROFILE_LOCAL && managementAPIKey == "" {
		managementAPIKey = "aa83b134-1a59-4ea3-b632-812f36d6b4c1"
	} else if managementAPIKey == "" {
		return nil, "", errl.Errorf("MANAGEMENT_API_KEY required")
	}
	cfg.CertAuthConfig.ManagementAPIKey = managementAPIKey

	// The secrets are either in a file which is not in the Git repo or in the environment variables.
	secretConfig := parseYamlConfig("secrets/config.yaml")

	// The TSA credentials are secret and compulsory
	tsaUser := GetStringEnvOrDefault("TSA_USER", secretConfig.TSACreds.User)
	tsaPassword := GetStringEnvOrDefault("TSA_PASSWORD", secretConfig.TSACreds.Password)
	if tsaUser == "" || tsaPassword == "" {
		return nil, "", errl.Errorf("TSA user and password required")
	}

	// The email credentials are secret and compulsory
	emailUser := GetStringEnvOrDefault("SMTP_USERNAME", secretConfig.EmailCreds.User)
	emailPassword := GetStringEnvOrDefault("SMTP_PASSWORD", secretConfig.EmailCreds.Password)
	if emailUser == "" || emailPassword == "" {
		return nil, "", errl.Errorf("email user and password required")
	}

	// Update the config with the secrets
	cfg.CertAuthConfig.TSAConfig.TSAUser = tsaUser
	cfg.CertAuthConfig.TSAConfig.TSAPassword = tsaPassword
	cfg.CertAuthConfig.EmailConfig.User = emailUser
	cfg.CertAuthConfig.EmailConfig.Email = emailUser
	cfg.CertAuthConfig.EmailConfig.Password = emailPassword

	return &cfg, adminPassword, nil
}

// GetStringEnvOrDefault gets an environment variable or returns a default value
func GetStringEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetBoolEnvOrDefault gets an environment variable or returns a default value.
func GetBoolEnvOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if strings.ToLower(value) == "true" {
			return true
		} else {
			return false
		}
	}
	return defaultValue
}

// parseYamlConfig reads a YAML configuration from the given filename.
func parseYamlConfig(filename string) SecretConfig {
	var out SecretConfig
	src, err := os.ReadFile(filename)
	if err != nil {
		return out
	}
	if err = yaml.Unmarshal(src, &out); err != nil {
		return out
	}
	return out
}
