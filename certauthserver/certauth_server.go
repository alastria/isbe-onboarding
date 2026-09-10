// Package certauth implements the main server logic for the CertAuth OpenID Provider and OID4VP Relying Party.
package certauth

import (
	"context"
	"embed"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/email"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/jwtservice"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/tmfservice"
	"github.com/alastria/isbe-onboarding/tsaservice"
	"github.com/alastria/isbe-onboarding/types"
	"github.com/ansrivas/fiberprometheus/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Configuration for the CertAuth server
type ConfigCertAuth struct {

	// The profile that we are running with
	Profile types.Profile

	// The URL and internal port for the CertAuth server, the one acting as an IdP
	CertAuthURL  string
	CertAuthPort string

	// The URL and internal port for the CertSec server, the one receiving directly the certificate from the user browser
	CertSecURL  string
	CertSecPort string

	// The Qualified Timestamping Authority configuration, to use for timestamping
	TSAConfig *tsaservice.TSAConfig

	// The email configuration, to use for sending emails to the user
	EmailConfig *email.EmailConfig

	// The URL for the management system where onboardings are reqistered
	ManagementURL    string
	ManagementAPIKey string

	// The URL for the Digital Signature Services. We use it now for verification of certificates only.
	EUDSSURL string

	// The URL for the TM Forum server
	TMFServerURL string

	// The admin token used to authenticate the superadmin to the TMF server
	TMFAdminToken string
}

// CertAuthServer represents the CertAuth server
// It acts as an OpenID Provider with the Relying Parties, and as an OID4VP Relying Party for the Wallet.
// In this way it insulates the OID4VP protocol from the Relying Parties, which just use standard OIDC to
// authenticate users and get an ID Token and an Access Token.
type CertAuthServer struct {
	// The HTTP server (using Fiber)
	httpServer *fiber.App

	// The environment where we are running
	profile types.Profile

	// The URL and internal port for the CertAuth server, the one acting as an IdP
	certAuthURL  string
	certAuthPort string

	// The URL for the CertSec server, we will use it to obtain the certificate from the user browser
	certSecURL string

	// The URL for the management system where onboardings are reqistered
	managementURL    string
	managementAPIKey string

	// The URL for the Digital Signature Services. We use it now for verification of certificates only.
	euDSSURL string

	// The database service
	db *database.Database

	// The JWT service to generate ID and access tokens
	jwtService *jwtservice.JWTService

	// The HTML renderer
	htmlRender *html.RendererFiber

	// The single session cache
	ssoCache *cache.GenericCache[string, *models.SSOSession]

	// The authentication process cache
	authprocCache *cache.GenericCache[string, *models.AuthProcess]

	// The TSA service
	tsaService *tsaservice.TSAService

	// The email service
	emailService *email.Service

	// The TMF service
	tmfService *tmfservice.TMFService

	// The admin token used to authenticate the superadmin in the TMF server
	tmfAdminToken string
}

const templateDebug = true
const templateDirectory = "certauthserver/views"
const templateExtension = ".hbs"
const templateStaticResources = "certauthserver/views/assets"

//go:embed views/*
var viewsfs embed.FS

// NewCertAuth creates a new CertAuth server
func NewCertAuth(
	db *database.Database,
	authprocCache *cache.GenericCache[string, *models.AuthProcess],
	ssoCache *cache.GenericCache[string, *models.SSOSession],
	adminPassword string,
	cfg *ConfigCertAuth) (*CertAuthServer, error) {

	// Ensure the contracts directory exists
	if err := os.MkdirAll("data/contracts", 0755); err != nil {
		return nil, errl.Errorf("failed to create contracts directory: %v", err)
	}

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererFiber(templateDebug, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		return nil, errl.Errorf("failed to initialize template engine: %w", err)
	}

	httpServer := fiber.New(fiber.Config{
		AppName:                 "CertAuth OP",
		ServerHeader:            "CertAuth",
		ReadBufferSize:          64 * 1024, // 64 KB — allows large Authorization headers (e.g. JWTs with many claims)
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Observability
	prometheus := fiberprometheus.New("certauth")
	prometheus.RegisterAt(httpServer, "/metrics")
	httpServer.Use(prometheus.Middleware)

	// Recover middleware recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	httpServer.Use(recover.New())

	// Helmet middleware helps secure your apps by setting various HTTP headers.
	httpServer.Use(helmet.New())

	// Ignores favicon requests
	httpServer.Use(favicon.New())

	// Logs HTTP request/response details
	httpServer.Use(FiberRequestLogger)

	// Enable CORS for all origins
	httpServer.Use(cors.New())

	httpServer.Static("/static", templateStaticResources)

	// Initialize JWT service, with us as the JWT Issuer
	jwtService, err := jwtservice.New(cfg.CertAuthURL)
	if err != nil {
		return nil, errl.Errorf("failed to initialize JWT service: %w", err)
	}

	// Initialize timestamping service
	tsaService, err := tsaservice.NewTSAService(cfg.TSAConfig)
	if err != nil {
		return nil, errl.Errorf("failed to initialize TSA service at: %s, %w", cfg.TSAConfig.TSAURL, err)
	}

	// Initialize the email service
	emailService, err := email.NewService(cfg.EmailConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create email service: %v", err)
	}

	// Initialize the tmfservice
	slog.Info("TMF server URL", "url", cfg.TMFServerURL)
	tmfservice, err := tmfservice.NewTMFService(&tmfservice.TMFClientConfig{
		BaseURL: cfg.TMFServerURL,
		Timeout: 30,
	})
	if err != nil {
		return nil, errl.Errorf("failed to create tmfservice: %v", err)
	}

	// Put everything together in a server
	s := &CertAuthServer{
		profile:          cfg.Profile,
		certAuthURL:      cfg.CertAuthURL,
		certAuthPort:     cfg.CertAuthPort,
		certSecURL:       cfg.CertSecURL,
		managementURL:    cfg.ManagementURL,
		managementAPIKey: cfg.ManagementAPIKey,
		euDSSURL:         cfg.EUDSSURL,
		httpServer:       httpServer,
		db:               db,
		jwtService:       jwtService,
		htmlRender:       htmlrender,
		authprocCache:    authprocCache,
		ssoCache:         ssoCache,
		tsaService:       tsaService,
		emailService:     emailService,
		tmfService:       tmfservice,
		tmfAdminToken:    cfg.TMFAdminToken,
	}

	// Register the health check endpoint
	s.httpServer.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy", "hostname": c.Hostname()})
	})

	// Register the OpenID Provider (OP) endpoints to support Relying Parties
	s.registerOIDCHandlers()

	// Register the endpoints for OIDVP with the Wallet
	s.registerWalletHandlers()

	// Register the eIDAS certificate endpoints to talk with CertSec (requesting the certificate from the browser)
	s.registerCertificateHandlers()

	// Register the admin endpoints (protected)
	s.registerAdminHandlers(adminPassword)

	return s, nil
}

// Start starts the server
func (s *CertAuthServer) Start(ctx context.Context) error {

	if s.httpServer == nil {
		return errors.New("server not initialized")
	}

	addr := net.JoinHostPort("0.0.0.0", s.certAuthPort)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.httpServer.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	slog.Info("CertAuth server started", "addr", addr)

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.httpServer.Shutdown()
	}

}

// MigrateTMFOrganizations updates the TMF Organization object for all registered organizations in our database,
// with the eIDAS certificate used to register the organization
func (s *CertAuthServer) MigrateTMFOrganizations() error {

	// Get all registrations from the database
	registrations, err := s.db.GetRegistrations()
	if err != nil {
		return errl.Errorf("failed to get registrations: %w", err)
	}

	// For each registration, update the TMF Organization object
	for _, registration := range registrations {
		// Build the organization objectid from the registration
		organizationId := "urn:ngsi-ld:organization:did:elsi:" + registration.OrganizationIdentifier

		organizationDID := "did:elsi:" + registration.OrganizationIdentifier

		// Get the existingOrganization from the TMF server
		existingOrganization, err := s.tmfService.TMFRetrieveOrganization(s.tmfAdminToken, organizationId, "")
		if err != nil {
			slog.Error("failed to retrieve organization from TMF", "error", err, "organizationId", organizationId)
			continue
		}

		// The derCertificate is a binary DER encoded X.509 certificate.
		// It needs to be converted to a base64 encoded string to be included in the TMF Organization object.
		base64Cert := base64.StdEncoding.EncodeToString([]byte(registration.EidasCert))

		eIDASAttachment := &tmfservice.AttachmentRefOrValue{
			AttachmentType: "eIDAS",
			Name:           "eIDAS_certificate",
			Description:    "eIDAS certificate used for identification",
			MimeType:       "application/pkix-cert",
			Content:        base64Cert,
		}

		// Replace the existing OrganizationIdentification with the new one
		existingOrganization.OrganizationIdentification = []tmfservice.OrganizationIdentification{
			{
				Type:               "organizationIdentification",
				IdentificationID:   organizationDID,
				IdentificationType: "did:elsi",
				IssuingAuthority:   "eIDAS",
				Attachment:         eIDASAttachment,
			},
		}

		// Delete the existing Object
		err = s.tmfService.TMFDeleteOrganization(s.tmfAdminToken, organizationId)
		if err != nil {
			slog.Error("failed to delete organization", "error", err, "organizationId", organizationId)
			continue
		}

		// Build an create object from the organization object
		orgCreate := tmfservice.OrgCreateFromOrg(existingOrganization)

		// Create the organization in the TMF server
		_, err = s.tmfService.TMFCreateOrganization(s.tmfAdminToken, orgCreate)
		if err != nil {
			slog.Error("failed to create organization", "error", err, "organizationId", organizationId)
			continue
		}

		slog.Info("Created organization", "organization", organizationId)

	}

	return nil
}

var noLoggingFor = map[string]bool{
	"/health":      true,
	"/favicon.ico": true,
}

// FiberRequestLogger logs HTTP requests on entry and exit
func FiberRequestLogger(c *fiber.Ctx) error {

	// Log entry, except the /health request, to keep logs clean
	if _, found := noLoggingFor[c.Path()]; !found {
		slog.Debug("=> "+c.Method()+" "+c.Path(), slog.String("ip", c.IP()))
	}

	// Go to next middleware
	if err := c.Next(); err != nil {
		return err
	}

	// Log exit
	code := c.Response().StatusCode()

	if code >= 500 {
		// Internal server errors
		meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
		slog.Error(meth, slog.Int("status", code), slog.String("ip", c.IP()))
	} else if code >= 400 {
		// Caller errors
		meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
		slog.Warn(meth, slog.Int("status", code), slog.String("ip", c.IP()))
	} else {
		// The rest
		if _, found := noLoggingFor[c.Path()]; !found {
			meth := fmt.Sprintf("<= %s %d %s", c.Method(), code, c.Path())
			slog.Debug(meth, slog.Int("status", code), slog.String("ip", c.IP()))
		}
	}

	return nil

}
