// Package certsec implements the server logic for handling client certificate authentication from the user's browser.
package certsec

import (
	"context"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/tmfservice"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/types"
)

const stdCertHeader = "tls-client-certificate"
const kubeCertHeader = "X-Amzn-Mtls-Clientcert"

const templateDirectory = "certsecserver/views"
const templateExtension = ".hbs"
const templateStaticResources = "certsecserver/views/assets"

// Config is the configuration for the CertSecserver.
type Config struct {

	// The environment where we are running
	Profile types.Profile

	// The URL and internal port of the CertSec server
	CertSecURL  string
	CertSecPort string

	// The URL of the CertAuth server, used to redirect the user back to the CertAuth server
	CertAuthURL             string
	CertificateBackEndpoint string
}

// CertSecServer represents the CertSec certificate authentication server
type CertSecServer struct {
	// The environment where we are running
	Profile types.Profile

	// The URL of the CertAuth server, used to redirect the user back to the CertAuth server
	CertSecURL  string
	CertSecPort string

	// The URL of the CertAuth server, used to redirect the user back to the CertAuth server
	CertAuthURL string

	// The endpoint of the CertAuth server, used to redirect the user back to the CertAuth server
	CertificateBackEndpoint string

	// The HTTP server (using Fiber)
	app *fiber.App

	// The database
	db *database.Database

	// The authentication process cache
	authprocCache *cache.GenericCache[string, *models.AuthProcess]

	// The single session cache
	ssoCache *cache.GenericCache[string, *models.SSOSession]

	// The template renderer
	htmlRender *html.RendererFiber

	// The TMF client
	tmfClient *tmfservice.TMFService
}

//go:embed views/*
var viewsfs embed.FS

// New creates a new CertSec server.
// This is a minimal server which requests a client certificate to the client browser.
// It is invoked from the CertAuth server, which is the main OpenID Provider
// supporting eIDAS certificates and Verifiable Credentials.
// The CerSec server requires a reverse proxy (like Caddy or Nginx) in front, terminating the TLS connection
// and configured to actually requesting the client certificate.
func New(
	db *database.Database,
	authprocCache *cache.GenericCache[string, *models.AuthProcess],
	ssoCache *cache.GenericCache[string, *models.SSOSession],
	cfg *Config) (*CertSecServer, error) {

	// The engine to display the HTML screens to the users
	htmlrender, err := html.NewRendererFiber(cfg.Profile == types.PROFILE_LOCAL, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		return nil, errl.Errorf("failed to initialize template engine: %w", err)
	}

	tmfClient, err := tmfservice.NewTMFService(&tmfservice.TMFClientConfig{
		BaseURL: "https://tmf.evidenceledger.eu",
		Timeout: 30,
	})
	if err != nil {
		return nil, errl.Errorf("failed to initialize TMF client: %w", err)
	}

	app := fiber.New(fiber.Config{
		AppName:        "CertSec Certificate Authentication",
		ReadBufferSize: 64 * 1024, // 64 KB — allows large Authorization headers (e.g. JWTs with many claims)
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
	})

	app.Use(recover.New())
	app.Use(logger.New())

	app.Static("/static", templateStaticResources)

	s := &CertSecServer{
		app:                     app,
		db:                      db,
		authprocCache:           authprocCache,
		ssoCache:                ssoCache,
		Profile:                 cfg.Profile,
		CertAuthURL:             cfg.CertAuthURL,
		CertificateBackEndpoint: cfg.CertificateBackEndpoint,
		CertSecURL:              cfg.CertSecURL,
		CertSecPort:             cfg.CertSecPort,
		htmlRender:              htmlrender,
		tmfClient:               tmfClient,
	}

	s.app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "healthy"})
	})

	// Certificate authentication endpoint
	s.app.Get("/auth", s.handleCertificateAuth)

	// Register admin pages
	s.app.Get("/admin", s.adminPages)
	s.app.Get("/admin/:page", s.adminPages)
	s.app.Post("/admin/:page", s.adminPages)

	return s, nil
}

type RelyingPartyCUDRequest struct {
	ID           int    `form:"id"`
	Action       string `form:"action"`
	Name         string `form:"name"`
	Description  string `form:"description"`
	ClientID     string `form:"client_id"`
	ClientSecret string `form:"client_secret"`
	RedirectURL  string `form:"redirect_url"`
	OriginURL    string `form:"origin_url"`
	Scopes       string `form:"scopes"`
	TokenExpiry  int    `form:"token_expiry"`
}

// adminPages handles the admin pages
func (s *CertSecServer) adminPages(c *fiber.Ctx) error {

	adminSubject, err := s.checkAdminAuthentication(c)
	if err != nil {
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": err.Error(),
		})
	}

	// Get the page from the path parameter
	page := c.Params("page")

	// Switch based on the page
	switch page {
	case "", "registrations":
		return s.registrationsPage(c, adminSubject)
	case "organizations":
		return s.organizationsPage(c, adminSubject)
	case "relyingparties":
		return s.relyingpartiesPage(c, adminSubject)
	case "contract":
		return s.contractDocument(c, adminSubject)
	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid page: " + page,
		})
	}

}

func (s *CertSecServer) relyingpartiesPage(c *fiber.Ctx, adminSubject *x509util.ELSIName) error {

	switch c.Method() {
	case "GET":

		// Retrieve the Relying Parties from the database
		rps, err := s.db.ListRelyingParties()
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to retrieve relying parties: " + err.Error(),
				"subject": adminSubject,
			})
		}

		return s.htmlRender.Render(c, "relyingparties", fiber.Map{
			"rps":     rps,
			"subject": adminSubject,
		})

	case "POST":

		var request RelyingPartyCUDRequest
		if err := c.BodyParser(&request); err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("Invalid request")
		}

		// Create the object
		rp := models.RelyingParty{
			ID:          request.ID,
			Name:        request.Name,
			Description: request.Description,
			ClientID:    request.ClientID,
			RedirectURL: request.RedirectURL,
			Scopes:      request.Scopes,
			TokenExpiry: request.TokenExpiry,
		}

		switch request.Action {
		case "create":
			if err := s.db.CreateRelyingParty(&rp, request.ClientSecret); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to create relying party: " + err.Error(),
					"subject": adminSubject,
				})
			}
		case "update":
			if err := s.db.UpdateRelyingParty(&rp, request.ClientSecret); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to update relying party: " + err.Error(),
					"subject": adminSubject,
				})
			}
		case "delete":
			if err := s.db.DeleteRelyingParty(request.ID); err != nil {
				return s.htmlRender.Render(c, "error", fiber.Map{
					"message": "Failed to delete relying party: " + err.Error(),
					"subject": adminSubject,
				})
			}
		}

		return c.Redirect("/admin/relyingparties")

	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid action: " + c.Method(),
			"subject": adminSubject,
		})
	}

}

func (s *CertSecServer) organizationsPage(c *fiber.Ctx, adminSubject *x509util.ELSIName) error {

	orgsPath := "/tmf-api/party/v4/organization"

	switch c.Method() {
	case "GET":

		// Retrieve the TMF Organization objects
		orgs, err := s.tmfClient.GetList(orgsPath, nil)
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to retrieve organizations: " + err.Error(),
				"subject": adminSubject,
			})
		}

		out, err := json.MarshalIndent(orgs, "", "  ")
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to marshal organizations: " + err.Error(),
				"subject": adminSubject,
			})
		}

		return s.htmlRender.Render(c, "organizations", fiber.Map{
			"File":    string(out),
			"subject": adminSubject,
		})

	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid action: " + c.Method(),
			"subject": adminSubject,
		})
	}

}

// Retrieve the registrations
func (s *CertSecServer) registrationsPage(c *fiber.Ctx, adminSubject *x509util.ELSIName) error {

	switch c.Method() {
	case "GET":

		// Retrieve the registrations from the database
		r, err := s.db.GetRegistrations()
		if err != nil {
			return s.htmlRender.Render(c, "error", fiber.Map{
				"message": "Failed to retrieve registrations: " + err.Error(),
				"subject": adminSubject,
			})
		}

		return s.htmlRender.Render(c, "registrations", fiber.Map{
			"registrations": r,
			"subject":       adminSubject,
		})

	default:
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Invalid action: " + c.Method(),
			"subject": adminSubject,
		})
	}

}

// Retrieve the PDF contract and return to the browser as a file
func (s *CertSecServer) contractDocument(c *fiber.Ctx, adminSubject *x509util.ELSIName) error {

	// Get the organization ID for the caller
	orgid := c.Query("orgid")
	if orgid == "" {
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Organization ID is required",
			"subject": adminSubject,
		})
	}

	slog.Info("Retrieving contract document", "orgid", orgid)

	// Retrieve the registration for this organization
	_, _, contractDocumentName, err := s.db.GetRegistration(orgid)
	if err != nil {
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Failed to retrieve registration: " + err.Error(),
			"subject": adminSubject,
		})
	}

	if len(contractDocumentName) == 0 {
		slog.Warn("Contract document name is empty", "orgid", orgid)
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": "Contract document name is empty",
			"subject": adminSubject,
		})
	}

	// Return the contract as a PDF file
	return c.SendFile(contractDocumentName, true)

}

var adminIssuerOrganizationIdentifiers = []string{
	"VATES-G87936159", // Alastria
	"VATES-11111111K", // Fake ISBE Foundation
}

var adminSubjectSerialNumbers = []string{
	"IDCES-21442837Y",
	"A12345678",
}

// isAdmin checks if the certificate is issued by any organization which is an authorized issuer.
// It additionally checks for a specific user.
func isAdmin(issuer *x509util.ELSIName, subject *x509util.ELSIName) bool {
	return slices.Contains(adminIssuerOrganizationIdentifiers, issuer.OrganizationIdentifier) || slices.Contains(adminSubjectSerialNumbers, subject.SerialNumber)
}

func (s *CertSecServer) checkAdminAuthentication(c *fiber.Ctx) (*x509util.ELSIName, error) {

	_, issuer, subject, _, err := s.retrieveCertificate(c)
	if err != nil {
		return nil, errl.Errorf("retrieving certificate: %w", err)
	}

	// Check for admin
	if !isAdmin(issuer, subject) {
		return nil, errl.Errorf("Certificate serial number '%s' or issuer.organizationIdentifier '%s' is invalid", subject.SerialNumber, issuer.OrganizationIdentifier)
	}

	return subject, nil
}

func (s *CertSecServer) retrieveCertificate(c *fiber.Ctx) (
	cert *x509.Certificate,
	issuer *x509util.ELSIName,
	subject *x509util.ELSIName,
	b64der string,
	err error) {
	// Check both the std and kube cert headers to see if we received a certificate
	certFromHeader := c.Get(stdCertHeader)
	if certFromHeader != "" {
		slog.Debug("Certificate data found in standard header", "header", stdCertHeader, "cert_length", len(certFromHeader))
	} else {
		certFromHeader = c.Get(kubeCertHeader)
		if certFromHeader != "" {
			slog.Debug("Certificate data found in kube header", "header", kubeCertHeader, "cert_length", len(certFromHeader))
		} else {
			return nil, nil, nil, "", errl.Errorf("No certificate provided, neither in %s nor in %s", stdCertHeader, kubeCertHeader)
		}
	}

	// Check that we received enough data
	if len(certFromHeader) < 100 {
		return nil, nil, nil, "", errl.Errorf("Certificate data too short: %d bytes", len(certFromHeader))
	}

	// Parse the certificate, which may come as DER or PEM format
	// First, detect if it seems PEM
	if strings.HasPrefix(certFromHeader, "-----BEGIN") {
		// It's PEM, so decode it from base64 and then PEM decode it

		// This header contains the URL-encoded PEM format of the entire client certificate chain presented in the connection, with +=/ as safe characters.
		// We have to first decode
		certFromHeaderDecoded, err := url.PathUnescape(certFromHeader)
		if err != nil {
			fmt.Printf("Failed to decode base64url certificate from header: %s\n", certFromHeader)
			return nil, nil, nil, "", errl.Errorf("Failed to decode base64url certificate from header: %w", err)
		}

		cert, issuer, subject, b64der, err = x509util.ParseCertificateFromPEM([]byte(certFromHeaderDecoded))
		if err != nil {
			fmt.Printf("Bad PEM certificate: %s\n", certFromHeader)
			return nil, nil, nil, "", errl.Errorf("Failed to parse certificate from PEM: %w", err)
		}
	} else {
		// Assume it is DER, so decode it directly
		cert, issuer, subject, err = x509util.ParseEIDASCertB64Der(certFromHeader)
		if err != nil {
			fmt.Printf("Bad DER certificate: %s\n", certFromHeader)
			return nil, nil, nil, "", errl.Errorf("Failed to parse certificate: %w", err)
		}
		b64der = certFromHeader
	}

	// For testing we accept personal certificates, but we do not accept that both
	// the organizationIdentifier and the serialNumber are empty.
	if subject.OrganizationIdentifier == "" && subject.SerialNumber == "" {
		return nil, nil, nil, "", errl.Errorf("Both organizationIdentifier and serialNumber are empty")
	}

	// Check certificate expiration
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return nil, nil, nil, "", errl.Errorf("Certificate not yet valid, not_before: %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return nil, nil, nil, "", errl.Errorf("Certificate expired not_after: %s", cert.NotAfter.Format(time.RFC3339))
	}

	return cert, issuer, subject, b64der, nil
}

// handleCertificateAuth handles the certificate authentication endpoint.
// This endpoint receives the certificate from the browser and sends it to the CertAuth server
// via the global cache. Both CertAuth and CerSec must be running in the same process.
func (s *CertSecServer) handleCertificateAuth(c *fiber.Ctx) error {
	// Get auth code from query parameter
	authCode := c.Query("code")
	if authCode == "" {
		slog.Error("missing authorization code")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the AuthorizationRequest associated with the authCode from the cache
	// to ensure the auth code is valid and was recently issued
	authProcess, found := s.authprocCache.Get(authCode)
	if !found {
		slog.Error("Authorization code not found in cache", "auth_code", authCode)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid or expired authorization code",
		})
	}

	if authProcess == nil {
		slog.Error("Retrieved nil for AuthorizationRequest in cache", "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	slog.Info("Certificate authentication requested", "auth_code", authCode)

	sendBackError := func(err error) error {
		// Redirect back to certauth with an error
		authProcess.ErrorInProcess = err
		redirectURL := s.CertAuthURL + s.CertificateBackEndpoint + "?code=" + authCode + "&error=true"
		return c.Status(fiber.StatusFound).Redirect(redirectURL)
	}

	// Get the certificate from the TLS connection
	cert, issuer, subject, b64der, err := s.retrieveCertificate(c)
	if err != nil {
		return sendBackError(errl.Errorf("retrieving certificate: %w", err))
	}

	// Determine certificate type
	certType := "personal"
	if subject.OrganizationIdentifier != "" {
		certType = "organizational"
	}

	// Log successful processing (Info level with organizational data only)
	logFields := []any{
		"auth_code", authCode,
		"certificate_type", certType,
		"valid_from", cert.NotBefore,
		"valid_to", cert.NotAfter,
	}

	// Only log organizational fields for privacy (exclude personal identifiers)
	if subject.Organization != "" {
		logFields = append(logFields, "organization", subject.Organization)
	}
	if subject.OrganizationIdentifier != "" {
		logFields = append(logFields, "organization_identifier", subject.OrganizationIdentifier)
	}
	if subject.SerialNumber != "" {
		logFields = append(logFields, "serial_number", "************")
	}
	if subject.Country != "" {
		logFields = append(logFields, "country", subject.Country)
	}

	slog.Info("Certificate processed successfully", logFields...)

	// Create the CertificateData struct
	certData := &models.CertificateData{
		Subject:         subject,
		Issuer:          issuer,
		ValidFrom:       cert.NotBefore,
		ValidTo:         cert.NotAfter,
		OrganizationID:  subject.OrganizationIdentifier,
		CertificateType: certType,
		Certificate:     cert,
		CertificateDER:  b64der,
	}

	// Set the certificate data in the auth request for later retrieval
	authProcess.CertificateData = certData

	// Redirect back to certauth
	redirectURL := s.CertAuthURL + "/certificate-back?code=" + authCode
	return c.Status(fiber.StatusFound).Redirect(redirectURL)

}

// Start starts the server
func (s *CertSecServer) Start(ctx context.Context) error {

	addr := net.JoinHostPort("0.0.0.0", s.CertSecPort)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.app.Listen(addr); err != nil {
			errChan <- fmt.Errorf("failed to start server: %w", err)
		}
	}()
	slog.Info("CertSec server started", "addr", s.CertSecPort)

	// Wait for context cancellation or error
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		return s.app.Shutdown()
	}
}
