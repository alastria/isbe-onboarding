// Package mainserver implements the main entry point logic for the server, managing CertAuth, CertSec, and Onboard services.
package mainserver

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	certauth "github.com/alastria/isbe-onboarding/certauthserver"
	certsec "github.com/alastria/isbe-onboarding/certsecserver"
	"github.com/alastria/isbe-onboarding/database"
	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	onboard "github.com/alastria/isbe-onboarding/onboard"
)

// Server manages the CertAuth, CertSec and Onboard servers
type Server struct {
	cfg            Config
	certauthServer *certauth.CertAuthServer
	certsecServer  *certsec.CertSecServer
	onboardServer  *onboard.Server
	db             *database.Database
	adminPW        string
}

// New creates a new server instance.
// It initializes the database, cache, CertAuth, CertSec and Onboard servers.
func New(adminPassword string, cfg Config) (*Server, error) {

	// Create a global in-memory cache for authentication processes with a default expiration time of 30 minutes
	// TODO(hesusruiz): make this configurable
	authprocCache := cache.NewGeneric[string, *models.AuthProcess](30 * time.Minute)

	// Create a global in-memory cache for SSO sessions with a default expiration time of 30 minutes
	// TODO(hesusruiz): make this configurable
	ssoCache := cache.NewGeneric[string, *models.SSOSession](30 * time.Minute)

	// Initialize database with the default name
	db, err := database.New("", cfg.Profile)
	if err != nil {
		slog.Error("Failed to initialize database", "error", err)
		return nil, errl.Errorf("failed to initialize database: %w", err)
	}

	// Initialize predefined Relying Parties
	for _, rp := range cfg.PredefinedRPs {
		if err := db.UpsertRelyingParty(rp.RelyingParty, rp.ClientSecret); err != nil {
			return nil, errl.Errorf("failed to initialize RP %s: %w", rp.RelyingParty.Name, err)
		}
	}

	// Create the authentication and authorization servers.
	// They share the same database and authentication process cache.

	cfg.CertAuthConfig.TMFServerURL = cfg.TMFServerURL
	certauthServer, err := certauth.NewCertAuth(db, authprocCache, ssoCache, adminPassword, cfg.CertAuthConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certauth server: %w", err)
	}

	// Migrate TMF Organizations
	if err := certauthServer.MigrateTMFOrganizations(); err != nil {
		return nil, errl.Errorf("failed to migrate TMF organizations: %w", err)
	}

	// CertSec server requests the certificate from the user browser and passes it to the CerAuth server.
	// It also implements admin functionalities, using a client certificate as authentication mechanism.
	newCertSecConfig := &certsec.Config{
		Profile:                 cfg.Profile,
		CertAuthURL:             cfg.CertAuthConfig.CertAuthURL,
		CertificateBackEndpoint: certauth.CertificateBackEndpoint,
		CertSecURL:              cfg.CertAuthConfig.CertSecURL,
		CertSecPort:             cfg.CertAuthConfig.CertSecPort,
	}
	certsecServer, err := certsec.New(db, authprocCache, ssoCache, newCertSecConfig)
	if err != nil {
		return nil, errl.Errorf("failed to create certsec server: %w", err)
	}

	// If the Onboard URL is configured, create the Onboard application server.
	// It uses the CertAuth server as the OP.

	var onboardServer *onboard.Server
	if cfg.OnboardURL != "" {
		onboardServer = onboard.New(cfg.OnboardPort, cfg.OnboardURL, cfg.CertAuthConfig.CertAuthURL, "isbeonboard", "isbesecret", cfg.PrivateArea)
	}

	return &Server{
		certauthServer: certauthServer,
		certsecServer:  certsecServer,
		onboardServer:  onboardServer,
		db:             db,
		adminPW:        adminPassword,
		cfg:            cfg,
	}, nil

}

// Start starts both servers: CertAuth and CertSec. It also starts the Onboarding test server if enabled
func (s *Server) Start(ctx context.Context) error {

	if s.db == nil {
		return errl.Errorf("server not initialized")
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	// Start CertAuth server (default port 8090)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certauthServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certauth server failed: %w", err)
		}
	}()

	// Start CertSec server (default port 8091)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.certsecServer.Start(ctx); err != nil {
			errChan <- fmt.Errorf("certsec server failed: %w", err)
		}
	}()

	// Start Onboard server (default port 8092)
	if s.onboardServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.onboardServer.Start(); err != nil {
				errChan <- fmt.Errorf("onboard server failed: %w", err)
			}
		}()
	}

	// Wait for either server to fail or context to be cancelled
	select {
	case err := <-errChan:
		s.db.Close()
		return err
	case <-ctx.Done():
		slog.Info("Shutting down servers")
		s.db.Close()
		return nil
	}
}
