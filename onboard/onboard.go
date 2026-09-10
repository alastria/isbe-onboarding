// Package onboard implements the onboarding service, allowing users to register and obtain credentials.
package onboard

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/alastria/isbe-onboarding/internal/cache"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

// Server represents the example RP server
type Server struct {
	internalPort  string
	ourURL        string
	providerURL   string
	sessions      map[string]*models.RPSession
	sessionsMutex sync.RWMutex
	clientID      string
	clientSecret  string
	oauth2Config  oauth2.Config
	verifier      *oidc.IDTokenVerifier
	html          *html.RendererStd
	privateArea   string
	loginCache    *cache.GenericCache[string, *SSOSession]
}

type SSOSession struct {
	State string `json:"state"`
	Nonce string `json:"nonce"`
}

// isSecure checks if the server URL uses HTTPS
func (s *Server) isSecure() bool {
	parsedURL, err := url.Parse(s.ourURL)
	if err != nil {
		return false
	}
	return parsedURL.Scheme == "https"
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// New creates a new Application server.
// internalPort is the port on which the server will listen for internal requests.
// ourURL is the public URL of the server.
// providerURL is the URL of the OpenID Provider (OP).
// clientID is our RP client ID as registered in the OP.
// clientSecret is our RP client secret as registered in the OP.
func New(internalPort, ourURL, providerURL, clientID, clientSecret, privateArea string) *Server {

	// Initialize the template engine
	htmlrender, err := html.NewRendererStd(templateDebug, viewsfs, "onboard/views", ".hbs")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	// Initialize the session cache
	loginCache := cache.NewGeneric[string, *SSOSession](30 * time.Minute)

	// Initialize the server
	return &Server{
		internalPort: internalPort,
		ourURL:       ourURL,
		providerURL:  providerURL,
		sessions:     make(map[string]*models.RPSession),
		clientID:     clientID,
		clientSecret: clientSecret,
		html:         htmlrender,
		privateArea:  privateArea,
		loginCache:   loginCache,
	}
}

// Start starts the Relying Party server
func (s *Server) Start() error {

	http.HandleFunc("/", s.handleHome)
	http.HandleFunc("/en", s.handleHome)
	http.HandleFunc("/login", s.handleLogin)
	http.HandleFunc("/login/en", s.handleLogin)
	http.HandleFunc("/register", s.handleRegister)
	http.HandleFunc("/register/en", s.handleRegister)
	http.HandleFunc("/callback", s.handleCallback)
	http.HandleFunc("/logout", s.handleLogout)

	// Serve files from the "static" directory
	fileServer := http.FileServer(http.Dir("onboard/views/assets"))

	// Handle requests with "/static/" prefix
	http.Handle("/static/", http.StripPrefix("/static", fileServer))

	addr := net.JoinHostPort("0.0.0.0", s.internalPort)
	slog.Info("Onboard server started", "addr", addr, "op_base_url", s.providerURL)

	return http.ListenAndServe(addr, nil)
}

func (s *Server) configureVerifier() error {

	if s.verifier != nil {
		return nil
	}

	ctx := context.Background()

	// Configure how to call the provider via discovery
	// Retry up to 3 times with 2 second sleep to allow the provider to start if it is started in the same process
	provider, err := oidc.NewProvider(ctx, s.providerURL)
	if err != nil {
		slog.Error("Failed to create provider for relying party, retrying", "error", err)
		for range 10 {
			time.Sleep(2 * time.Second)
			provider, err = oidc.NewProvider(ctx, s.providerURL)
			if err != nil {
				slog.Error("Retry failed to create provider for relying party", "error", err)
			} else {
				slog.Info("Provider for relying party created")
				break
			}
		}
	} else {
		slog.Info("Provider for relying party created")
	}
	if err != nil {
		return errl.Errorf("failed to create provider for relying party: %w", err)
	}

	// Get an IDTokenVerifier that uses the provider's key set to verify JWTs
	verifier := provider.Verifier(&oidc.Config{
		ClientID: s.clientID,
		SupportedSigningAlgs: []string{
			"RS256",
			"ES256",
			"PS256",
		},
	})

	// We want the OP to call us back here
	redirectURL, err := url.JoinPath(s.ourURL, "/callback")
	if err != nil {
		return errl.Errorf("failed to parse our URL: %w", err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecret,
		RedirectURL:  redirectURL,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		// "eidas" is the scope for the eIDAS flow
		Scopes: []string{oidc.ScopeOpenID, "eidas"},
	}

	s.oauth2Config = oauth2Config
	s.verifier = verifier

	return nil
}

// handleHome handles the home page
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/en" {
		http.NotFound(w, r)
		return
	}

	err := s.configureVerifier()
	if err != nil {
		slog.Error("Failed to configure verifier", "error", err)
		http.Error(w, "Failed to configure verifier", http.StatusInternalServerError)
		return
	}

	// If user is logged in, show welcome page
	sessionID := s.getSessionID(r)
	if session := s.getSession(sessionID); session != nil {
		s.renderWelcomePage(w, r, session)
		return
	}

	s.renderRegisterOrLoginPage(w, r)
}

type LoginOrRegister bool

const (
	Login    LoginOrRegister = true
	Register LoginOrRegister = false
)

// handleLogin initiates the OIDC flow
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {

	s.handleLoginOrRegister(w, r, Login)

}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {

	s.handleLoginOrRegister(w, r, Register)

}

func (s *Server) handleLoginOrRegister(w http.ResponseWriter, r *http.Request, login LoginOrRegister) {

	err := s.configureVerifier()
	if err != nil {
		slog.Error("Failed to configure verifier", "error", err)
		http.Error(w, "Failed to configure verifier", http.StatusInternalServerError)
		return
	}

	// Generate state for CSRF protection
	state := s.generateRandomString(32)
	isEnglish := strings.HasSuffix(r.URL.Path, "/en")
	if isEnglish {
		state = "en_" + state
	}

	// Generate nonce for replay protection
	nonce := s.generateRandomString(32)

	// Store state in the login cache
	s.loginCache.Set(state, &SSOSession{
		State: state,
		Nonce: nonce,
	}, 0)

	// // Store state in session (in a real app, you'd use proper session management)
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "oauth_state",
	// 	Value:    state,
	// 	Path:     "/",
	// 	HttpOnly: true,
	// 	Secure:   s.isSecure(), // Only use Secure flag when using HTTPS
	// 	SameSite: http.SameSiteLaxMode,
	// 	MaxAge:   300, // 5 minutes
	// })

	// Redirect to the OP for authentication
	if login {
		s.oauth2Config.Scopes = []string{oidc.ScopeOpenID, "learcred"}
	} else {
		s.oauth2Config.Scopes = []string{oidc.ScopeOpenID, "eidas"}
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
	}

	if isEnglish {
		opts = append(opts, oauth2.SetAuthURLParam("ui_locales", "en"))
	}

	redirectURL := s.oauth2Config.AuthCodeURL(state, opts...)
	http.Redirect(w, r, redirectURL, http.StatusFound)

}

// handleCallback handles the OIDC callback
// The OP calls us here when it has finished authenticating the user
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get parameters from callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	autherror := r.URL.Query().Get("error")
	errorDescription := r.URL.Query().Get("error_description")

	// Check that the state exists in our login cache
	loginSession, found := s.loginCache.Get(state)
	if !found {
		slog.Error("Invalid state parameter", "error", "state not found in login cache")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	if loginSession.State != state {
		slog.Error("Invalid state parameter", "error", "state not found in login cache")
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// // Validate that the state we received is the same as the one we sent
	// cookieState, err := r.Cookie("oauth_state")
	// if err != nil || cookieState.Value != state {
	// 	slog.Error("Invalid state parameter", "error", err)
	// 	http.Error(w, "Invalid state parameter", http.StatusBadRequest)
	// 	return
	// }

	// // Clear state cookie, as the authentication flow has finished
	// http.SetCookie(w, &http.Cookie{
	// 	Name:     "oauth_state",
	// 	Value:    "",
	// 	Path:     "/",
	// 	HttpOnly: true,
	// 	Secure:   s.isSecure(), // Only use Secure flag when using HTTPS
	// 	SameSite: http.SameSiteLaxMode,
	// 	MaxAge:   -1,
	// })

	if autherror != "" {
		slog.Error("RP OIDC error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, r, autherror, errorDescription)
		return
	}

	var oauth2Token *oauth2.Token
	var idToken *oidc.IDToken
	var tokens map[string]any

	ctx := r.Context()

	// Exchange the authorization code for an access_token and an ID_token
	oauth2Token, err := s.oauth2Config.Exchange(ctx, code)
	if err != nil {
		slog.Error("RP token exchange error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, r, autherror, errorDescription)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		// handle missing token
	}

	// Parse and verify ID Token payload.
	idToken, err = s.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		slog.Error("RP verifying the ID token error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, r, autherror, errorDescription)
		return
	}

	// Extract custom claims
	var claims models.ELSI_IDTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		slog.Error("RP extract custom claims error received", "error", autherror, "description", errorDescription)
		s.renderErrorPage(w, r, autherror, errorDescription)
		return
	}

	tokens = map[string]any{
		"access_token": oauth2Token.AccessToken,
		"id_token":     rawIDToken,
		"token_type":   oauth2Token.Type(),
		"expires_in":   oauth2Token.ExpiresIn,
		"scope":        "",
	}

	// Create user session
	session := s.createSession(tokens)

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    session.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // 1 hour
	})

	slog.Info("Redirecting to private area", "path", s.privateArea, "state", state)
	redirectPath := s.privateArea
	if strings.HasPrefix(state, "en_") {
		redirectPath = strings.TrimSuffix(redirectPath, "/") + "/en"
	}
	http.Redirect(w, r, redirectPath, http.StatusFound)
}

// handleLogout handles user logout
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {

	err := s.configureVerifier()
	if err != nil {
		slog.Error("Failed to configure verifier", "error", err)
		http.Error(w, "Failed to configure verifier", http.StatusInternalServerError)
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "rp_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	// Redirect to home page
	// http.Redirect(w, r, "/", http.StatusFound)
	http.Redirect(w, r, s.privateArea, http.StatusFound)
}

// Helper methods

func (s *Server) generateRandomString(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s *Server) getSessionID(r *http.Request) string {
	cookie, err := r.Cookie("rp_session")
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) getSession(sessionID string) *models.RPSession {
	s.sessionsMutex.RLock()
	defer s.sessionsMutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil
	}

	// Check if session is expired (1 hour)
	if time.Since(session.LastAccessed) > time.Hour {
		delete(s.sessions, sessionID)
		return nil
	}

	// Update last accessed time
	session.LastAccessed = time.Now()
	return session
}

func (s *Server) createSession(tokens map[string]any) *models.RPSession {
	sessionID := s.generateRandomString(32)

	// Extract user info from tokens
	var userID string
	if sub, ok := tokens["sub"].(string); ok {
		userID = sub
	} else {
		userID = "unknown"
	}

	session := &models.RPSession{
		SessionID:    sessionID,
		UserID:       userID,
		AccessToken:  tokens["access_token"].(string),
		IDToken:      tokens["id_token"].(string),
		CreatedAt:    time.Now(),
		LastAccessed: time.Now(),
	}

	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, jwt.MapClaims{})
	if err != nil {
		slog.Error("Failed to parse ID token", "error", err)
		return nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		slog.Error("Failed to parse ID token", "error", err)
		return nil
	}

	session.IDTokenClaims = claims

	out, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println("ID token claims", string(out))

	s.sessionsMutex.Lock()
	s.sessions[sessionID] = session
	s.sessionsMutex.Unlock()

	return session
}

// HTML rendering methods

// renderRegisterOrLoginPage renders the login page, when there is no session yet
func (s *Server) renderRegisterOrLoginPage(w http.ResponseWriter, r *http.Request) {

	isEnglish := strings.HasSuffix(r.URL.Path, "/en")
	templateName := "register_or_login"
	if isEnglish {
		templateName = "register_or_login_en"
	}

	s.html.Render(w, templateName, nil)

}

// renderWelcomePage renders the welcome page, displaying the certificate information
func (s *Server) renderWelcomePage(w http.ResponseWriter, r *http.Request, session *models.RPSession) {

	isEnglish := strings.HasSuffix(r.URL.Path, "/en")

	var idTokenClaims models.ELSI_IDTokenClaims
	token, _, err := jwt.NewParser().ParseUnverified(session.IDToken, &idTokenClaims)
	if err != nil {
		slog.Error("Failed to parse ID token", "error", err)
		return
	}

	_ = token

	fmt.Printf("ID token claims: %+v\n", idTokenClaims)

	certInfo := map[string]string{
		"organization":     idTokenClaims.Organization,
		"organization_id":  idTokenClaims.OrganizationIdentifier,
		"common_name":      idTokenClaims.Name,
		"email":            idTokenClaims.Email,
		"country":          idTokenClaims.Country,
		"locality":         idTokenClaims.Locality,
		"province":         idTokenClaims.Province,
		"certificate_type": idTokenClaims.CertificateType,
		"valid_from":       time.Unix(idTokenClaims.IssuedAt, 0).Format("2006-01-02 15:04:05"),
		"valid_to":         time.Unix(idTokenClaims.Expiration, 0).Format("2006-01-02 15:04:05"),
	}

	idTokenClaims.ValidFromStr = time.Unix(idTokenClaims.ValidFrom, 0).Format("2006-01-02 15:04:05")
	idTokenClaims.ValidToStr = time.Unix(idTokenClaims.ValidTo, 0).Format("2006-01-02 15:04:05")

	data := map[string]any{
		"session":  session,
		"certInfo": certInfo,
		"subject":  idTokenClaims,
	}

	templateName := "welcome"
	if isEnglish {
		templateName = "welcome_en"
	}

	s.html.Render(w, templateName, data)

}

// renderErrorPage renders the error page
func (s *Server) renderErrorPage(w http.ResponseWriter, r *http.Request, error, description string) {

	isEnglish := strings.HasSuffix(r.URL.Path, "/en")

	data := map[string]any{
		"error":       error,
		"description": description,
	}

	templateName := "error"
	if isEnglish {
		templateName = "error_en"
	}

	s.html.Render(w, templateName, data)

}
