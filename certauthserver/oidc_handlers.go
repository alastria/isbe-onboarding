package certauth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"
	jwtV5 "github.com/golang-jwt/jwt/v5"
)

const (
	oidc_configuration     = "/.well-known/openid-configuration"
	authorization_endpoint = "/oauth2/auth"
	token_endpoint         = "/oauth2/token"
	// userinfo_endpoint      = "/oauth2/userinfo"
	jwks_uri = "/.well-known/jwks.json"

	loginEndpoint  = "/login"
	logoutEndpoint = "/logout"
)

func (s *CertAuthServer) registerOIDCHandlers() {

	// The discovery endpoints, where the Relying Party can retrieve information about the server
	s.httpServer.Get(oidc_configuration, s.APIDiscovery)
	s.httpServer.Get(jwks_uri, s.APIJWKS)

	// The authorization endpoint, where the Relying Party redirects the user to initiate the authentication process
	s.httpServer.Get(authorization_endpoint, s.Authorization)

	// The login page displaying to the user the possible user authentication methods (certificate, wallet)
	s.httpServer.Get(loginEndpoint, s.PageLogin)

	// The token endpoint, where the Relying Party exchanges the authorization code for an access token
	s.httpServer.Post(token_endpoint, s.APITokenExchange)

	// The logout endpoint, where the Relying Party can invalidate the access token
	s.httpServer.Get(logoutEndpoint, s.Logout)

}

// APIDiscovery handles the discovery endpoint, where the Relying Party can retrieve information about the server
func (s *CertAuthServer) APIDiscovery(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"issuer":                 s.certAuthURL,
		"authorization_endpoint": s.certAuthURL + authorization_endpoint,
		"token_endpoint":         s.certAuthURL + token_endpoint,
		// "userinfo_endpoint":                     s.cfg.CertAuthURL + userinfo_endpoint,
		"jwks_uri":                              s.certAuthURL + jwks_uri,
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"ES256"},
		"scopes_supported":                      []string{"openid", "eidas", "learcredential", "learcred"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "given_name", "family_name", "email", "organization", "organization_identifier", "country"},
	})
}

// APIJWKS handles the JSON Web Key Set endpoint
func (s *CertAuthServer) APIJWKS(c *fiber.Ctx) error {
	jwks := s.jwtService.GetJWKS()
	return c.JSON(jwks)
}

// Authorization handles OAuth2 authorization endpoint.
// This is the first step of the authorization process.
// We support two types of authorization: with an eIDAS certificate and with a Verifiable Credential
func (s *CertAuthServer) Authorization(c *fiber.Ctx) error {

	// Parse authorization request
	authReq := &models.AuthorizationRequest{
		ResponseType: utils.CopyString(c.Query("response_type")),
		ClientID:     utils.CopyString(c.Query("client_id")),
		RedirectURI:  utils.CopyString(c.Query("redirect_uri")),
		// Scope:        utils.CopyString(c.Query("scope")),
		Scopes:    strings.Fields(c.Query("scope")),
		State:     utils.CopyString(c.Query("state")),
		Nonce:     utils.CopyString(c.Query("nonce")),
		UILocales: utils.CopyString(c.Query("ui_locales")),
		CreatedAt: time.Now(),
	}

	slog.Info("Authorization request received",
		"response_type", authReq.ResponseType,
		"client_id", authReq.ClientID,
		"redirect_uri", authReq.RedirectURI,
		"scope", c.Query("scope"),
		"state", authReq.State,
		"nonce", authReq.Nonce,
		"ui_locales", authReq.UILocales,
	)

	// Validate request
	if errorCode, errorDesc := s.validateAuthorizationRequest(authReq); errorCode != "" {
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// The relying party must have been registered previously
	rp, err := s.db.GetRelyingParty(authReq.ClientID)
	if err != nil {
		errorCode := "server_error"
		errorDesc := fmt.Sprintf("database error: %s", err.Error())
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}
	if rp == nil {
		errorCode := "unauthorized_client"
		errorDesc := fmt.Sprintf("invalid client_id: %s", authReq.ClientID)
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Validate redirect_uri matches registered RP redirect URL
	// For security reasons, the redirect_uri must be the same as the one that was registered
	if authReq.RedirectURI != rp.RedirectURL {
		errorCode := "invalid_request"
		errorDesc := fmt.Sprintf("invalid redirect_uri: %s", authReq.RedirectURI)
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Check if certificate authentication is requested with scope 'eidas', 'onlyeidas' or 'learcred'
	if !slices.Contains(authReq.Scopes, "eidas") && !slices.Contains(authReq.Scopes, "onlyeidas") && !slices.Contains(authReq.Scopes, "learcred") {
		errorCode := "invalid_scope"
		errorDesc := "the server requires scope eidas, learcred or eidasonly"
		return s.handleAuthorizationError(c, authReq.RedirectURI, authReq.State, errorCode, errorDesc)
	}

	// Check if we received the SSO cookie that we generated in a possible recent authentication
	ssoCookie := c.Cookies("__Http-sso_certauth")
	var ssoClaims jwtV5.MapClaims
	if ssoCookie != "" {
		ssoClaims, err = s.jwtService.ParseSSOCookieToken(ssoCookie)
		if err != nil {
			slog.Debug("Invalid SSO cookie received, proceeding with normal flow", "error", errl.Error(err))
		}
	} else {
		slog.Debug("No SSO cookie received, proceeding with normal flow")
	}

	var ssoSession *models.SSOSession
	// If received a valid SSO cookie, may bypass certificate selection
	if ssoClaims != nil {

		slog.Debug("Valid SSO cookie received", "subject", ssoClaims["sub"])

		// Retrieve the SSO session ID from the claims
		ssoSessionID, _ := ssoClaims["session_id"].(string)
		if ssoSessionID == "" {
			slog.Warn("No SSO session ID found in claims, proceeding with normal flow")
		}

		ssoSessionCached, found := s.ssoCache.Get(ssoSessionID)
		if !found {
			slog.Warn("SSO session not found in cache, proceeding with normal flow", "sso_session_id", ssoSessionID)
		} else {
			ssoSession = ssoSessionCached
		}

		// Retrieve the SSO session data from the cache corresponding to that session id
		// ssoSessionIntf, found := s.cache.Get(ssoSessionID)
		// if !found {
		// 	slog.Warn("SSO session not found in cache, proceeding with normal flow", "sso_session_id", ssoSessionID)
		// } else {
		// 	ss, ok := ssoSessionIntf.(*models.SSOSession)
		// 	if !ok {
		// 		slog.Warn("Invalid SSO session type in cache, proceeding with normal flow", "sso_session_id", ssoSessionID)
		// 	} else {
		// 		ssoSession = ss
		// 	}
		// }

	}

	// Generate an authorization code for this RP authentication process.
	// The code is associated to an authorization process object which will be used to track
	// the whole set of interactions with the user.
	authProcess := s.generateAuthProcess(authReq, rp)

	// Store the authorization process struct in a cache with a reasonable expiration time (currently hardcoded to 15 min)
	// It will hold the certificate data once it is received by the certsec handler
	// The key is the unique authorization code used in the OAUth authorithation code flow, which will be
	// passed around the endpoints to associate with the in-memory authorization proces object.
	// TODO: maybe create a unique id specific for this purpose, and only send the auth code when it is required.
	// s.cache.Set(authProcess.Code, authProcess, 15*time.Minute)
	s.authprocCache.Set(authProcess.Code, authProcess, 15*time.Minute)

	if ssoSession != nil {

		// Bypass certificate selection and return directly to caller
		slog.Debug("bypassing certificate selection", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store certificate data, email of the user and powers in the authProcess struct
		authProcess.CertificateData = ssoSession.CertificateData
		authProcess.Email = ssoSession.Email
		authProcess.Powers = ssoSession.Powers

		// And redirect back to the caller
		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	} else {

		// No valid SSO cookie, proceed with normal flow

		// We pass the auth code so we will be able to retrieve the in-memory auth process object later
		// TODO: include redirection logic based on Relying Party configuration
		if slices.Contains(authReq.Scopes, "onlyeidas") || slices.Contains(authReq.Scopes, "eidas") {
			slog.Info("Redirection to ONLY Certificate login")
			return c.Redirect("/cert/login?code="+authProcess.Code, fiber.StatusFound)
		}
		slog.Info("Redirection to BOTH Certificate and Wallet login")
		return c.Redirect(loginEndpoint+"?code="+authProcess.Code, fiber.StatusFound)

	}

}

func (s *CertAuthServer) PageLogin(c *fiber.Ctx) error {
	slog.Info("Login page", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	data := map[string]any{
		"authCode": authProcess.Code,
	}
	slog.Debug("Login page", "data", data)

	templateName := "login"
	if authProcess.UILocales == "en" {
		templateName = "login_en"
	}

	return s.htmlRender.Render(c, templateName, data)

}

// APITokenExchange handles OAuth2 token endpoint.
// This is the last step for the RP in the authentication flow.
func (s *CertAuthServer) APITokenExchange(c *fiber.Ctx) error {

	// Parse token request
	var tokenReq models.TokenRequest
	if err := c.BodyParser(&tokenReq); err != nil {
		return errl.Errorf("invalid request body: %w", err)
	}

	slog.Info("Token request received", "client_id", tokenReq.ClientID, "grant_type", tokenReq.GrantType, "code", tokenReq.Code, "code_verifier", tokenReq.CodeVerifier, "redirect_uri", tokenReq.RedirectURI)

	if tokenReq.ClientID == "" {
		// We reject immediately RPs which are not authorized
		username, err := s.validateClientTokenAuthorization(c)
		if err != nil {
			return errl.Errorf("invalid authorization: %w", err)
		}

		slog.Info("Client ID retrieved from Authorization header", "client_id", username)
		// Set the user name in tokenReq
		tokenReq.ClientID = username
	}

	// Retrieve the Authorization process associated with the authCode
	authProcess, err := s.getAuthProcess(tokenReq.Code)
	if err != nil {
		err = errl.Errorf("failed to get auth process: %w", err)
		slog.Error(err.Error(), "auth_code", tokenReq.Code)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Validate received auth code against the stored one
	if authProcess.ClientID != tokenReq.ClientID {
		return errl.Errorf("auth code client mismatch")
	}

	// Get the registered relying party
	rp, err := s.db.GetRelyingParty(tokenReq.ClientID)
	if err != nil {
		return errl.Errorf("failed to get relying party: %w", err)
	}

	// Generate tokens with certificate data if available
	tokens, err := s.generateTokens(authProcess, rp)
	if err != nil {
		return errl.Errorf("failed to generate tokens: %w", err)
	}

	// Delete used auth process
	s.authprocCache.Delete(tokenReq.Code)

	slog.Info("Tokens generated successfully", "client_id", tokenReq.ClientID)

	return c.JSON(tokens)
}

// APIUserInfo handles OpenID Connect userinfo endpoint
func (s *CertAuthServer) APIUserInfo(c *fiber.Ctx) error {
	// TODO: Implement userinfo with token validation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// Logout handles logout endpoint
func (s *CertAuthServer) Logout(c *fiber.Ctx) error {
	// TODO: Implement logout (no-op for now)
	return c.JSON(fiber.Map{"status": "logged_out"})
}

// Helper methods

func (s *CertAuthServer) validateAuthorizationRequest(req *models.AuthorizationRequest) (errorCode string, errorDescription string) {
	if req.ResponseType != "code" {
		return "invalid_request", "unsupported response_type"
	}
	if req.ClientID == "" {
		return "invalid_request", "missing client_id"
	}
	if req.RedirectURI == "" {
		return "invalid_request", "missing redirect_uri"
	}
	if !slices.Contains(req.Scopes, "openid") {
		return "invalid_request", "openid scope required"
	}
	return "", ""
}

// validateClientTokenAuthorization validates the authorization header for the token endpoint, for a registered RP.
// It returns the client ID and an error if the authorization is invalid.
func (s *CertAuthServer) validateClientTokenAuthorization(c *fiber.Ctx) (clientid string, err error) {

	// Get authorization header
	authHeader := c.Get(fiber.HeaderAuthorization)

	// Check if the header contains content besides "basic"
	if len(authHeader) <= 6 || !utils.EqualFold(authHeader[:6], "basic ") {
		return "", errl.Errorf("invalid authorization header")
	}

	// Decode the header contents
	raw, err := base64.StdEncoding.DecodeString(authHeader[6:])
	if err != nil {
		return "", errl.Errorf("invalid authorization header: %w", err)
	}

	// Get the credentials
	creds := string(raw)

	// Check if the credentials are in the correct form
	// which is "username:password".
	index := strings.Index(creds, ":")
	if index == -1 {
		return "", errl.Errorf("invalid authorization header")
	}

	// Get the username and password
	username := creds[:index]
	password := creds[index+1:]

	// Validate client credentials
	valid, err := s.db.ValidateClientSecret(username, password)
	if err != nil {
		slog.Error("Failed to validate client secret", "error", err)
		return "", errl.Errorf("internal error")
	}
	if !valid {
		return "", errl.Errorf("invalid client credentials")
	}

	username = utils.CopyString(username)
	return username, nil
}

// handleAuthorizationError handles authorization errors by redirecting back to the RP with error details
func (s *CertAuthServer) handleAuthorizationError(c *fiber.Ctx, redirectURI, state, errorCode, errorDescription string) error {
	slog.Error("Authorization error", "error", errorCode, "redirect_uri", redirectURI)

	redirectURL, _ := url.Parse(redirectURI)
	q := redirectURL.Query()
	if state != "" {
		q.Set("state", state)
	}
	q.Set("error", errorCode)
	q.Set("error_description", errorDescription)
	redirectURL.RawQuery = q.Encode()

	return c.Status(fiber.StatusFound).Redirect(redirectURL.String())
}

func (s *CertAuthServer) generateAuthProcess(req *models.AuthorizationRequest, rp *models.RelyingParty) *models.AuthProcess {
	// Generate random code
	codeBytes := make([]byte, 32)
	rand.Read(codeBytes)
	code := base64.URLEncoding.EncodeToString(codeBytes)

	authCode := &models.AuthProcess{
		Code:        code,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		State:       req.State,
		Nonce:       req.Nonce,
		UILocales:   req.UILocales,
		Scopes:      req.Scopes,
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	}

	slog.Debug("Generated auth code", "code", authCode.Code, "client_id", authCode.ClientID, "redirect_uri", authCode.RedirectURI)
	return authCode
}

func (s *CertAuthServer) generateTokens(authProcess *models.AuthProcess, rp *models.RelyingParty) (map[string]any, error) {

	if authProcess.CertificateData == nil && authProcess.CredentialData == nil {
		err := errl.Errorf("no credential or certificate data found in auth process")
		slog.Error(err.Error(), "auth_code", authProcess.Code)
		return nil, err
	}

	if authProcess.CertificateData != nil {
		// Authentication performed with a certificate

		certData := authProcess.CertificateData

		// Generate ID token
		idToken, err := s.jwtService.GenerateIDTokenForCert(authProcess, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}
		slog.Debug("ID Token", "token", idToken)

		tokenString, err := s.jwtService.GenerateAccessTokenForCert(authProcess, certData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}
		slog.Debug("Access Token", "token", tokenString)

		slog.Info("JWT tokens generated with certificate data",
			"organization_id", certData.OrganizationID,
			"organization", certData.Subject.Organization,
		)

		return map[string]any{
			"access_token": tokenString,
			"token_type":   "Bearer",
			"expires_in":   rp.TokenExpiry,
			"scope":        strings.Join(authProcess.Scopes, " "),
			"id_token":     idToken,
		}, nil

	} else {
		// Authentication performed with a Verifiable Credential

		credData := authProcess.CredentialData

		idToken, err := s.jwtService.GenerateIDTokenForCredential(authProcess, credData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate ID token: %w", err)
		}

		tokenString, err := s.jwtService.GenerateAccessTokenForCredential(authProcess, credData, rp)
		if err != nil {
			return nil, errl.Errorf("failed to generate access token: %w", err)
		}

		slog.Info("JWT tokens generated with credential data")

		return map[string]any{
			"access_token": tokenString,
			"token_type":   "Bearer",
			"expires_in":   rp.TokenExpiry,
			"scope":        strings.Join(authProcess.Scopes, " "),
			"id_token":     idToken,
		}, nil

	}

}

func generateRandomString() string {
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)

	return base64.URLEncoding.EncodeToString(tokenBytes)
}

// generateSSOCookie generates the SSO cookie
func (s *CertAuthServer) generateSSOCookie(ssoSessionID string, certData *models.CertificateData) (*fiber.Cookie, error) {

	// Determine the sub identifier based on certificate type
	var sub string
	if certData.Subject.OrganizationIdentifier != "" {
		sub = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			sub = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			sub = certData.Subject.CommonName
		} else {
			return nil, errl.Errorf("cannot determine subject identifier for SSO cookie")
		}
	}

	// Standard OIDC claims
	claims := jwtV5.MapClaims{
		// Standard claims
		"iss":   s.jwtService.Issuer(),                 // Issuer
		"sub":   sub,                                   // Subject (org ID or personal identifier)
		"aud":   s.certAuthURL,                         // Audience
		"exp":   time.Now().Add(24 * time.Hour).Unix(), // Expiration
		"iat":   time.Now().Unix(),                     // Issued at
		"email": certData.Subject.EmailAddress,         // Email
		// Custom claims
		"session_id": ssoSessionID, // SSO session ID
	}

	// Generate the token
	token, err := s.jwtService.GenerateSSOCookieToken(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate sso token: %w", err)
	}

	// Generate SSO cookie
	cookie := new(fiber.Cookie)
	cookie.Name = "__Http-sso_certauth"
	cookie.Value = token
	// cookie.Expires = time.Now().Add(24 * time.Hour)
	cookie.Secure = true
	cookie.HTTPOnly = true
	cookie.SameSite = "Lax"
	cookie.SessionOnly = true

	// Set the domain to the main domain so it's accessible by subdomains
	u, err := url.Parse(s.certAuthURL)
	if err != nil {
		slog.Error("failed to parse cert auth url", "error", err)
	} else {
		hostname := u.Hostname()
		// Heuristic to get the naked domain.
		// This works for domains like 'example.com' and 'sub.example.com',
		// but not for 'example.co.uk'.
		if hostname != "localhost" && net.ParseIP(hostname) == nil {
			parts := strings.Split(hostname, ".")
			if len(parts) > 2 {
				hostname = strings.Join(parts[len(parts)-2:], ".")
			}
		}
		cookie.Domain = hostname
	}

	return cookie, nil
}

func (s *CertAuthServer) getAuthProcess(authCode string) (*models.AuthProcess, error) {
	if authCode == "" {
		return nil, errl.Errorf("Missing authorization code")
	}

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, found := s.authprocCache.Get(authCode)
	if !found {
		return nil, errl.Errorf("Authorization code not found in cache for auth_code: %s", authCode)
	}

	return authProcess, nil

}
