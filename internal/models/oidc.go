// Package models defines the data structures and types used across the application.
package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AuthorizationRequest represents an OAuth2 authorization request sent from the RP
type AuthorizationRequest struct {
	ResponseType string `json:"response_type"`
	ClientID     string `json:"client_id"`
	RedirectURI  string `json:"redirect_uri"`
	// Scope        string `json:"scope"`
	Scopes    []string
	State     string `json:"state"`
	Nonce     string `json:"nonce,omitempty"`
	UILocales string `json:"ui_locales,omitempty"`
	CreatedAt time.Time
}

// RelyingParty represents a registered OIDC relying party
type RelyingParty struct {
	ID               int       `json:"id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	ClientID         string    `json:"client_id"`
	ClientSecretHash string    `json:"-"` // Never expose in JSON
	RedirectURL      string    `json:"redirect_url"`
	Scopes           string    `json:"scopes"`
	TokenExpiry      int       `json:"token_expiry"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// AuthProcess holds the info during the whole application authorization process for a given RP
type AuthProcess struct {
	Code                  string           `json:"code"`
	ClientID              string           `json:"client_id"`
	RedirectURI           string           `json:"redirect_uri"`
	State                 string           `json:"state"`
	Nonce                 string           `json:"nonce"`
	UILocales             string           `json:"ui_locales,omitempty"`
	Scopes                []string         `json:"scopes"`
	CreatedAt             time.Time        `json:"created_at"`
	ExpiresAt             time.Time        `json:"expires_at"`
	CertificateData       *CertificateData `json:"certificate_data,omitempty"`
	Powers                string           `json:"powers,omitempty"`
	Email                 string           `json:"email,omitempty"`
	EmailVerificationCode string           `json:"email_verification_code,omitempty"`
	EmailVerified         bool             `json:"email_verified,omitempty"`
	ConsentGiven          bool             `json:"consent_given,omitempty"`
	WalletAuthRequest     string           `json:"wallet_auth_request,omitempty"`
	CredentialData        map[string]any   `json:"credential_data,omitempty"`
	FinishedWalletAuth    bool             `json:"finished_wallet_auth,omitempty"`
	ErrorInProcess        error            `json:"-"`
}

// SSOSession represents a single sign-on session, stored in-memory in the server
// This supports several RPs using the same certificate without having to re-authenticate the user.
type SSOSession struct {
	SessionID       string           `json:"session_id"`
	CertificateData *CertificateData `json:"certificate_data,omitempty"`
	Powers          string           `json:"powers,omitempty"`
	Email           string           `json:"email,omitempty"`
}

// TokenRequest represents a token exchange request
type TokenRequest struct {
	GrantType    string `form:"grant_type"`
	Code         string `form:"code"`
	CodeVerifier string `form:"code_verifier"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id"`
}

// IDToken represents an OpenID Connect ID token
type IDToken struct {
	Issuer          string         `json:"iss"`
	Subject         string         `json:"sub"`
	Audience        string         `json:"aud"`
	Expiration      int64          `json:"exp"`
	IssuedAt        int64          `json:"iat"`
	Nonce           string         `json:"nonce,omitempty"`
	AccessTokenHash string         `json:"at_hash,omitempty"`
	CustomClaims    map[string]any `json:"custom_claims"`
}

// TokenResponse represents an OAuth2 response to the token endpoint
type TokenResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	Scope       string         `json:"scope"`
	Claims      map[string]any `json:"claims"`
	IdToken     string         `json:"id_token,omitempty"`
}

// RPSession represents a user session in the example RP
type RPSession struct {
	SessionID     string           `json:"session_id"`
	UserID        string           `json:"user_id"`
	UserInfo      *CertificateData `json:"user_info"`
	AccessToken   string           `json:"access_token"`
	IDToken       string           `json:"id_token"`
	CreatedAt     time.Time        `json:"created_at"`
	LastAccessed  time.Time        `json:"last_accessed"`
	IDTokenClaims jwt.MapClaims    `json:"id_token_claims"`
}

type ELSI_IDTokenClaims struct {
	Audience               string `json:"aud"`
	CertificateType        string `json:"elsi_certificate_type"`
	Country                string `json:"country"`
	Organization           string `json:"organization"`
	OrganizationalUnit     string `json:"organizational_unit"`
	OrganizationIdentifier string `json:"organization_identifier"`
	SerialNumber           string `json:"serial_number"`
	Expiration             int64  `json:"exp"`
	IssuedAt               int64  `json:"iat"`
	Issuer                 string `json:"iss"`
	Name                   string `json:"name"`
	Nonce                  string `json:"nonce"`
	Subject                string `json:"sub"`
	CommonName             string `json:"common_name"`
	Surname                string `json:"surname"`
	FamilyName             string `json:"family_name"`
	GivenName              string `json:"given_name"`
	Email                  string `json:"email"`
	Locality               string `json:"locality"`
	Province               string `json:"province"`
	StreetAddress          string `json:"street_address"`
	PostalCode             string `json:"postal_code"`
	ValidFrom              int64  `json:"valid_from"`
	ValidTo                int64  `json:"valid_to"`
	ValidFromStr           string `json:"-"`
	ValidToStr             string `json:"-"`
}

func (c *ELSI_IDTokenClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(c.Expiration, 0)}, nil
}

func (c *ELSI_IDTokenClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(c.IssuedAt, 0)}, nil
}

func (c *ELSI_IDTokenClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return &jwt.NumericDate{Time: time.Unix(c.IssuedAt, 0)}, nil
}

func (c *ELSI_IDTokenClaims) GetIssuer() (string, error) {
	return c.Issuer, nil
}

func (c *ELSI_IDTokenClaims) GetSubject() (string, error) {
	return c.Subject, nil
}

func (c *ELSI_IDTokenClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{c.Audience}, nil
}

// Make sure we implement the Claims interface
var _ jwt.Claims = (*ELSI_IDTokenClaims)(nil)
