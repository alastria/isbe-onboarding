// Package jwtservice provides functionality for generating, signing, and verifying JSON Web Tokens (JWT).
package jwtservice

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/jpath"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/golang-jwt/jwt/v5"

	ssicrypto "github.com/hesusruiz/eudiw-ssi-go/crypto"
	didkey "github.com/hesusruiz/eudiw-ssi-go/did/key"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

// JWTService handles JWT token generation
type JWTService struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
	issuer     string
	issuerdid  string
}

// New creates a new JWT service
func New(issuer string) (*JWTService, error) {

	// Generate EC key pair for token signing
	// This is efemeral and only valid while the server is up.
	// This is on purpose, as it should be used only to sign short-lived access tokens
	// If the server fails during an authentication process, the process has to be started from the beginning

	privKey1, did, err := didkey.GenerateDIDKey(ssicrypto.P256)
	if err != nil {
		return nil, errl.Errorf("failed to generate DID key: %w", err)
	}

	privKey, ok := privKey1.(ecdsa.PrivateKey)
	if !ok {
		return nil, errl.Errorf("failed to generate DID key: %w", err)
	}
	privateKey := &privKey
	publicKey := &privateKey.PublicKey

	slog.Info("JWT service initialized", "issuer", issuer, "did", did.String())
	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		issuerdid:  did.String(),
	}, nil
}

// GenerateIDTokenForCert generates an OpenID Connect ID token
func (s *JWTService) GenerateIDTokenForCert(authProcess *models.AuthProcess, certData *models.CertificateData, rp *models.RelyingParty) (string, error) {
	now := time.Now()

	// Determine the sub identifier based on certificate type
	var sub string
	if certData.Subject.OrganizationIdentifier != "" {
		sub = certData.Subject.OrganizationIdentifier
	} else {
		// For personal certificates, use serial number or generate a unique identifier
		if certData.Subject.SerialNumber != "" {
			sub = certData.Subject.SerialNumber
		} else if certData.Subject.CommonName != "" {
			sub = certData.Subject.CommonName + "_" + certData.Subject.SerialNumber
		} else {
			// Fallback: generate a hash based on certificate data
			sub = fmt.Sprintf("%s_%s_%s",
				certData.Subject.GivenName,
				certData.Subject.Surname,
				certData.Subject.SerialNumber)
		}
	}

	// Standard OIDC claims
	claims := jwt.MapClaims{
		// Standard claims
		"iss":   s.issuer,                                                    // Issuer
		"sub":   sub,                                                         // Subject (org ID or personal identifier)
		"aud":   rp.ClientID,                                                 // Audience
		"exp":   now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix(), // Expiration
		"iat":   now.Unix(),                                                  // Issued at
		"nonce": authProcess.Nonce,                                           // Nonce (if provided)
	}

	// Add standard claims from certificate if available
	if certData.Subject.Organization != "" {
		claims["name"] = certData.Subject.Organization
	} else if certData.Subject.CommonName != "" {
		claims["name"] = certData.Subject.CommonName
	}

	if certData.Subject.GivenName != "" {
		claims["given_name"] = certData.Subject.GivenName
	}
	if certData.Subject.Surname != "" {
		claims["family_name"] = certData.Subject.Surname
	}

	claims["user"] = certData.Subject.GivenName + " " + certData.Subject.Surname

	claims["email"] = authProcess.Email
	claims["email_verified"] = true

	claims["eidas_cert"] = certData.CertificateDER

	claims["organization_identifier"] = certData.Subject.OrganizationIdentifier

	if certData.Subject.Organization != "" {
		claims["organization"] = certData.Subject.Organization
	}
	if certData.Subject.OrganizationalUnit != "" {
		claims["organizational_unit"] = certData.Subject.OrganizationalUnit
	}
	if certData.Subject.CommonName != "" {
		claims["common_name"] = certData.Subject.CommonName
	}
	if certData.Subject.Locality != "" {
		claims["locality"] = certData.Subject.Locality
	}
	if certData.Subject.Province != "" {
		claims["province"] = certData.Subject.Province
	}
	if certData.Subject.StreetAddress != "" {
		claims["street_address"] = certData.Subject.StreetAddress
	}
	if certData.Subject.PostalCode != "" {
		claims["postal_code"] = certData.Subject.PostalCode
	}
	if certData.Subject.SerialNumber != "" {
		claims["serial_number"] = certData.Subject.SerialNumber
		claims["user_identifier"] = certData.Subject.SerialNumber
	}
	if certData.Subject.Country != "" {
		claims["country"] = certData.Subject.Country
	}

	claims["valid_from"] = certData.ValidFrom.Unix()
	claims["valid_to"] = certData.ValidTo.Unix()

	// Add certificate type information
	claims["elsi_certificate_type"] = certData.CertificateType

	// Add signed annex information
	claims["power"] = authProcess.Powers

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", errl.Errorf("failed to sign ID token: %w", err)
	}

	slog.Debug("ID token generated",
		"subject", claims["sub"],
		"audience", claims["aud"],
		"expiration", claims["exp"],
	)

	return tokenString, nil
}

func (s *JWTService) GenerateIDTokenForCredential(authProcess *models.AuthProcess, cred map[string]any, rp *models.RelyingParty) (string, error) {
	now := time.Now()

	mandator := jpath.GetMap(cred, "credentialSubject.mandate.mandator")
	if len(mandator) == 0 {
		return "", errl.Errorf("mandator not found in credential")
	}

	mandatee := jpath.GetMap(cred, "credentialSubject.mandate.mandatee")
	if len(mandator) == 0 {
		return "", errl.Errorf("mandatee not found in credential")
	}

	// Subject is the organization identifier of the Mandator
	sub := jpath.GetString(mandator, "organizationIdentifier")
	if sub == "" {
		return "", errl.Errorf("organizationIdentifier not found in credential")
	}

	// Standard OIDC claims
	claims := jwt.MapClaims{
		// Standard claims
		"iss":   s.issuer,                                                    // Issuer
		"sub":   sub,                                                         // Subject (org ID or personal identifier)
		"aud":   rp.ClientID,                                                 // Audience
		"exp":   now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix(), // Expiration
		"iat":   now.Unix(),                                                  // Issued at
		"nonce": authProcess.Nonce,                                           // Nonce (if provided)
	}

	claims["name"] = jpath.GetString(mandator, "organization")

	claims["given_name"] = jpath.GetString(mandatee, "firstName")
	claims["family_name"] = jpath.GetString(mandatee, "lastName")

	email := jpath.GetString(mandatee, "email")
	if email != "" {
		claims["email"] = email
		claims["email_verified"] = true
	} else {
		email = jpath.GetString(mandator, "emailAddress")
		if email != "" {

			claims["email"] = email
			claims["email_verified"] = true
		}
	}

	claims["organization_identifier"] = jpath.GetString(mandator, "organizationIdentifier")
	claims["organization"] = jpath.GetString(mandator, "organization")
	claims["organizational_unit"] = jpath.GetString(mandator, "organizationalUnit")
	claims["common_name"] = jpath.GetString(mandator, "commonName")

	claims["country"] = jpath.GetString(mandator, "country")

	claims["vc"] = cred

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", errl.Errorf("failed to sign ID token: %w", err)
	}

	slog.Debug("ID token generated",
		"subject", claims["sub"],
		"audience", claims["aud"],
		"expiration", claims["exp"],
	)

	return tokenString, nil
}

// generateELSIClaims generates custom elsi_ claims for ETSI standardized fields
func (s *JWTService) generateELSIClaims(certData *models.CertificateData) map[string]any {
	claims := make(map[string]any)

	// Map certificate fields to elsi_ claims
	if certData.Subject.Organization != "" {
		claims["organization"] = certData.Subject.Organization
	}
	if certData.Subject.OrganizationalUnit != "" {
		claims["organizational_unit"] = certData.Subject.OrganizationalUnit
	}
	if certData.Subject.CommonName != "" {
		claims["common_name"] = certData.Subject.CommonName
	}
	if certData.Subject.Locality != "" {
		claims["locality"] = certData.Subject.Locality
	}
	if certData.Subject.Province != "" {
		claims["province"] = certData.Subject.Province
	}
	if certData.Subject.StreetAddress != "" {
		claims["street_address"] = certData.Subject.StreetAddress
	}
	if certData.Subject.PostalCode != "" {
		claims["postal_code"] = certData.Subject.PostalCode
	}
	if certData.Subject.SerialNumber != "" {
		claims["serial_number"] = certData.Subject.SerialNumber
	}
	if certData.Subject.Country != "" {
		claims["country"] = certData.Subject.Country
	}
	// Always include the organization identifier
	claims["organization_identifier"] = certData.Subject.OrganizationIdentifier

	claims["valid_from"] = certData.ValidFrom.Unix()
	claims["valid_to"] = certData.ValidTo.Unix()

	return claims
}

// GetPublicKey returns the public key in PEM format for JWKS
func (s *JWTService) GetPublicKey() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return "", errl.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return string(pem.EncodeToMemory(pemBlock)), nil
}

// GetJWKS returns the JSON Web Key Set
func (s *JWTService) GetJWKS() map[string]any {

	jk, err := jwk.Import(s.publicKey)
	if err != nil {
		return nil
	}

	jk.Set("use", "sig")
	jk.Set(jwk.KeyIDKey, "certauth-key")
	jk.Set(jwk.AlgorithmKey, "ES256")

	jwks := map[string]any{
		"keys": []any{jk},
	}
	return jwks
}

// GenerateSSOCookieToken generates a JWT token for the SSO cookie
func (s *JWTService) GenerateSSOCookieToken(claims jwt.MapClaims) (string, error) {
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", errl.Errorf("failed to sign sso token: %w", err)
	}

	return tokenString, nil
}

func (s *JWTService) GenerateToken(header map[string]any, claims jwt.Claims) (string, error) {
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	maps.Copy(token.Header, header)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", errl.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// Issuer returns the issuer of the JWT
func (s *JWTService) Issuer() string {
	return s.issuer
}

// IssuerDID return the DID associated to the issuer
func (s *JWTService) IssuerDID() string {
	return s.issuerdid
}

// ParseSSOCookieToken parses a JWT token from the SSO cookie
func (s *JWTService) ParseSSOCookieToken(tokenString string) (jwt.MapClaims, error) {
	if tokenString == "" {
		return nil, errl.Errorf("empty sso token")
	}

	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, errl.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return s.publicKey, nil
	})

	if err != nil {
		return nil, errl.Errorf("failed to parse sso token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errl.Errorf("invalid sso token")
}
