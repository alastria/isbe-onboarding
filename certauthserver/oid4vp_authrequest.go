package certauth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/golang-jwt/jwt/v5"
)

type OID4VPAuthRequest struct {
	jwt.RegisteredClaims
	Scope          string `json:"scope,omitempty"`
	ResponseType   string `json:"response_type,omitempty"`
	ResponseMode   string `json:"response_mode,omitempty"`
	ClientId       string `json:"client_id,omitempty"`
	ClientIdScheme string `json:"client_id_scheme,omitempty"`
	ResponseUri    string `json:"response_uri,omitempty"`
	State          string `json:"state,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
}

func (o *OID4VPAuthRequest) String() string {
	out, _ := json.MarshalIndent(o, "", "  ")
	return string(out)
}

// createJWTSecuredAuthenticationRequest creates an Authorization Request Object according to:
// "IETF RFC 9101: The OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)""
func (s *CertAuthServer) createJWTSecuredAuthenticationRequest(response_uri string, state string) (string, error) {

	// This specifies the type of credential that the Verifier will accept
	// TODO: In this use case it is hardcoded, which is enough if the Verifier is simple and uses
	// only one type of credential for authenticating its users.

	verifierDID := "did:elsi:VATES:55555555"

	now := time.Now()

	// Create claims with multiple fields populated
	claims := OID4VPAuthRequest{
		Scope:          "LEARCredentialEmployee", // We do not use a DCL Query, as this is simpler
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post",
		ClientId:       verifierDID,
		ClientIdScheme: "did",
		ResponseUri:    response_uri,
		State:          state,
		Nonce:          GenerateNonce(),
	}

	// Expires in one year.
	// TODO: make it configurable
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(24 * 365 * time.Hour))

	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.NotBefore = jwt.NewNumericDate(now)
	claims.Issuer = verifierDID
	claims.Audience = jwt.ClaimStrings{"https://self-issued.me/v2"}
	claims.ID = GenerateNonce()

	// As per the OID4VP
	header := map[string]any{
		"typ": "oauth-authz-req+jwt",
		"kid": s.jwtService.IssuerDID(),
	}

	tokenString, err := s.jwtService.GenerateToken(header, claims)
	if err != nil {
		return "", errl.Errorf("error generating and signing token: %w", err)
	}

	return tokenString, nil

}

func GenerateNonce() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	nonce := base64.RawURLEncoding.EncodeToString(b)
	return nonce
}
