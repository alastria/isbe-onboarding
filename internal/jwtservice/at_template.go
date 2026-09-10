package jwtservice

import (
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/golang-jwt/jwt/v5"
)

const at_template = `{
  "aud": "did:key:zDnaeypyWjzn54GuUP7PmDXiiggCyiG7ksMF7Unm7kjtEKBez",
  "sub": "did:key:zDnaejCht7VjsEWSkCLjzGwdwJLhukNCLAaXJ5kfsu8fihRSh",
  "scope": "openid learcredential",
  "iss": "https://verifier.dome-marketplace-sbx.org",
  "exp": 1758641125,
  "iat": 1758637525,
  "vc": {
    "@context": [
      "https://www.w3.org/ns/credentials/v2",
      "https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3"
    ],
    "credentialStatus": {
      "id": "https://issuer.dome-marketplace-sbx.org/backoffice/v1/credentials/status/1#SYC908RIQQqeUXR19nh3EQ",
      "statusListCredential": "https://issuer.dome-marketplace-sbx.org/backoffice/v1/credentials/status/1",
      "statusListIndex": "SYC908RIQQqeUXR19nh3EQ",
      "statusPurpose": "revocation",
      "type": "PlainListEntity"
    },
    "credentialSubject": {
      "mandate": {
        "mandatee": {
          "email": "roger.miret@in2.es",
          "employeeId": "A-12345678",
          "firstName": "Roger",
          "id": "did:key:zDnaejCht7VjsEWSkCLjzGwdwJLhukNCLAaXJ5kfsu8fihRSh",
          "lastName": "Miret"
        },
        "mandator": {
          "commonName": "Mandator lastname",
          "country": "Spain",
          "email": "roger.miret@in2.es",
          "id": "did:elsi:VATES-B60645900",
          "organization": "IN2 INGENIERIA DE LA INFORMACION SOCIEDAD LIMITADA",
          "organizationIdentifier": "VATES-B60645900",
          "serialNumber": ""
        },
        "power": [
          {
            "action": [
              "Execute"
            ],
            "domain": "DOME",
            "function": "Onboarding",
            "type": "domain"
          },
          {
            "action": [
              "Create",
              "Update",
              "Delete"
            ],
            "domain": "DOME",
            "function": "ProductOffering",
            "type": "domain"
          }
        ]
      }
    },
    "description": "Verifiable Credential for employees of an organization",
    "id": "urn:uuid:a5747bc5-2ba6-40f5-94b8-a8a1ec5098da",
    "issuer": {
      "commonName": "Seal Signature Credentials in SBX for testing",
      "country": "ES",
      "id": "did:elsi:VATES-B60645900",
      "organization": "IN2",
      "organizationIdentifier": "VATES-B60645900",
      "serialNumber": "B47447560"
    },
    "type": [
      "LEARCredentialEmployee",
      "VerifiableCredential"
    ],
    "validFrom": "2025-09-23T14:24:37.029200096Z",
    "validUntil": "2026-09-23T14:24:37.029200096Z"
  },
  "jti": "9710a4ee-2829-4b8a-a038-aa19ffcd3282",
  "client_id": "https://verifier.dome-marketplace-sbx.org"
}`

func (s *JWTService) GenerateAccessTokenForCert(authProcess *models.AuthProcess, certData *models.CertificateData, rp *models.RelyingParty) (string, error) {
	now := time.Now()

	iss := s.issuer
	sub := authProcess.ClientID
	aud := rp.ClientID
	exp := now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix()
	iat := now.Unix()
	nonce := authProcess.Nonce
	scope := strings.Join(authProcess.Scopes, " ")
	jti := rand.Text()

	// Standard claims
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   sub,
		"aud":   aud,
		"exp":   exp,
		"iat":   iat,
		"nonce": nonce,
		"scope": scope,
		"jti":   jti,
	}

	// Mandatee claims
	mandatee := map[string]any{
		"id":         certData.Subject.SerialNumber,
		"employeeId": certData.Subject.SerialNumber,
		"email":      authProcess.Email,
		"firstName":  certData.Subject.GivenName,
		"lastName":   certData.Subject.Surname,
	}

	mandator := map[string]any{
		"id":                     "did:elsi:" + certData.Subject.OrganizationIdentifier,
		"email":                  authProcess.Email,
		"commonName":             certData.Subject.CommonName,
		"organization":           certData.Subject.Organization,
		"organizationIdentifier": certData.Subject.OrganizationIdentifier,
		"serialNumber":           certData.Subject.SerialNumber,
		"country":                certData.Subject.Country,
	}

	power := []map[string]any{
		{
			"action":   []string{"Execute"},
			"domain":   "DOME",
			"function": "Onboarding",
			"type":     "domain",
		},
		{
			"action":   []string{"Create", "Update", "Delete"},
			"domain":   "DOME",
			"function": "ProductOffering",
			"type":     "domain",
		},
	}

	mandate := map[string]any{
		"mandatee": mandatee,
		"mandator": mandator,
		"power":    power,
	}

	vcID := "urn:uuid" + rand.Text()

	// Verifiable Credential
	vc := map[string]any{
		"id": vcID,
		"@context": []string{
			"https://www.w3.org/ns/credentials/",
			"https://credentials.eudistack.eu/.well-known/credentials/lear_credential_employee/w3c/v3",
		},
		"type": []string{
			"LEARCredentialEmployee",
			"VerifiableCredential",
		},
		"validFrom":  certData.ValidFrom.Format(time.RFC3339),
		"validUntil": certData.ValidTo.Format(time.RFC3339),

		"credentialStatus": map[string]any{
			"id":                   "https://issuer.dome-marketplace-sbx.org/backoffice/v1/credentials/status/1#SYC908RIQQqeUXR19nh3EQ",
			"statusListCredential": "https://issuer.dome-marketplace-sbx.org/backoffice/v1/credentials/status/1",
			"statusListIndex":      "SYC908RIQQqeUXR19nh3EQ",
			"statusPurpose":        "revocation",
			"type":                 "PlainListEntity",
		},
		"credentialSubject": map[string]any{
			"mandate": mandate,
		},
		"description": "Verifiable Credential for employees of an organization",
		"issuer": map[string]any{
			"commonName":             "CertAuth Identity Provider for ISBE",
			"country":                "ES",
			"id":                     "did:elsi:VATES-B60645900",
			"organization":           "IN2",
			"organizationIdentifier": "VATES-B60645900",
			"serialNumber":           "B47447560",
		},
	}

	claims["vc"] = vc

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return tokenString, nil
}

func (s *JWTService) GenerateAccessTokenForCredential(authProcess *models.AuthProcess, cred map[string]any, rp *models.RelyingParty) (string, error) {
	now := time.Now()

	iss := s.issuer
	sub := authProcess.ClientID
	aud := rp.ClientID
	exp := now.Add(time.Duration(rp.TokenExpiry) * time.Second).Unix()
	iat := now.Unix()
	nonce := authProcess.Nonce
	scope := strings.Join(authProcess.Scopes, " ")
	jti := rand.Text()

	// Standard claims
	claims := jwt.MapClaims{
		"iss":   iss,
		"sub":   sub,
		"aud":   aud,
		"exp":   exp,
		"iat":   iat,
		"nonce": nonce,
		"scope": scope,
		"jti":   jti,
	}

	claims["vc"] = cred

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Sign token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %w", err)
	}

	return tokenString, nil
}
