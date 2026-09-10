package certauth

import (
	"os"
	"testing"
	"time"

	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
)

func TestGetContract(t *testing.T) {
	// Initialize a minimal CertAuthServer
	s := &CertAuthServer{}

	// Initialize the template engine using the embedded filesystem
	// templateDirectory is "certauthserver/views" as defined in certauth_server.go
	// However, when running tests from the certauthserver directory, the path in embed.FS
	// might be relative to the package.
	// viewsfs embeds "views/*".
	htmlrender, err := html.NewRendererFiber(false, viewsfs, templateDirectory, templateExtension)
	if err != nil {
		t.Fatalf("Failed to initialize template engine: %v", err)
	}
	s.htmlRender = htmlrender

	// Prepare dummy data
	authCode := "test-auth-code"
	authProcess := &models.AuthProcess{
		Code:        authCode,
		RedirectURI: "https://example.com/callback",
		State:       "test-state",
		CreatedAt:   time.Now(),
		CertificateData: &models.CertificateData{
			Subject: &x509util.ELSIName{
				CommonName:   "Test User",
				Organization: "Test Org",
				Country:      "ES",
			},
		},
	}
	formData := &models.ContractForm{
		TodayDay:            9,
		TodayMonth:          4,
		TodayYear:           2026,
		OrganizationName:    "Test Org",
		OrganizationCountry: "ES",
		OrganizationAddress: "Test Address",
		OrganizationNif:     "VAT-ES-12345678X",
		RepresentativeName:  "Test User",
		RepresentativeEmail: "test@example.com",
	}

	// Call the method being tested (Spanish version)
	data, err := s.getContract(authCode, authProcess, formData, false)
	if err != nil {
		t.Errorf("getContract (Spanish) failed: %v", err)
	}
	if len(data) == 0 {
		t.Error("getContract (Spanish) returned empty data")
	}

	// Call the method being tested (English version)
	dataEn, err := s.getContract(authCode, authProcess, formData, true)
	if err != nil {
		t.Errorf("getContract (English) failed: %v", err)
	}
	if len(dataEn) == 0 {
		t.Error("getContract (English) returned empty data")
	}

	// Cleanup the generated PDF file if it exists
	if _, err := os.Stat("invoice.pdf"); err == nil {
		os.Remove("invoice.pdf")
	}
}
