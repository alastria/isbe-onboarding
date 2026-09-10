package contract

import (
	"bytes"
	"embed"
	_ "embed"
	"html/template"
	"log"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/types"
)

// Use embed to process the templates

//go:embed html/templates/*.hbs
var templates embed.FS

var tmpl *template.Template

func init() {
	var err error
	tmpl, err = template.New("contract").ParseFS(templates, "html/templates/*.hbs")
	if err != nil {
		log.Fatalf("error parsing templates: %v", err)
	}

}

// Generate creates a PDF contract from the given contract form and profile
func Generate(contractForm *models.ContractForm, profile types.Profile, certUrl string, isEnglish bool) ([]byte, error) {

	templateName := "contract_main"
	if isEnglish {
		templateName = "contract_main_en"
	}

	contractData := map[string]any{
		"formData":    contractForm,
		"profile":     profile,
		"certUrl":     certUrl,
		"countryName": countryName(contractForm.OrganizationCountry, isEnglish),
	}

	// Execute the template, passing the contract data
	var renderedHTML bytes.Buffer
	err := tmpl.ExecuteTemplate(&renderedHTML, templateName, contractData)
	if err != nil {
		return nil, errl.Errorf("error executing template: %v", err)
	}
	htmlStr := renderedHTML.String()

	// Run WeasyPrint as external process to generate PDF, using stdin and stdout
	cmd := exec.Command("weasyprint", "-", "-")
	if profile == types.PROFILE_LOCAL {
		cmd = exec.Command("docker", "run", "--rm", "-i", "weasyprint", "-", "-")
		slog.Info("using the docker container to run WeasyPrint")
	} else {
		slog.Info("using the local WeasyPrint installation")
	}

	// Set up stdin to send the HTML
	cmd.Stdin = bytes.NewReader([]byte(htmlStr))

	// Create a buffer or file to capture the PDF output
	var pdfBuffer bytes.Buffer
	cmd.Stdout = &pdfBuffer

	// Run the command
	if err := cmd.Run(); err != nil {
		return nil, errl.Errorf("error running weasyprint: %v", err)
	}

	return pdfBuffer.Bytes(), nil
}

// countryName returns the real country name (EU/EEA only) fromn the two-letter country code
func countryName(countryCode string, isEnglish bool) string {
	countries := map[string]string{
		"ES": "España",
		"FR": "Francia",
		"DE": "Alemania",
		"IT": "Italia",
		"PT": "Portugal",
		"NL": "Países Bajos",
		"BE": "Bélgica",
		"LU": "Luxemburgo",
		"AT": "Austria",
		"SE": "Suecia",
		"FI": "Finlandia",
		"DK": "Dinamarca",
		"IE": "Irlanda",
		"EL": "Grecia",
		"CY": "Chipre",
		"MT": "Malta",
		"EE": "Estonia",
		"LV": "Letonia",
		"LT": "Lituania",
		"PL": "Polonia",
		"CZ": "República Checa",
		"SK": "Eslovaquia",
		"HU": "Hungría",
		"RO": "Rumanía",
		"BG": "Bulgaria",
		"HR": "Croacia",
		"SI": "Eslovenia",
	}

	countries_en := map[string]string{
		"ES": "Spain",
		"FR": "France",
		"DE": "Germany",
		"IT": "Italy",
		"PT": "Portugal",
		"NL": "Netherlands",
		"BE": "Belgium",
		"LU": "Luxembourg",
		"AT": "Austria",
		"SE": "Sweden",
		"FI": "Finland",
		"DK": "Denmark",
		"IE": "Ireland",
		"EL": "Greece",
		"CY": "Cyprus",
		"MT": "Malta",
		"EE": "Estonia",
		"LV": "Latvia",
		"LT": "Lithuania",
		"PL": "Poland",
		"CZ": "Czech Republic",
		"SK": "Slovakia",
		"HU": "Hungary",
		"RO": "Romania",
		"BG": "Bulgaria",
		"HR": "Croatia",
		"SI": "Slovenia",
	}

	if isEnglish {
		country, ok := countries_en[strings.ToUpper(strings.TrimSpace(countryCode))]
		if !ok {
			return countryCode
		}
		return country

	} else {
		country, ok := countries[strings.ToUpper(strings.TrimSpace(countryCode))]
		if !ok {
			return countryCode
		}
		return country

	}
}
