package tsaservice

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/jpath"
)

const defaultEUDSSURL = "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate"

type EUDSSVerifyCertificateRequest struct {
	Certificate struct {
		EncodedCertificate string `json:"encodedCertificate"`
	} `json:"certificate"`
	TokenExtractionStrategy string `json:"tokenExtractionStrategy"`
}

// VerifyCertificate verifies a certificate using the EUDSS service.
func VerifyCertificate(data []byte) ([]byte, error) {
	req := EUDSSVerifyCertificateRequest{
		Certificate: struct {
			EncodedCertificate string `json:"encodedCertificate"`
		}{
			EncodedCertificate: string(data),
		},
		TokenExtractionStrategy: "NONE",
	}

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, errl.Errorf("failed to marshal EUDSS request: %w", err)
	}

	// We use a timeout of 30 seconds
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Post(defaultEUDSSURL, "application/json", bytes.NewBuffer(jsonReq))
	if err != nil {
		return nil, errl.Errorf("failed to send EUDSS request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errl.Errorf("EUDSS request failed with status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errl.Errorf("failed to read EUDSS response: %w", err)
	}

	// Parse response as a map[string]any
	var respMap map[string]any
	if err := json.Unmarshal(body, &respMap); err != nil {
		return nil, errl.Errorf("failed to unmarshal EUDSS response: %w", err)
	}

	// Get the simpleCertificateReport object
	simpleCertificateReport := jpath.GetMap(respMap, "simpleCertificateReport")
	if simpleCertificateReport == nil {
		return nil, errl.Errorf("simpleCertificateReport not found in EUDSS response")
	}

	// Get the ChainItem array
	chainItemArray := jpath.GetList(simpleCertificateReport, "ChainItem")
	if chainItemArray == nil {
		return nil, errl.Errorf("ChainItem not found in EUDSS response")
	}

	// All objects of the list must have a field "Indication": "PASSED"
	for _, chainItem := range chainItemArray {
		indication := jpath.GetString(chainItem, "Indication")
		if indication != "PASSED" {
			// Get the subject object
			subject := jpath.GetMap(chainItem, "subject")
			// Log the subject
			out, _ := json.Marshal(subject)
			slog.Error("Validation error for certificate", "subject", string(out))
			return nil, errl.Errorf("validation error for certificate %s", string(out))
		}
	}

	return body, nil
}
