package certauth

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyCertificate(t *testing.T) {
	// 1. Read the info.txt file
	cert, err := os.ReadFile("./testdata/cert.txt")
	if err != nil {
		t.Fatalf("Failed to read cert.txt: %v", err)
	}

	// 2. Call VerifyCertificate
	resp, errService, errValidation := VerifyCertificate(string(cert), "https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/services/rest/certificate-validation/validateCertificate")
	if errService != nil {
		t.Fatalf("VerifyCertificate service failure: %v", errService)
	}
	if errValidation != nil {
		t.Fatalf("VerifyCertificate validation failure: %v", errValidation)
	}

	// 3. Validate response is JSON
	if !json.Valid(resp) {
		t.Error("Response is not valid JSON")
	}
}
