package tsaservice

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyEUDSS(t *testing.T) {
	// 1. Read the info.txt file
	cert, err := os.ReadFile("../eudss/cert.txt")
	if err != nil {
		t.Fatalf("Failed to read cert.txt: %v", err)
	}

	// 4. Call VerifyEUDSS
	resp, err := VerifyCertificate([]byte(cert))
	if err != nil {
		t.Fatalf("VerifyEUDSS failed: %v", err)
	}

	// 5. Validate success status (implied by err == nil, but let's be sure about the content if needed,
	// though the requirement is just 'successful status' which usually means the HTTP call didn't return error
	// and VerifyEUDSS returns error on non-200)

	// 6. Validate response is JSON
	if !json.Valid(resp) {
		t.Error("Response is not valid JSON")
	}
}
