package tsaservice

import (
	"fmt"
	"os"
	"testing"
)

func TestTimestampAndVerify(t *testing.T) {
	// Skip if manual or CI without net? Assuming we can run it.
	// We need environment variables or just default to the hardcoded ones for this test task?
	// The service.go has defaults.

	cfg := TSAConfig{
		TSAURL:      "",
		TSAUser:     "",
		TSAPassword: "",
		CACertURL:   "",
	}

	svc, err := NewTSAService(&cfg)
	if err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}

	data := []byte("Hello, World! This is a test for timestamping.")

	tsr, err := svc.Timestamp(data)
	if err != nil {
		t.Fatalf("Timestamp failed: %v", err)
	}

	ll := len(tsr)
	fmt.Printf("Length: %d\n", ll)

	// Save TSR for debugging if needed
	if os.Getenv("DEBUG_TSR") != "" {
		os.WriteFile("debug.tsr", tsr, 0644)
	}

	_, err = svc.Verify(tsr, data)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}
