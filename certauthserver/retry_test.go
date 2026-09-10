package certauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyCertificateRetries(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		// Return error for the first two attempts
		if atomic.LoadInt32(&attempts) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Return success for the third attempt
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"simpleCertificateReport": {"Certificate": {"Indication": "PASSED"}, "ChainItem": [{"Indication": "PASSED"}]}}`)
	}))
	defer server.Close()

	start := time.Now()
	_, errService, errValidation := VerifyCertificate("dummy-data", server.URL)
	duration := time.Since(start)

	if errService != nil {
		t.Errorf("Expected success on 3rd attempt, got service error: %v", errService)
	}
	if errValidation != nil {
		t.Errorf("Expected no validation error, got: %v", errValidation)
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}

	// Wait time should be around 3 + 5 = 8 seconds
	if duration < 8*time.Second {
		t.Errorf("Expected duration >= 8s, got %v", duration)
	}
}

func TestVerifyCertificateMaxRetries(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, errService, _ := VerifyCertificate("dummy-data", server.URL)

	if errService == nil {
		t.Error("Expected service error after max retries, got nil")
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}
