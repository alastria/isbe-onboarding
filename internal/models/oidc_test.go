package models

import (
	"sync"
	"testing"
)

// The certificate steps run in concurrent requests that share the AuthProcess. Run with -race.
func TestCertificateAcceptanceIsBoundToTheCertificate(t *testing.T) {
	validated, other := &CertificateData{}, &CertificateData{}

	for range 200 {
		p := &AuthProcess{}
		p.SetCertificate(validated)

		var wg sync.WaitGroup
		wg.Add(3)
		go func() { // CertSec receives another certificate
			defer wg.Done()
			p.SetCertificate(other)
		}()
		go func() { // CertAuth accepts the one it validated and completes the flow
			defer wg.Done()
			if p.AcceptCertificate(validated) {
				p.CompleteCertificateFlow(validated)
			}
		}()
		go func() { // the token endpoint and the later steps
			defer wg.Done()
			if cd := p.CompletedCertificate(); cd != nil && cd != validated {
				t.Errorf("completed certificate is not the validated one")
			}
			if cd := p.AcceptedCertificate(); cd != nil && cd != validated {
				t.Errorf("accepted certificate is not the validated one")
			}
		}()
		wg.Wait()

		// Once the other certificate is set, nothing is accepted any more
		if p.Certificate() == other && (p.AcceptedCertificate() != nil || p.CompletedCertificate() != nil) {
			t.Fatalf("the other certificate is accepted without validation")
		}
	}

	// Accepting a certificate that is no longer the current one fails
	p := &AuthProcess{}
	p.SetCertificate(other)
	if p.AcceptCertificate(validated) || p.CompleteCertificateFlow(other) {
		t.Fatalf("accepted or completed without validation")
	}
}
