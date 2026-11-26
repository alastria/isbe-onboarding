package models

import (
	"errors"
	"sync"
	"testing"
)

// The requests of an authentication run concurrently and share the AuthProcess. Run with -race.
func TestAuthenticationStateUnderConcurrency(t *testing.T) {
	validated, other := &CertificateData{}, &CertificateData{}
	wallet := map[string]any{"wallet": true}

	for range 200 {
		p := &AuthProcess{}
		p.SetCertificate(validated)

		var wg sync.WaitGroup
		wg.Add(4)
		go func() { // CertSec receives another certificate
			defer wg.Done()
			p.StartCertificateAttempt()
			p.SetCertificate(other)
		}()
		go func() { // CertAuth accepts the certificate it validated and completes the flow
			defer wg.Done()
			if p.AcceptCertificate(validated, validated) {
				p.CompleteCertificateFlow(validated, "user@example.com", "powers")
			}
		}()
		go func() { // the wallet completes with the same code
			defer wg.Done()
			p.CompleteWalletAuthentication(wallet)
		}()
		go func() { // the token endpoint and the steps of the certificate flow
			defer wg.Done()
			if done := p.Completed(); done != nil && done.Certificate != nil && done.Certificate != validated {
				t.Errorf("tokens for a certificate that was not validated")
			}
			if cd := p.AcceptedCertificate(); cd != nil && cd != validated {
				t.Errorf("steps for a certificate that was not validated")
			}
			p.WalletAuthFinished()
		}()
		wg.Wait()

		// Whatever the order, the completed authentication is exactly one validated method
		if done := p.Completed(); done != nil {
			if (done.Certificate == nil) == (done.Credential == nil) || (done.Certificate != nil && done.Certificate != validated) {
				t.Fatalf("unexpected completed authentication: %+v", done)
			}
		}
	}
}

func TestAuthenticationStateTransitions(t *testing.T) {
	validated, other := &CertificateData{}, &CertificateData{}

	// Only the current certificate can be accepted and completed
	p := &AuthProcess{}
	p.SetCertificate(other)
	if p.AcceptCertificate(validated, validated) || p.CompleteCertificateFlow(other, "", "") || p.Completed() != nil {
		t.Fatalf("accepted or completed without validation")
	}

	// The accepted copy carries the result of the validation and replaces the received data,
	// which is not modified
	received := &CertificateData{}
	p.SetCertificate(received)
	result := *received
	result.EIDASCertificate = true
	if !p.AcceptCertificate(received, &result) || p.AcceptedCertificate() != &result || received.EIDASCertificate {
		t.Fatalf("the validated copy did not replace the received certificate")
	}
	if cd, _ := p.CertificateResult(); !cd.EIDASCertificate {
		t.Fatalf("the result of the validation was lost")
	}

	// Once completed, the steps of the certificate flow are closed and the tokens carry the
	// email and powers recorded at completion
	p.SetCertificate(validated)
	p.AcceptCertificate(validated, validated)
	p.CompleteCertificateFlow(validated, "user@example.com", "powers")
	if p.AcceptedCertificate() != nil {
		t.Fatalf("the steps of the certificate flow are still open after completion")
	}
	if done := p.Completed(); done.Certificate != validated || done.Email != "user@example.com" || done.Powers != "powers" {
		t.Fatalf("unexpected completed authentication: %+v", done)
	}

	// The wallet replaces the certificate
	p.CompleteWalletAuthentication(map[string]any{"wallet": true})
	if done := p.Completed(); done.Certificate != nil || done.Credential == nil || !p.WalletAuthFinished() {
		t.Fatalf("wallet authentication not recorded: %+v", done)
	}
	if cd, _ := p.CertificateResult(); cd != nil {
		t.Fatalf("certificate kept after the wallet authentication")
	}

	// A new certificate attempt starts clean: no certificate, error, wallet or completion
	p.FailCertificateAttempt(errors.New("rejected"))
	p.StartCertificateAttempt()
	if cd, err := p.CertificateResult(); cd != nil || err != nil || p.Completed() != nil || p.WalletAuthFinished() {
		t.Fatalf("state kept after a new certificate attempt")
	}
}
