package models

import (
	"errors"
	"sync"
	"testing"
)

// The requests of an authentication run concurrently and share the AuthProcess. Run with -race.
func TestAuthenticationStateUnderConcurrency(t *testing.T) {
	received, other := &CertificateData{}, &CertificateData{}
	wallet := map[string]any{"wallet": true}

	for range 200 {
		p := &AuthProcess{}
		attempt := p.StartCertificateAttempt()
		p.SetCertificate(received)

		var wg sync.WaitGroup
		run := func(f func()) {
			wg.Add(1)
			go func() { defer wg.Done(); f() }()
		}
		// Two validations of the same attempt (e.g. a reload), each with its own copy
		for range 2 {
			run(func() {
				validated := *received
				validated.EIDASCertificate = true
				if p.AcceptCertificate(attempt, &validated) {
					p.CompleteCertificateFlow(attempt, &validated, "user@example.com", "powers")
				}
			})
		}
		run(func() { p.StartCertificateAttempt(); p.SetCertificate(other) }) // CertSec, a new attempt
		run(func() { p.CompleteWalletAuthentication(wallet) })               // the wallet
		run(func() {                                                         // later steps and tokens
			if cd, _ := p.AcceptedCertificate(); cd != nil && !cd.EIDASCertificate {
				t.Errorf("steps for a certificate that was not validated")
			}
			if done := p.Completed(); done != nil && done.Certificate != nil && !done.Certificate.EIDASCertificate {
				t.Errorf("tokens for a certificate that was not validated")
			}
			p.WalletAuthFinished()
		})
		wg.Wait()

		// Whatever the order, the completed authentication is exactly one validated method
		if done := p.Completed(); done != nil && (done.Certificate == nil) == (done.Credential == nil) {
			t.Fatalf("unexpected completed authentication: %+v", done)
		}
	}
}

func TestAuthenticationStateTransitions(t *testing.T) {
	received := &CertificateData{}
	p := &AuthProcess{}
	attempt := p.StartCertificateAttempt()
	p.SetCertificate(received)

	// Validations of the same attempt are all accepted, each copy replacing the data; the
	// received data is never modified
	first, second := *received, *received
	first.EIDASCertificate, second.EIDASCertificate = true, true
	if !p.AcceptCertificate(attempt, &first) || !p.AcceptCertificate(attempt, &second) || received.EIDASCertificate {
		t.Fatalf("validations of the same attempt invalidate each other")
	}
	if cd, a := p.AcceptedCertificate(); cd != &second || a != attempt {
		t.Fatalf("the latest validation of the attempt is not the accepted one")
	}
	// A step that started with the first copy can still complete the attempt
	if !p.CompleteCertificateFlow(attempt, &first, "user@example.com", "powers") {
		t.Fatalf("the attempt can not complete with an earlier validation")
	}
	if cd, _ := p.AcceptedCertificate(); cd != nil {
		t.Fatalf("the steps of the certificate flow are still open after completion")
	}
	if done := p.Completed(); done.Certificate != &first || done.Email != "user@example.com" || done.Powers != "powers" {
		t.Fatalf("unexpected completed authentication: %+v", done)
	}

	// A new attempt invalidates the previous one
	next := p.StartCertificateAttempt()
	p.SetCertificate(&CertificateData{})
	if p.AcceptCertificate(attempt, &first) || p.CompleteCertificateFlow(attempt, &first, "", "") || p.Completed() != nil {
		t.Fatalf("the previous attempt is still valid")
	}
	if !p.AcceptCertificate(next, &CertificateData{}) {
		t.Fatalf("the new attempt can not be accepted")
	}
	if p.CompleteCertificateFlow(attempt, &first, "", "") {
		t.Fatalf("a step of the previous attempt completed the new one")
	}

	// The wallet replaces the certificate attempt
	p.CompleteWalletAuthentication(map[string]any{"wallet": true})
	if done := p.Completed(); done.Certificate != nil || done.Credential == nil || !p.WalletAuthFinished() {
		t.Fatalf("wallet authentication not recorded: %+v", done)
	}
	if p.AcceptCertificate(next, &CertificateData{}) {
		t.Fatalf("the certificate attempt is still valid after the wallet")
	}

	// A new certificate attempt starts clean: no certificate, error, wallet or completion
	p.FailCertificateAttempt(errors.New("rejected"))
	p.StartCertificateAttempt()
	if cd, _, err := p.CertificateResult(); cd != nil || err != nil || p.Completed() != nil || p.WalletAuthFinished() {
		t.Fatalf("state kept after a new certificate attempt")
	}
}
