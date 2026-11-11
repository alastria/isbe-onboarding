//go:build integration

package email

import (
	"os"
	"testing"
)

// These tests send REAL emails through the configured provider. They are
// excluded from normal builds and must be run deliberately:
//
//	SMTP_USERNAME=... SMTP_PASSWORD=... EMAIL_TEST_TO=you@example.org \
//	  go test -tags integration -run 'TestEmailService_(SendVerificationEmail|DebugEmail)' ./internal/email/
//
// Credentials must never be written in this file.

func integrationConfig(t *testing.T) (*EmailConfig, string) {
	t.Helper()
	user, pass, to := os.Getenv("SMTP_USERNAME"), os.Getenv("SMTP_PASSWORD"), os.Getenv("EMAIL_TEST_TO")
	if user == "" || pass == "" || to == "" {
		t.Skip("set SMTP_USERNAME, SMTP_PASSWORD and EMAIL_TEST_TO to send real test emails")
	}
	return &EmailConfig{
		User:     user,
		Password: pass,
		Email:    user,
		SMTP:     "smtp.serviciodecorreo.es",
		SMTPPort: "465",
		IMAP:     "imap.serviciodecorreo.es",
	}, to
}

func TestEmailService_SendVerificationEmail(t *testing.T) {
	cfg, to := integrationConfig(t)
	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}
	if err := service.SendVerificationEmail(to, "123456"); err != nil {
		t.Errorf("SendVerificationEmail() error = %v", err)
	}
}

func TestEmailService_DebugEmail(t *testing.T) {
	cfg, to := integrationConfig(t)
	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}
	if err := service.sendEmail(to, "isbe-onboarding integration test", "This is the email body."); err != nil {
		t.Errorf("SendMail error = %v", err)
	}
}
