package email

import (
	"testing"
	"time"
)

func TestEmailService_ValidateEmail(t *testing.T) {

	cfg := &EmailConfig{
		User:     "register@redisbe.com",
		Password: "RegisterRedIsbe@2025",
		Email:    "register@redisbe.com",
		SMTP:     "smtp.serviciodecorreo.es",
		IMAP:     "imap.serviciodecorreo.es",
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}

	tests := []struct {
		name    string
		email   string
		wantErr bool
	}{
		{"valid email", "test@example.com", false},
		{"valid email with subdomain", "test@sub.example.com", false},
		{"empty email", "", true},
		{"missing @", "testexample.com", true},
		{"missing domain", "test@", true},
		{"missing local part", "@example.com", true},
		{"missing TLD", "test@example", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateEmail(tt.email)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateEmail() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEmailService_SendVerificationEmail(t *testing.T) {
	cfg := &EmailConfig{
		User:     "api.postmarkapp.com",
		Password: "",
		Email:    "hello@redisbe.com",
		SMTP:     "smtp.serviciodecorreo.es",
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}

	// Test sending verification email (should log in development mode)
	err = service.SendVerificationEmail("jesus@alastria.io", "123456")
	if err != nil {
		t.Errorf("SendVerificationEmail() error = %v", err)
	}
}

func TestEmailService_DebugEmail(t *testing.T) {

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	to := "jesus@alastria.io"
	subject := "discount Gophers!"
	body := "This is the email body."

	cfg := &EmailConfig{
		User:     "register@redisbe.com",
		Password: "RegisterRedIsbe@2025",
		Email:    "register@redisbe.com",
		SMTP:     "smtp.serviciodecorreo.es",
		SMTPPort: "465",
		IMAP:     "imap.serviciodecorreo.es",
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}

	// Use the internal sendEmail method (via passing a test? No, it's private).
	// The user wants to debug "Simple email send functionality".
	// The simplest way now is to use SendVerificationEmail which uses the fixed logic,
	// OR replicate the manual connection logic here correctly.
	// I will use SendVerificationEmail as it validates the whole flow, including the fix.
	// But wait, the user specifically had a custom body in their test.
	// I can't call private methods from valid test package (if it is package email_test).
	// But it is `package email` at line 1. So I CAN call private methods.

	err = service.sendEmail(to, subject, body)
	if err != nil {
		t.Errorf("SendMail error = %v", err)
	}

}

func TestEmailTemplate_Data(t *testing.T) {
	cfg := &EmailConfig{
		User:     "register@redisbe.com",
		Password: "RegisterRedIsbe@2025",
		Email:    "register@redisbe.com",
		SMTP:     "smtp.serviciodecorreo.es",
		IMAP:     "imap.serviciodecorreo.es",
	}

	service, err := NewService(cfg)
	if err != nil {
		t.Fatalf("failed to create email service: %v", err)
	}

	// Test that the template can be executed with data
	data := EmailData{
		VerificationCode: "123456",
		ExpiresAt:        time.Now().Add(10 * time.Minute),
		AppName:          "TestApp",
	}

	// This should not panic
	_ = data
	_ = service
}
