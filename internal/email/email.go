// Package email provides functionality for sending emails using SMTP, including template-based email generation.
package email

import (
	"bytes"
	"crypto/tls"
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/html"
)

type EmailConfig struct {
	User     string `yaml:"user"`
	Password string `yaml:"password"`
	Email    string `yaml:"email"`
	IMAP     string `yaml:"imap"`
	SMTP     string `yaml:"smtp"`
	SMTPPort string `yaml:"smtp_port"`
}

// Service represents an email service
type Service struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	fromName     string
	htmlrender   *html.RendererStd
}

// EmailData represents the data passed to email templates
type EmailData struct {
	VerificationCode string
	ExpiresAt        time.Time
	AppName          string
}

const templateDebug = true

//go:embed views/*
var viewsfs embed.FS

// NewService creates a new email service
func NewService(cfg *EmailConfig) (*Service, error) {
	// Parse email templates

	// The engine to display the screens HTML screens to the users
	htmlrender, err := html.NewRendererStd(templateDebug, viewsfs, "internal/email/views", ".hbs")
	if err != nil {
		return nil, errl.Errorf("failed to initialize template engine: %w", err)
	}

	return &Service{
		smtpHost:     cfg.SMTP,
		smtpPort:     cfg.SMTPPort,
		smtpUsername: cfg.User,
		smtpPassword: cfg.Password,
		fromEmail:    "hello@redisbe.com",
		fromName:     cfg.User,
		htmlrender:   htmlrender,
	}, nil
}

// SendVerificationEmail sends a verification email with a code
func (s *Service) SendVerificationEmail(toEmail string, verificationCode string) error {
	// Validate email format
	if err := s.ValidateEmail(toEmail); err != nil {
		return errl.Errorf("invalid email: %w", err)
	}

	// Prepare email data
	data := EmailData{
		VerificationCode: verificationCode,
		ExpiresAt:        time.Now().Add(10 * time.Minute),
		AppName:          "Red ISBE",
	}

	// Generate email body using template
	body, err := s.htmlrender.RenderToBuffer("sendemail", data)
	if err != nil {
		return errl.Errorf("failed to execute email template: %w", err)
	}

	// Send the email
	subject := "Verificación de correo electrónico - Red ISBE"
	return s.sendPostmarkEmail(toEmail, subject, body.String())
}

func (s *Service) sendPostmarkEmail(toEmail string, subject string, body string) error {

	// Send a POST to the Postmark API to send an email.
	// The POST is like this below, where the 'X-Postmark-Server-Token' is the 'smtpPassword' in the config.
	//
	// POST https://api.postmarkapp.com/email
	// X-Postmark-Server-Token: uwewe23nn8dn2d2b2n22
	// Accept: application/json
	// Content-Type: application/json
	//
	// {
	//   "From": "hello@redisbe.com",
	//   "To": "jesus@alastria.io",
	//   "Subject": "Postmark test",
	//   "TextBody": "Hello dear Postmark user.",
	//   "HtmlBody": "<html><body><strong>Hello</strong> dear Postmark user.</body></html>",
	//   "MessageStream": "outbound"
	// }

	payload := map[string]string{
		"From":          s.fromEmail,
		"To":            toEmail,
		"Subject":       subject,
		"HtmlBody":      body,
		"MessageStream": "outbound",
	}
	slog.Debug("Postmark payload", "from", s.fromEmail, "to", toEmail, "subject", subject)
	slog.Debug("Postmark token", "token", s.smtpPassword)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return errl.Errorf("failed to marshal postmark payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.postmarkapp.com/email", bytes.NewReader(payloadBytes))
	if err != nil {
		return errl.Errorf("failed to create postmark request: %w", err)
	}
	req.Header.Set("X-Postmark-Server-Token", s.smtpPassword)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errl.Errorf("failed to send postmark request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errl.Errorf("postmark API returned non-2xx status: %d", resp.StatusCode)
	}

	slog.Info("Postmark email sent", "to", toEmail)
	return nil
}

// sendEmail sends an email using SMTP
func (s *Service) sendEmail(toEmail string, subject string, body string) error {

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	to := []string{toEmail}
	msg := []byte("From: " + s.fromName + " <" + s.fromEmail + ">\r\n" +
		"To: " + toEmail + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		body)

	addr := fmt.Sprintf("%s:%s", s.smtpHost, s.smtpPort)

	// If port is 465, use implicit TLS
	if s.smtpPort == "465" {
		tlsConfig := &tls.Config{
			ServerName: s.smtpHost,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return errl.Errorf("failed to dial tls: %w", err)
		}

		c, err := smtp.NewClient(conn, s.smtpHost)
		if err != nil {
			conn.Close()
			return errl.Errorf("failed to create smtp client: %w", err)
		}
		defer c.Quit()

		auth := smtp.PlainAuth("", s.smtpUsername, s.smtpPassword, s.smtpHost)
		if err = c.Auth(auth); err != nil {
			return errl.Errorf("failed to authenticate: %w", err)
		}

		if err = c.Mail(s.fromEmail); err != nil {
			return errl.Errorf("failed to set sender: %w", err)
		}

		for _, recipient := range to {
			if err = c.Rcpt(recipient); err != nil {
				return errl.Errorf("failed to set recipient: %w", err)
			}
		}

		w, err := c.Data()
		if err != nil {
			return errl.Errorf("failed to create data writer: %w", err)
		}

		_, err = w.Write(msg)
		if err != nil {
			return errl.Errorf("failed to write message: %w", err)
		}

		err = w.Close()
		if err != nil {
			return errl.Errorf("failed to close data writer: %w", err)
		}
	} else {
		// Use standard smtp.SendMail (handles STARTTLS automatically)
		auth := smtp.PlainAuth("", s.smtpUsername, s.smtpPassword, s.smtpHost)
		err := smtp.SendMail(addr, auth, s.fromEmail, to, msg)
		if err != nil {
			return errl.Errorf("failed to send email: %w", err)
		}
	}

	slog.Info("Verification email sent", "to", toEmail)
	return nil
}

// ValidateEmail validates email format
func (s *Service) ValidateEmail(email string) error {
	if email == "" {
		return errl.Errorf("email is required")
	}

	if !strings.Contains(email, "@") {
		return errl.Errorf("invalid email format")
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return errl.Errorf("invalid email format")
	}

	if parts[0] == "" || parts[1] == "" {
		return errl.Errorf("invalid email format")
	}

	if !strings.Contains(parts[1], ".") {
		return errl.Errorf("invalid email format")
	}

	return nil
}
