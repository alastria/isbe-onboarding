# Email Service

This package provides email functionality for the CertAuth application, specifically for sending verification emails.

## Features

- **Email Validation**: Validates email format before sending
- **Template-based Emails**: Uses Go templates for email content
- **SMTP Support**: Configurable SMTP settings
- **Development Mode**: Logs emails instead of sending when no SMTP credentials are provided
- **HTML Emails**: Sends beautifully formatted HTML emails

## Usage

### Basic Usage

```go
import "github.com/alastria/isbe-onboarding/internal/email"

// Create email service
emailService := email.NewService()

// Send verification email
err := emailService.SendVerificationEmail("user@example.com", "123456")
if err != nil {
    // Handle error
}
```

### Configuration

The email service is configured via environment variables:

- `SMTP_HOST`: SMTP server hostname (default: "localhost")
- `SMTP_PORT`: SMTP server port (default: "587")
- `SMTP_USERNAME`: SMTP username (required for production)
- `SMTP_PASSWORD`: SMTP password (required for production)
- `FROM_EMAIL`: Sender email address (default: "noreply@certauth.mycredential.eu")
- `FROM_NAME`: Sender name (default: "CertAuth")

### Development Mode

When `SMTP_USERNAME` and `SMTP_PASSWORD` are not set, the service runs in development mode and logs emails instead of sending them:

```
time=2025-09-01T18:55:41.666Z level=INFO msg="Email would be sent (development mode)" to=test@example.com subject="Email Verification Required - CertAuth" body_length=3718
```

### Email Template

The verification email template includes:

- **Verification Code**: Large, easy-to-read 6-digit code
- **Expiration Time**: Shows when the code expires
- **Security Information**: Important security notices
- **Professional Design**: Clean, responsive HTML layout

### Template Variables

The email template accepts the following variables:

- `{{.VerificationCode}}`: The 6-digit verification code
- `{{.ExpiresAt}}`: Time when the code expires
- `{{.AppName}}`: Application name (default: "CertAuth")

## Testing

Run the tests with:

```bash
go test ./internal/email/...
```

## Example Email Output

The service generates professional HTML emails with:

- Responsive design that works on mobile and desktop
- Clear verification code display
- Security warnings and instructions
- Professional branding
- Accessibility considerations
