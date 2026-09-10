# Docker Compose Setup Guide

This guide explains how to run the certauth services locally with HTTPS/TLS using Caddy as a reverse proxy.

## Services

The setup includes 3 application services running in a single container, plus a reverse proxy:

1. **certauth** - Main OpenID Provider authentication service (internal port 8010)
2. **certsec** - Certificate security service with mTLS client authentication (internal port 8011)
3. **onboard** - User onboarding/registration service (internal port 8012)
4. **caddy** - Reverse proxy with automatic HTTPS/TLS (ports 80, 443)

## Service URLs

All services are accessed through Caddy's HTTPS proxy:

- **Certauth**: https://certauth.localhost
- **Certsec**: https://certsec.localhost (requires client certificate for mTLS)
- **Onboard**: https://onboard.localhost

## Prerequisites

1. **Docker and Docker Compose** installed
2. **Hosts file configuration** - Add these entries to your `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```bash
127.0.0.1 certauth.localhost
127.0.0.1 certsec.localhost
127.0.0.1 onboard.localhost
```

## Quick Start

### 1. Create Test Certificates

Run the provided script to create test certificates with all required eIDAS fields:

```bash
chmod +x create-test-cert.sh
./create-test-cert.sh
```

This creates:
- CA certificate and key
- Client certificate with all required fields (given name, surname, organization, etc.)
- PKCS#12 bundle for browser import (`certs/client.p12` with password: `test`)

### 2. Install CA Certificate (macOS)

Install Caddy's local CA certificate to avoid browser warnings:

```bash
chmod +x install-cert.sh
./install-cert.sh
```

For other operating systems, you'll need to manually trust the Caddy root CA after starting the services.

### 3. Import Client Certificate

**macOS Keychain:**
```bash
security import certs/client.p12 -k ~/Library/Keychains/login.keychain-db -f pkcs12 -P test -A
```

**Manual import (all platforms):**
- **Chrome/Edge**: Settings → Privacy and security → Security → Manage certificates → Import `certs/client.p12`
- **Firefox**: Settings → Privacy & Security → Certificates → View Certificates → Your Certificates → Import `certs/client.p12`
- **Password**: `test`

### 4. Start Services

```bash
docker-compose up -d
```

### 5. Verify Services are Running

```bash
docker-compose ps
```

You should see `certauth` and `caddy` containers running.

### 6. Test the Application

1. Open https://onboard.localhost in your browser
2. Click "Login" to start the authentication flow
3. You'll be redirected through the certificate authentication
4. When prompted, select the "Test User" certificate
5. Complete the email verification (code will be displayed on screen in local mode)
6. Accept the contract to complete registration

## Managing Services

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f certauth
docker-compose logs -f caddy

# Last 50 lines
docker-compose logs --tail=50 certauth
```

### Stop Services

```bash
docker-compose down
```

### Rebuild and Restart

```bash
docker-compose down && docker-compose build && docker-compose up -d
```

### Check Service Health

```bash
# Check container status
docker-compose ps

# Check certauth health endpoint
curl -k https://certauth.localhost/health
```

## Local Development Features

When running with `PROFILE=local` (default in docker-compose.yml):

### 1. Email Verification Bypass
- SMTP email sending failures are non-blocking
- Verification codes are displayed on screen
- Allows testing without a working email server

### 2. Certificate Validation
- Non-eIDAS certificates are accepted with warnings
- Self-signed certificates work for testing
- Validation failures are logged but don't block the flow

### 3. Cookie Settings
- Cookies work correctly in local HTTPS environment
- Secure flag is automatically adjusted based on URL scheme

## Certificate Details

The test certificate created by `create-test-cert.sh` includes all required eIDAS fields:

- **Common Name (CN)**: Test User
- **Given Name (GN)**: Juan
- **Surname (SN)**: García López
- **Organization (O)**: Test Organization
- **Organization Identifier (OID 2.5.4.97)**: VATES-A12345678
- **Organizational Unit (OU)**: Test Unit
- **Country (C)**: ES
- **State/Province (ST)**: Madrid
- **Locality (L)**: Madrid
- **Serial Number**: A12345678
- **Email (SAN)**: testuser@example.com
- **Valid for**: 1 year

### Services not accessible

Check if all services are running:
```bash
docker-compose ps
```

Check logs for errors:
```bash
docker-compose logs certauth
```

### Certificate errors in browser

**Option 1: Install Caddy CA (Recommended)**
```bash
./install-cert.sh  # macOS
```

**Option 2: Accept browser warning**
- Click "Advanced" → "Proceed to certauth.localhost (unsafe)"
- This is safe for local development

### Client certificate not working

1. Verify certificate is imported:
   - **macOS**: Open Keychain Access, search for "Test User"
   - **Chrome**: Settings → Privacy and security → Manage certificates

2. Recreate certificate:
   ```bash
   rm -rf certs/
   ./create-test-cert.sh
   # Re-import into browser
   ```

3. Check certificate details:
   ```bash
   openssl x509 -in certs/client.crt -noout -subject -dates
   ```

### Port conflicts

If ports 80 or 443 are already in use:

```bash
# Check what's using the ports
lsof -i :443
lsof -i :80

# Stop conflicting services or modify docker-compose.yml
```

### DNS resolution not working

Verify `/etc/hosts` entries:
```bash
cat /etc/hosts | grep localhost
```

Should show:
```
127.0.0.1 certauth.localhost
127.0.0.1 certsec.localhost  
127.0.0.1 onboard.localhost
```

### Database issues

Reset database:
```bash
docker-compose down
rm -rf data/
docker-compose up -d
```

### Cookie/state errors in OAuth flow

This usually means services aren't accessed via HTTPS domains. Make sure you:
- Access via `https://onboard.localhost` (not `http://localhost:8012`)
- Have proper `/etc/hosts` configuration
- Services are using HTTPS URLs in environment variables

## Architecture Overview

```
Browser
   ↓ (HTTPS)
   ↓
Caddy Reverse Proxy (ports 80, 443)
   ├── certauth.localhost → certauth:8010
   ├── certsec.localhost → certauth:8011 (+ client cert header)
   └── onboard.localhost → certauth:8012
            ↓
CertAuth Container
   ├── CertAuth Service (port 8010) - OpenID Provider
   ├── CertSec Service (port 8011) - mTLS authentication
   └── Onboard Service (port 8012) - User registration
```

## Environment Variables

Configured in `docker-compose.yml`:

### Core Configuration
- `PROFILE=local` - Development profile (enables test mode features)
- `CERTAUTH_DEVELOPMENT=true` - Development mode
- `CERTAUTH_ADMIN_PASSWORD=admin123` - Admin panel password

### Service URLs
- `CERTAUTH_URL=http://localhost:8010` - Internal URL
- `CERTSEC_URL=https://certsec.localhost` - External URL for mTLS
- `ONBOARD_URL=https://onboard.localhost` - External URL for OAuth callbacks

### Credentials (for production, replace with real values)
- `TSA_USER=dev_user` - Timestamp Authority username
- `TSA_PASSWORD=dev_password` - Timestamp Authority password  
- `SMTP_USERNAME=dev@localhost` - Email server username
- `SMTP_PASSWORD=dev_password` - Email server password

## Configuration Files

- **`docker-compose.yml`** - Service orchestration and environment configuration
- **`Caddyfile`** - Reverse proxy configuration with HTTPS and mTLS
- **`Dockerfile`** - Application container build instructions
- **`config.go`** - Application profiles and configuration
- **`create-test-cert.sh`** - Test certificate generation script
- **`install-cert.sh`** - CA certificate installation script (macOS)

## Production Considerations

For production deployment:

1. **Use proper SSL certificates** - Replace Caddy's local CA with Let's Encrypt or commercial certs
2. **Change profile** - Set `PROFILE=isbe-dev`, `isbe-pre`, or `isbe-pro`
3. **Secure credentials** - Use secrets management for TSA and SMTP credentials
4. **Configure real domains** - Replace `.localhost` domains with production domains
5. **Enable monitoring** - Prometheus metrics available at `/metrics` endpoint
6. **Set up logging** - Configure centralized logging aggregation
7. **Database persistence** - Ensure `./data` volume is properly backed up
8. **Health checks** - Monitor `/health` endpoints
9. **Email service** - Configure working SMTP server for email verification
10. **Remove test features** - Email code display and certificate validation bypass are disabled in non-local profiles

## Additional Resources

- **Project Documentation**: `PROJECT_DOCUMENTATION.md`
- **Metrics Information**: `internal/certauth/METRICS.md`
- **Main README**: `README.md`

## Configuration Files

- `docker-compose.yml` - Service orchestration
- `Caddyfile` - Reverse proxy configuration with HTTPS/TLS
- `Dockerfile` - Application container build

## Production Considerations

For production deployment:

1. Use real domain names and proper SSL certificates (Let's Encrypt)
2. Configure proper health checks
3. Add database services if needed
4. Configure persistent volumes for application data
5. Set up proper logging and monitoring
6. Use secrets management for sensitive data
7. Configure rate limiting and security headers
8. Review and harden the Caddyfile configuration
