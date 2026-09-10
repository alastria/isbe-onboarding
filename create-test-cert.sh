#!/bin/bash
set -e

echo "🔐 Creating test client certificate for mTLS..."

# Create certs directory if it doesn't exist
mkdir -p certs

# Generate CA private key and certificate
openssl genrsa -out certs/ca.key 4096
openssl req -x509 -new -nodes -key certs/ca.key -sha256 -days 3650 \
  -out certs/ca.crt -subj "/CN=Test CA/O=Development/C=ES"

# Generate client private key
openssl genrsa -out certs/client.key 2048

# Create OpenSSL config with organizationIdentifier OID and all required fields
cat > certs/client.cnf << 'CNFEOF'
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req

[req_distinguished_name]

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
email = testuser@example.com
CNFEOF

# Create CSR with organizationIdentifier and all required eIDAS fields
# Including: Country, Organization, OrganizationalUnit, Locality, State/Province, 
# CommonName, GivenName (2.5.4.42), Surname (2.5.4.4), SerialNumber, OrganizationIdentifier (2.5.4.97)
openssl req -new -key certs/client.key -out certs/client.csr \
  -subj "/C=ES/ST=Madrid/L=Madrid/O=Test Organization/OU=Test Unit/CN=Test User/GN=Juan/SN=García López/serialNumber=A12345678/2.5.4.97=VATES-A12345678" \
  -config certs/client.cnf

# Sign the certificate
openssl x509 -req -in certs/client.csr -CA certs/ca.crt -CAkey certs/ca.key \
  -CAcreateserial -out certs/client.crt -days 365 -sha256 \
  -extfile certs/client.cnf -extensions v3_req

# Create PKCS#12 bundle for browser import (password: test)
openssl pkcs12 -export -out certs/client.p12 \
  -inkey certs/client.key -in certs/client.crt -certfile certs/ca.crt \
  -passout pass:test

echo "✅ Certificates created:"
echo "   • CA cert: certs/ca.crt"
echo "   • Client cert: certs/client.crt"
echo "   • Client key: certs/client.key"
echo "   • PKCS#12 bundle: certs/client.p12 (password: test)"
echo ""
echo "📥 To import into your browser:"
echo "   1. Open browser settings > Certificates"
echo "   2. Import certs/client.p12"
echo "   3. Enter password: test"
echo ""
echo "🔄 Restart Caddy to use the new CA:"
echo "   docker-compose restart caddy"
