#!/bin/bash
# Install Caddy localhost certificate on macOS

set -e

echo "🔐 Installing Caddy Local CA Certificate..."
echo ""

# Check if Caddy is running
if ! docker-compose ps | grep caddy | grep -q "Up"; then
    echo "❌ Caddy service is not running. Starting services..."
    docker-compose up -d
    echo "⏳ Waiting for Caddy to start..."
    sleep 5
fi

# Extract the certificate
echo "📥 Extracting Caddy root CA certificate..."
docker-compose exec caddy cat /data/caddy/pki/authorities/local/root.crt > caddy-root-ca.crt

# Check if extraction was successful
if [ ! -s caddy-root-ca.crt ]; then
    echo "❌ Failed to extract certificate"
    exit 1
fi

echo "✅ Certificate extracted to: $(pwd)/caddy-root-ca.crt"
echo ""

# Show certificate info
echo "📋 Certificate details:"
openssl x509 -in caddy-root-ca.crt -text -noout | grep -E "Issuer:|Subject:|Not Before|Not After" | sed 's/^/   /'
echo ""

# Install on macOS
echo "🔧 Installing certificate in macOS system keychain..."
echo "   (You'll be prompted for your password)"
echo ""

sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain caddy-root-ca.crt

echo ""
echo "✅ Certificate installed successfully!"
echo ""
echo "🌐 You can now access the services without certificate warnings:"
echo "   • https://certauth.localhost"
echo "   • https://certsec.localhost"
echo "   • https://onboard.localhost"
echo ""
echo "💡 Note: You may need to restart your browser for changes to take effect."
echo ""
echo "🗑️  To uninstall later, run:"
echo "   sudo security delete-certificate -c 'Caddy Local Authority - 2025 ECC Root' /Library/Keychains/System.keychain"
