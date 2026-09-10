# Build stage
FROM golang:1.26-alpine AS builder

# Install build tools for CGO
RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum files to download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary with CGO enabled
# -ldflags="-w -s" strips debug information and symbols, reducing the binary size
RUN go build -ldflags="-w -s" -o /certauth .

# Final stage
FROM alpine/curl:latest

# Install weasyprint and a basic font set (required for text rendering)
RUN apk add --no-cache \
    weasyprint \
    ttf-dejavu

# Verify installation
RUN weasyprint --version

WORKDIR /
COPY --from=builder /certauth /certauth
RUN chmod +x /certauth
COPY --from=builder /app/certauthserver/views /certauthserver/views
COPY --from=builder /app/certsecserver/views /certsecserver/views
COPY --from=builder /app/onboard/views /onboard/views

HEALTHCHECK \
    --interval=60s \
    --timeout=5s \
    --start-period=10s \
    --start-interval=3s \
    --retries=3 \
    CMD curl -f http://localhost:8010/health || exit 1

# Expose the port the server runs on
EXPOSE 8010
EXPOSE 8011
EXPOSE 8012

# Run the binary
ENTRYPOINT ["/certauth"]