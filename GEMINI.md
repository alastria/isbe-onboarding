# GEMINI.md

## Project Overview

This project is a Go application that provides an OpenID Provider (OP) for authenticating users with an eIDAS digital certificate. It consists of three main services:

*   **CertAuth**: The core OpenID Provider service.
*   **CertSec**: A service that handles mTLS (mutual TLS) authentication to obtain the user's certificate from the browser.
*   **Onboard**: A user registration service.

The services are designed to be run in Docker containers and are exposed to the outside world through a Caddy reverse proxy that handles HTTPS.

The application uses a SQLite database to store its data and also utilizes in-memory caching for authentication processes and SSO sessions.

## Building and Running

The project is designed to be built and run using Docker and Docker Compose.

### Prerequisites

*   Docker and Docker Compose installed.
*   The following entries added to your `/etc/hosts` file:
    ```
    127.0.0.1 certauth.localhost
    127.0.0.1 certsec.localhost
    127.0.0.1 onboard.localhost
    ```

### Local Development

To run the application for local development, follow these steps:

1.  **Create test certificates**:
    ```bash
    chmod +x create-test-cert.sh && ./create-test-cert.sh
    ```

2.  **Install the CA certificate** (optional, to avoid browser warnings):
    ```bash
    chmod +x install-cert.sh && ./install-cert.sh
    ```

3.  **Import the client certificate** into your browser:
    *   Import the `certs/client.p12` file.
    *   The password for the certificate is `test`.

4.  **Start the services**:
    ```bash
    docker-compose up -d
    ```

5.  **Access the services**:
    *   **Onboard**: [https://onboard.localhost](https://onboard.localhost)
    *   **CertAuth**: [https://certauth.localhost](https://certauth.localhost)
    *   **CertSec**: [https://certsec.localhost](https://certsec.localhost)

### Building for Production

To build a production Docker image, you can use the provided `Dockerfile`:

```bash
docker build -t certauth-app .
```

## Development Conventions

*   **Logging**: The application uses the standard `log/slog` library for logging. In a local development environment, logs are colored for better readability. In a containerized environment, logs are not colored.
*   **Configuration**: The application is configured using environment variables. A `PROFILE` environment variable can be used to select a predefined configuration profile (`isbe-dev`, `isbe-pre`, `isbe-pro`). Sensitive information like database credentials and API keys are provided through separate environment variables.
*   **Database**: The application uses a SQLite database. Migrations are handled by the application itself.
*   **Testing**: The project contains unit tests for some of its packages. To run the tests, you can use the `go test` command.

```bash
go test ./...
```
