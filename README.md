# Onboarding in ISBE with eIDAS certificate of representation

This project implements the onboarding application of ISBE, where the users are authenticated using their eIDAS certificate of representation.

The eIDAS certificate of the users is validated against the EU Trusted Lists (https://eidas.ec.europa.eu/efda/trust-services/browse/eidas/tls), ensuring the association of the certificate with the real-world identity of the user, as a natural person who is a legal representative of an organization.

## Deployment

The deployment of this project is very simple using Docker. With other infrastructure, it should be very simple to map into its requirements.

The project includes a Dockerfile which can be used to generate a Docker image. When creating a container instance, the folowing environment variables have to be provided.

- `PROFILE`: Optional. The profile to use. If you omit it, the default is `local`. The available profiles are `isbe-dev`, `isbe-pre`, `isbe-pro`.
- `SMTP_USERNAME`: The username for the SMTP server used to send emails to the end-users.
- `SMTP_PASSWORD`: The password for the SMTP server.
- `TSA_USER`: The username for the TSA (Timestamping Authority) server, used to timestamp the act of user acceptance of the terms of service.
- `TSA_PASSWORD`: The password for the TSA server.

The `PROFILE` environment variable is used to select the profile to use for a deployment in ISBE. The available profiles are `isbe-dev`, `isbe-pre` and `isbe-pro`. Selecting a profile will configure the application with the appropriate values for the target environment.

The other four environment variables are required for all profiles. You should ask your systems administyrator for the appropriate values for your environment.

## Configuration Reference

The following environment variables can be used to override configuration values of the standard profiles:

| Variable | Description | Default |
|----------|-------------|---------|
| `CERTAUTH_URL` | Base URL for the CertAuth service | Profile dependent |
| `CERTAUTH_PORT` | Port for CertAuth service | `8010` |
| `CERTSEC_URL` | URL for the mTLS CertSec service | Profile dependent |
| `CERTSEC_PORT` | Port for CertSec service | `8011` |
| `ONBOARD_URL` | URL for the Onboard service | Profile dependent |
| `ONBOARD_PORT` | Port for Onboard service | `8012` |
| `TSA_URL` | Timestamp Authority URL | `https://timestamp-service...` |
| `MANAGEMENT_URL` | Management Service URL | Profile dependent |
| `CERTAUTH_LOGS_NOCOLOR` | Set to "true" to disable log coloring | `false` |

## Observability

The onboard application exposes Prometheus metrics at the `/metrics` endpoint of the CertAuth service. 
These metrics include standard Go runtime metrics as well as HTTP request metrics.

### Endpoint
`GET /metrics`

No authentication is currently required for this endpoint.

### Metric Labels
All HTTP metrics include the following common labels:
- `service`: "certauth" (The name of this service)
- `method`: HTTP method (e.g., "GET", "POST")
- `path`: The registered route path (e.g., "/health", "/oidc/authorize")
- `status`: HTTP status code (e.g., "200", "500")

### HTTP Metrics

#### `http_requests_total`
- **Type**: Counter
- **Description**: Total number of HTTP requests processed, partitioned by status code, method, and path.
- **Usage**: Use `rate()` to calculate requests per second (RPS).

#### `http_request_duration_seconds`
- **Type**: Histogram
- **Description**: The duration of HTTP requests in seconds.
- **Buckets**: Default buckets are used (def `[.005 .01 .025 .05 .1 .25 .5 1 2.5 5 10]`).
- **Usage**: Use `histogram_quantile(0.95, ...)` to calculate 95th percentile latency.

#### `http_requests_in_progress_total`
- **Type**: Gauge
- **Description**: The number of inflight requests currently being processed.

### Runtime Metrics
Standard Go runtime metrics are also exposed, including:
- `go_goroutines`: Number of goroutines that currently exist.
- `go_memstats_*`: Memory usage statistics.
- `process_cpu_seconds_total`: Total user and system CPU time spent in seconds.


## The authentication flow

The overall flow is the following. There are several actors:

- The application, acting as an OpenID Relying Party (RP). When the application wants to authenticate a user, it uses the OIDC Authentication Code Flow to pass control to the CertAuth server, which acts as an OpenID Provider (OP). The OP runs in a domain of its own (e.g. certauth.mycredential.eu).
- The OpenID Provider (OP) authenticates the user. It presents a screen describing what is going to happen, and allows the user to click a button to request the eIDAS certificate from the browser. It asks for consent to the user.
- The button redirects the user to another domain (eg. certsec.mycredential.eu). This domain is configured in the reverse proxy (we use Caddy for the examples, but any other reverse proxy would work with the proper configuration) to ask for a client certificate.

For example, in Caddy it is done with:

```
(client_auth) {
    tls {
        client_auth {
            mode require
        }
    }
}
```

- When the user's browser starts the TLS session, it presents a popup to the user to select one of the certificates in the keystore of the user machine. It even allows the user to use a smartcard or any other supported mechanism in the client machine.

- The user selects the certificate to be used (we require an eIDAS certificate, more on this later), and the browser starts the TLS session. The reverse proxy then sends the certificate to our server (at the internal port assigned to the domain certsec.mycredential.eu). In Caddy, this is done with:

```
certsec.mycredential.es {
    import client_auth
    reverse_proxy localhost:8090 {
        header_up tls-client-certificate {http.request.tls.client.certificate_der_base64}
    }   
}
```

- Caddy sends the certificate in an HTTP header (our default is `tls-client-certificate`).
- Our application receives the certificate, decodes it and extracts the user information from the certificate, mainly the Subject field.
- For this application, we require the certificate to be an "organizational" certificate, that is, either a certificate for seals (QSeal), or a certificate of representation (a QSign where the user is associated to the organization that represents). In both certificates, the Subject field contains the `organizationIdentifier` (OID 2.5.4.97). For details, see the `x509util` package in this project.
- Once this is done, the certsec.mycredential.eu server sends back to the certauth.mycredential.eu server the information about the user (essentially the fields in the Subject field of the certificate).
- The certauth server then responds back to the RP using the standard OIDC mechanism (specifically Authentication Code Flow). The user information is in the ID Token, as usual, using the standard claims when appropriate, but with claims defined to suit our needs if there are no standard claims.
- The RP then uses that information to welcome the user or whatever the application requires. The RP can also request an access token from the OP. In our simple OP, we will not support token refresh.



NOTE:
This server is based on code from [ORY Fosite example](https://github.com/ory/fosite-example) for the OpenID Provider functionality. The code maintains the copyright and attributions, but it removes unneccesary code to help keep this server simple and understandable.

# Development Guide & Workflow

We use the development workflow described below. It is designed for small teams, to be simple and with predictable deployments.

---

## 1. Branches and Environments

The repository maintains two permanent branches connected to deployment environments:

| Branch | Target Environment | Description | Direct Push Allowed? |
| :--- | :--- | :--- | :--- |
| `main` | **Production** | Production-ready, stable releases. | ❌ No (PR only) |
| `development` | **Testing** | Active integration branch. Automatically deployed to the testing and preproduction environments. | ❌ No (PR only) |
| `feat/*`, `fix/*` | Local / Preview | Short-lived feature and bug fix branches. | ✅ Author only |

---

## 2. Branch Naming Conventions

All temporary branches must follow the standard categorized structure using forward slashes (`/`):

```text
<category>/<short-description>
```

### Categories (`<category>`)

- `feat/` — New feature or capability (e.g. `feat/oidc-memory-cache`, `feat/42-error-pages`)
- `fix/` — Bug fix (e.g. `fix/cert-validation-null-check`, `fix/88-port-mismatch`)
- `refactor/` — Code restructuring with no behavior changes (e.g. `refactor/errl-formatting`)
- `chore/` — Build system, CI, dependencies, or tool updates (e.g. `chore/bump-go-1-25`)
- `docs/` — Documentation changes only (e.g. `docs/update-readme`)
- `test/` — Adding or modifying unit/integration tests (e.g. `test/x509-parser`)

### Rules
1. **Lowercase and hyphens only (`kebab-case`)**:
   - ✅ `feat/custom-errors`
   - ❌ `feat/custom_errors`
   - ❌ `feat/CustomErrors` (mixing cases causes issues across Linux, macOS, and Windows filesystems).
2. **Keep it concise**: 2 to 4 words describing the functional area.
3. **No standalone prefixes**: Never create a branch named solely `feat` or `fix`, as Git's directory-based ref storage will prevent creating child branches like `feat/login`.

---

## 3. Developer Lifecycle

### Step 1: Start from the Latest `development`
Before starting any new work, update your local `development` branch and branch off it:

```bash
git checkout development
git pull origin development
git checkout -b feat/your-feature-name
```

### Step 2: Code & Local Verification
Before opening a Pull Request, format the code and run all tests locally:

```bash
# Format source code
go fmt ./...

# Run static analysis
go vet ./...

# Run unit tests
go test ./...
```

### Step 3: Push and Open a PR into `development`
Push your branch to GitHub:

```bash
git push -u origin feat/your-feature-name
```

1. Open a Pull Request on GitHub:
   - **Base:** `development` $\leftarrow$ **Compare:** `feat/your-feature-name`
2. Request a review from a teammate.
3. Once approved, merge using **"Squash and merge"** (to keep history clean).
4. Delete the remote feature branch.
5. CI/CD will deploy `development` to the **Testing environment** for end-to-end verification.

### Step 4: Promote to Production (`development` $\rightarrow$ `main`)
When features on `development` are verified in DEV and PRE and ready for release:

1. Open a Pull Request from `development` to `main`:
   - **Base:** `main` $\leftarrow$ **Compare:** `development`
2. Merge using **"Create a merge commit"** (records the release milestone).
3. CI/CD automatically deploys `main` to **Production**.

### Step 5: Post-Release Synchronization
Because GitHub creates a merge commit on `main`, pull that commit back into `development` right after the release to ensure `development` stays up-to-date with `main` (`0 behind`):

```bash
git checkout development
git pull origin main
git push origin development
```

---

## 4. Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) convention:

```text
<type>: <short imperative summary>
```

### Examples
- `feat: display specific error message when personal certificates are rejected`
- `fix: update healthcheck port to match server configuration in Dockerfile`
- `refactor: replace fmt.Errorf with errl.Errorf for improved error handling`
- `docs: add development workflow and branching guide`

---

## 5. Recommended Repository Settings (Admins)

To protect the workflow across the team, configure the following in the GitHub repository settings:

1. **Branch Protection Rules** (`Settings` $\rightarrow$ `Branches`):
   - Protect both `main` and `development`.
   - Enable **Require a pull request before merging**.
   - Require at least 1 approval.
   - Require status checks (e.g., CI tests) to pass before merging.
2. **Auto-delete head branches** (`Settings` $\rightarrow$ `General`):
   - Enable **Automatically delete head branches** to avoid clutter from merged feature branches.
3. **Merge Button Configurations**:
   - Allow **Squash merging** (ideal for `feature/*` $\rightarrow$ `development`).
   - Allow **Merge commits** (ideal for `development` $\rightarrow$ `main`).


## 6. Quick Start (Local Development)

To run the application locally with Docker:

### Prerequisites
1. Docker and Docker Compose installed
2. Add to `/etc/hosts`:
   ```bash
   127.0.0.1 certauth.localhost
   127.0.0.1 certsec.localhost
   127.0.0.1 onboard.localhost
   ```

### Setup and Run

```bash
# 1. Create test certificates
chmod +x create-test-cert.sh && ./create-test-cert.sh

# 2. (macOS) Install CA certificate to avoid browser warnings
chmod +x install-cert.sh && ./install-cert.sh

# 3. Import client certificate to your browser
# Import certs/client.p12 (password: test)

# 4. Start services
docker-compose up -d

# 5. Open browser
# Visit https://onboard.localhost and test the flow
```

### Local Development Features

When running with `PROFILE=local` (default):
- **Email verification bypass**: Codes displayed on screen, SMTP failures non-blocking
- **Certificate validation**: Self-signed certificates accepted with warnings
- **Test data**: Sample certificates with all required eIDAS fields

### Service URLs
- **Onboard** (user registration): https://onboard.localhost
- **CertAuth** (OpenID Provider): https://certauth.localhost  
- **CertSec** (mTLS authentication): https://certsec.localhost

### Complete Documentation
See [DOCKER_SETUP.md](DOCKER_SETUP.md) for detailed setup, troubleshooting, and configuration options.
