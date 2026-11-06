# tsaservice — RFC 3161 timestamping and verification

The onboarding flow timestamps the evidence of every registration with an
external Time Stamping Authority (TSA, currently DigitelTS). This package is the
client for that TSA and a strict verifier for the tokens it returns.

## Architecture

```
certauthserver (contract acceptance, admin update)
   │  ctx + correlation id (auth_code)
   ▼
database.CreateRegistration / UpdateRegistration
   │  evidence = contract PDF || eidas_cert   (database.TimestampedEvidence)
   ▼
tsaservice.TSAService.Timestamp(ctx, evidence)
   ├─ build TimeStampReq (SHA-512 imprint, 64-bit random nonce, certReq, optional reqPolicy)
   ├─ HTTPS POST, Basic auth, timeout, no redirects, 1 MiB response limit
   └─ Verifier.verifyResponse (fail closed) ──► Token{Response DER, GenTime, ...}
   ▼
registrations row: timestamp = DER TimeStampResp, created_at = genTime, contract file on disk
```

| File | Responsibility |
|------|----------------|
| `config.go` | `TSAConfig`, defaults, validation, `ApplyEnv`, redaction in logs |
| `tsaservice.go` | `TSAService` (HTTP exchange, logging, metrics) and `Verifier` |
| `request.go` | `TimeStampReq` encoding and nonce generation |
| `parse.go` | strict DER parser (cryptobyte) for TimeStampResp / CMS / TSTInfo |
| `verify.go` | verification policy |
| `trust.go` | trust store loading, pins, embedded DigitelTS bundle |
| `revocation.go` | optional CRL checking |
| `metrics.go` | Prometheus metrics |
| `tsatest/` | in-process fake TSA and test PKI (tests only) |
| `trust/digitelts/` | embedded public certificates (see below) |
| `eudss.go` | unrelated EU DSS certificate check, kept unchanged |

### Why no CMS library

The candidates were evaluated (November 2026):

* `github.com/digitorus/timestamp` + `digitorus/pkcs7` (used by sigstore): the
  current versions require Go ≥ 1.27; the project builds with Go 1.25/1.26.
* `github.com/smallstep/pkcs7` (maintained fork of `mozilla/pkcs7`): verifies the
  signature over **re-encoded** signed attributes (`marshalAttributes`) instead of
  the received bytes, does not support `SubjectKeyIdentifier` signer
  identifiers, and does not know RFC 3161.

The parser therefore uses `golang.org/x/crypto/cryptobyte` (already a
dependency), which enforces DER lengths and rejects trailing data. The
signature is verified over the signed attributes **exactly as received**, with
only the `[0]` tag replaced by `SET` (RFC 5652 §5.4). Signature primitives come
from the Go standard library. A real DigitelTS token is part of the tests and
gives the same result as `openssl ts -verify` (OpenSSL 3.5).

## Verification policy

A token is accepted only if **all** these checks pass (`verify.go`):

1. `TimeStampResp` is a single DER structure; PKIStatus is `granted` or
   `grantedWithMods`; a token is present.
2. The token is a CMS `ContentInfo`/`SignedData` v3 encapsulating `id-ct-TSTInfo`
   with exactly one `SignerInfo` (RFC 3161 §2.4.2).
3. `TSTInfo` v1 parses strictly (GeneralizedTime with optional fractional seconds).
4. MessageImprint algorithm ∈ {SHA-256, SHA-384, SHA-512} and the digest matches
   the data (for new requests: same algorithm and digest as requested).
5. Nonce equals the request nonce (new requests, unless disabled).
6. Policy equals `TSA_POLICY_OID` when configured.
7. No unknown critical `TSTInfo` extensions.
8. The signer certificate is in the token and matches the `SignerInfo` identifier
   (issuer+serial or SKI, with the matching `SignerInfo` version).
9. Signed attributes are present: `content-type` = id-ct-TSTInfo,
   `message-digest` = hash of the TSTInfo, `CMSAlgorithmProtection` consistent
   when present (RFC 6211), and an ESS `signing-certificate(-v2)` whose first
   `ESSCertID` hashes to the signer certificate and whose `IssuerSerial`, if
   present, matches it (RFC 5035/5816).
10. Digest algorithm ∈ {SHA-256, SHA-384, SHA-512}; signature RSA PKCS#1 v1.5,
    RSA-PSS or ECDSA (P-256/384/521); RSA ≥ 2048 bits; the hash named by the
    signature algorithm must equal the digest algorithm.
11. The signature verifies over the received signed attributes.
12. The signer chains to a configured trust anchor, **at genTime**, through the
    token certificates and configured intermediates, with every CA allowed to
    issue time-stamping certificates.
13. The signer has exactly one, critical, EKU `id-kp-timeStamping` (RFC 3161 §2.3)
    and a key usage allowing signatures.
14. `TSTInfo.tsa`, when it is a directoryName, equals the signer subject.
15. New tokens only: genTime within the request window ± `MaxClockSkew` (5 min).
16. New tokens only, with `TSA_REVOCATION_CHECK=crl`: no certificate of the chain
    is listed in its issuer's CRL (signature-checked, not stale). Unavailable
    revocation information fails the request.

Historical verification (`Verifier.Verify`, `tsatool verify-registration`)
applies 1–14 with the chain evaluated at genTime. It does not check nonce,
freshness or current revocation status.

### What this does not prove

A valid token proves that a TSA certified by the configured anchors asserted
genTime for the data. It does **not** by itself establish that the token is an
**eIDAS qualified electronic time stamp**. That requires, at genTime, the TSA unit
being listed as a `QTST` service with status *granted* in the EU Trusted Lists
(here the Spanish TSL), and the token being issued under the qualified policy.
For reference, on 2026-11-06 the Spanish TSL lists the DigitelTS TSUs
`DIGITEL TS QUALIFIED TSU 01 G1…G8` (issued by `DIGITEL TS QUALIFIED CA TSA G1`)
as granted QTST services, and the sample token carries an ETSI qcStatement
extension. No legal conclusion is drawn here; a TSL-based check can be built on
`cmd/eutl`.

## Trust store

Default: the embedded DigitelTS bundle in `trust/digitelts/` (public certificates,
no secrets):

| File | Subject | SHA-256 |
|------|---------|---------|
| `root-ca.pem` (anchor) | DIGITEL TS CA ROOT 01 | `011e258310b37f92030d14a672079507632cf72789fc101ce0a0bdc5ef2808cc` |
| `qualified-ca-tsa-g1.pem` (intermediate) | DIGITEL TS QUALIFIED CA TSA G1 | `1c1e385cc2b7e02d337531150af065514b733beb702a8bdbd286e706055a0df7` |

Provenance (checked 2026-11-06): both downloaded over HTTPS from
`pki.digitelts.es` (identical to the HTTP copies); the root verifies the
signature of `DIGITEL TS QUALIFIED CA G1`, which is published in the Spanish
Trusted List (`tsl.digital.gob.es`, located through the EU LOTL); the
intermediate is the AIA `caIssuers` of the TSU certificate; the chain
TSU → CA TSA G1 → root verifies with OpenSSL 3 for purpose `timestampsign`.

**Root cause of the old bypass**: DigitelTS tokens only carry the TSU
certificate, not `CA TSA G1`. With only the root configured, path validation
always failed, which is consistent with the `if true { return }` shortcut that
disabled verification.

Overrides, in order of precedence:

* `TSA_TRUST_ANCHORS_FILE` — PEM bundle mounted in the container (preferred for
  another provider or a renewed hierarchy).
* `TSA_TRUST_ANCHORS_PEM` — the same as an environment variable.
* `TSA_CA_CERT_URL` — legacy download at start-up. Requires
  `TSA_TRUST_ANCHOR_SHA256` (except in the `local` profile); HTTP is acceptable
  only because the pin authenticates the content. Redirects are not followed.
* `TSA_TRUST_ANCHOR_SHA256` — comma-separated SHA-256 pins; every loaded anchor
  must match one. Use it also with files to detect accidental substitution.
* `TSA_INTERMEDIATES_FILE` — extra intermediates (e.g. when the provider renews
  its TSA CA). Intermediates are not trusted by themselves: they must chain to an anchor.

Renewal: add the new intermediate/anchor to a PEM bundle (keep the old ones, so
that historical tokens still validate at their genTime), deploy, then remove
obsolete ones only when no evidence depends on them.

## Configuration

| Variable | Default | Notes |
|----------|---------|-------|
| `TSA_URL` | none (`local`: DigitelTS pre-production) | Required outside `local`. HTTPS only, no credentials in the URL. |
| `TSA_USER` / `TSA_USER_FILE` | none | Required. `_FILE` reads a mounted secret. |
| `TSA_PASSWORD` / `TSA_PASSWORD_FILE` | none | Required. Never logged. |
| `TSA_TRUST_ANCHORS_FILE` / `_PEM` | embedded | See trust store. |
| `TSA_CA_CERT_URL` | unset | Legacy; needs a pin. |
| `TSA_TRUST_ANCHOR_SHA256` | unset | Pins. |
| `TSA_INTERMEDIATES_FILE` | unset | |
| `TSA_HASH_ALGORITHM` | `sha512` | `sha256`, `sha384`, `sha512`. Kept at SHA-512, which DigitelTS accepts (all stored tokens use it). |
| `TSA_POLICY_OID` | unset | E.g. `0.4.0.2023.1.1` (the policy of current DigitelTS tokens) once confirmed with the provider. |
| `TSA_NONCE` | `true` | `false` only if the provider cannot echo nonces. |
| `TSA_TIMEOUT` | `30s` | Max `2m`. |
| `TSA_REVOCATION_CHECK` | `none` | `crl` to check CRLs on every new token. |

The legacy `secrets/config.yaml` (`tsa.user`, `tsa.password`) is still read when
the variables are absent. There are no built-in credentials.

## Requests, retries and limits

* One HTTP request per registration, no automatic retries: each request may be
  billed and produces a distinct token; the user can retry the acceptance.
* `context.Context` from the HTTP handler is propagated; cancellation aborts the request.
* Responses over 1 MiB are rejected; error bodies are discarded, never logged.
* 401/403 → `ErrAuthentication`, 429 → `ErrRateLimited`, 5xx → `ErrServiceUnavailable`,
  other statuses (including redirects) → `ErrUnexpectedHTTPStatus`.

## Observability

Log lines (slog, `component=tsa`): `TSA service configured` (redacted config),
`TSA trust anchor loaded`, `TSA timestamp request started`, `TSA HTTP response
received`, `TSA token verified` (genTime, token serial, policy, signer and its
fingerprint), `TSA request failed` (`reason`, `http_status`), `TSA token
verification failed` (`reason`). Each operation has an `op_id`; registrations
add `correlation_id` (the auth code). Passwords, `Authorization` headers and
response bodies are never logged.

Metrics on `/metrics`:

* `tsa_requests_total{outcome}` — `success`, `transport_error`, `http_error`, `rejected`, `verification_failed`
* `tsa_request_duration_seconds{outcome}`
* `tsa_errors_total{reason}` — `auth`, `rate_limited`, `server_error`, `http_status`, `timeout`, `canceled`, `network`, `response_too_large`, `rejected`, `malformed`, `internal`
* `tsa_verification_failures_total{reason}` — the `Reason*` constants in `errors.go`

There is deliberately no HTTP endpoint that requests timestamps (it would spend
provider quota); `/health` is unchanged. Use `tsatool probe` for a manual check.

## Evidence format and historical tokens

The timestamped data is `contract PDF bytes || eidas_cert` (the base64 DER text
stored in the `eidas_cert` column), built by `database.TimestampedEvidence`.
Every stored token uses it, with a SHA-512 imprint. It is kept unchanged so that
all existing tokens keep verifying. It is not self-delimiting; a versioned,
length-delimited, domain-separated format (e.g. a DER `SEQUENCE { version,
"isbe-onboarding-evidence", contractHash, certificate }`) would be better but
needs a new column recording the format version of each token, so it is left
for a separate change.

Verify stored evidence (read-only, no TSA call, no credentials):

```bash
go run ./cmd/tsatool verify-registration -db data/onboard.db -org VATES-B12345678
```

The verifier needs the contract file referenced by `contract_document` and the
`eidas_cert` value exactly as stored. Long-term validation of old tokens also
needs revocation information archived at genTime (not stored today), or a
re-timestamp before the TSA certificate expires (G3 TSU: 2029-03-14).

### Known limitations

* **Evidence framing**: `contract || eidas_cert` has no separator, so a token for
  (C, X) also verifies for any (C', X') with C'||X' = C||X. Exploiting it requires
  write access to the database row or the contract file. Fixed only by the
  versioned format above (separate ticket).
* **Stored response is not bit-unique**: fields outside the signature (PKIStatus
  text, extra certificates, `crls`, unsigned attributes) can change without
  affecting verification. The asserted time and imprint cannot. If bit-exact
  integrity of the stored blob matters, store its hash at creation time.
* **Backdating after key compromise**: historical verification validates the
  chain at the token's own genTime. A TSU key leaked after its certificate expired
  could produce backdated tokens that pass. Countering that needs revocation
  data archived at genTime or re-timestamping (long-term validation).
* **Revocation** is off by default (`TSA_REVOCATION_CHECK=none`). Partitioned
  CRLs (IssuingDistributionPoint) are treated as complete.

## Tests

```bash
go test ./tsaservice/... ./database/...          # unit + end-to-end, no network
go test -tags integration ./tsaservice/ -run TestTimestampAndVerify   # REAL TSA, manual only
```

The integration tests need real credentials in the environment and consume
quota; they are excluded from the default build and must not run in CI.
