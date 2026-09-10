# CertAuth Metrics Documentation

The CertAuth service exposes Prometheus metrics at the `/metrics` endpoint. 
These metrics are generated using `ansrivas/fiberprometheus/v2` and include standard Go runtime metrics as well as HTTP request metrics.

## Endpoint
`GET /metrics`

No authentication is currently required for this endpoint.

## Metric Labels
All HTTP metrics include the following common labels:
- `service`: "certauth" (The name of this service)
- `method`: HTTP method (e.g., "GET", "POST")
- `path`: The registered route path (e.g., "/health", "/oidc/authorize")
- `status`: HTTP status code (e.g., "200", "500")

## HTTP Metrics

### `http_requests_total`
- **Type**: Counter
- **Description**: Total number of HTTP requests processed, partitioned by status code, method, and path.
- **Usage**: Use `rate()` to calculate requests per second (RPS).

### `http_request_duration_seconds`
- **Type**: Histogram
- **Description**: The duration of HTTP requests in seconds.
- **Buckets**: Default buckets are used (def `[.005 .01 .025 .05 .1 .25 .5 1 2.5 5 10]`).
- **Usage**: Use `histogram_quantile(0.95, ...)` to calculate 95th percentile latency.

### `http_requests_in_progress_total`
- **Type**: Gauge
- **Description**: The number of inflight requests currently being processed.

## Runtime Metrics
Standard Go runtime metrics are also exposed, including:
- `go_goroutines`: Number of goroutines that currently exist.
- `go_memstats_*`: Memory usage statistics.
- `process_cpu_seconds_total`: Total user and system CPU time spent in seconds.
