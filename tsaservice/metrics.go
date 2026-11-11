package tsaservice

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Prometheus metrics. They are not registered anywhere by this package: the
// HTTP server must call RegisterMetrics on the registry it serves at /metrics
// (fiberprometheus.New uses a private registry, not the default one). Every
// label has a small, fixed set of values (see outcome* and Reason* constants).
var (
	metricRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_requests_total",
		Help: "Timestamp requests sent to the TSA, by outcome.",
	}, []string{"outcome"})

	metricDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tsa_request_duration_seconds",
		Help:    "Duration of a timestamp operation (HTTP exchange plus verification), by outcome.",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
	}, []string{"outcome"})

	metricErrors = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_errors_total",
		Help: "Errors communicating with the TSA, by reason.",
	}, []string{"reason"})

	metricVerificationFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_verification_failures_total",
		Help: "Timestamp tokens rejected by the verifier, by reason.",
	}, []string{"reason"})
)

// The outcome series are created at zero so that /metrics shows the TSA
// metrics right after start-up and rate() alerts work before the first request.
func init() {
	for _, o := range []string{outcomeSuccess, outcomeTransportError, outcomeHTTPError, outcomeRejected, outcomeVerificationFailed} {
		metricRequests.WithLabelValues(o)
		metricDuration.WithLabelValues(o)
	}
}

// Collectors returns the TSA metrics, for registration on a Prometheus registry.
func Collectors() []prometheus.Collector {
	return []prometheus.Collector{metricRequests, metricDuration, metricErrors, metricVerificationFailures}
}

// RegisterMetrics registers the TSA metrics on reg. A collector may be
// registered on several registries; registering twice on the same one fails.
func RegisterMetrics(reg prometheus.Registerer) error {
	for _, c := range Collectors() {
		if err := reg.Register(c); err != nil {
			return err
		}
	}
	return nil
}

// Outcomes of a timestamp operation (label "outcome").
const (
	outcomeSuccess            = "success"
	outcomeTransportError     = "transport_error"
	outcomeHTTPError          = "http_error"
	outcomeRejected           = "rejected"
	outcomeVerificationFailed = "verification_failed"
)

// Transport error reasons (label "reason" of tsa_errors_total).
const (
	errReasonAuth          = "auth"
	errReasonRateLimited   = "rate_limited"
	errReasonServerError   = "server_error"
	errReasonHTTPStatus    = "http_status"
	errReasonTimeout       = "timeout"
	errReasonCanceled      = "canceled"
	errReasonNetwork       = "network"
	errReasonTooLarge      = "response_too_large"
	errReasonRejected      = "rejected"
	errReasonMalformed     = "malformed"
	errReasonInternalError = "internal"
)
