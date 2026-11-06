package tsaservice

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics. They are registered in the default registry, which is
// the one exposed by fiberprometheus at /metrics. Every label has a small,
// fixed set of values (see outcome* and Reason* constants).
var (
	metricRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_requests_total",
		Help: "Timestamp requests sent to the TSA, by outcome.",
	}, []string{"outcome"})

	metricDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "tsa_request_duration_seconds",
		Help:    "Duration of a timestamp operation (HTTP exchange plus verification), by outcome.",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
	}, []string{"outcome"})

	metricErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_errors_total",
		Help: "Errors communicating with the TSA, by reason.",
	}, []string{"reason"})

	metricVerificationFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "tsa_verification_failures_total",
		Help: "Timestamp tokens rejected by the verifier, by reason.",
	}, []string{"reason"})
)

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
