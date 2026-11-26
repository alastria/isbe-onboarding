package tsaservice

import (
	"errors"
	"fmt"
)

// Sentinel errors. Callers should use errors.Is to classify a failure. None of
// the error messages produced by this package contain credentials or raw
// response bodies.
var (
	// ErrInvalidConfig is returned when the TSA configuration is incomplete or unsafe.
	ErrInvalidConfig = errors.New("invalid TSA configuration")

	// ErrAuthentication is returned when the TSA answers 401 or 403.
	ErrAuthentication = errors.New("TSA rejected the credentials")
	// ErrRateLimited is returned when the TSA answers 429.
	ErrRateLimited = errors.New("TSA rate limit exceeded")
	// ErrServiceUnavailable is returned for 5xx answers.
	ErrServiceUnavailable = errors.New("TSA service unavailable")
	// ErrUnexpectedHTTPStatus is returned for any other non-200 answer, including redirects.
	ErrUnexpectedHTTPStatus = errors.New("unexpected HTTP status from TSA")
	// ErrTimeout is returned when the request exceeds the configured timeout or the context deadline.
	ErrTimeout = errors.New("TSA request timed out")
	// ErrCanceled is returned when the caller's context is canceled.
	ErrCanceled = errors.New("TSA request canceled")
	// ErrNetwork is returned for connection-level failures.
	ErrNetwork = errors.New("network error talking to TSA")
	// ErrResponseTooLarge is returned when the response exceeds the size limit.
	ErrResponseTooLarge = errors.New("TSA response too large")

	// ErrMalformedResponse is returned when the response is not valid RFC 3161 DER.
	ErrMalformedResponse = errors.New("malformed RFC 3161 response")
	// ErrTimestampRejected is returned when the TSA answers with a PKIStatus other than granted.
	ErrTimestampRejected = errors.New("TSA rejected the timestamp request")
	// ErrVerificationFailed is returned (wrapped in a *VerificationError) when any
	// mandatory verification check fails.
	ErrVerificationFailed = errors.New("timestamp token verification failed")
)

// Verification failure reasons. They are used as the "reason" label of the
// tsa_verification_failures_total metric, so the set must stay small and fixed.
const (
	ReasonMalformed        = "malformed"
	ReasonStatus           = "status"
	ReasonImprint          = "imprint"
	ReasonNonce            = "nonce"
	ReasonPolicy           = "policy"
	ReasonAlgorithm        = "algorithm"
	ReasonSigner           = "signer"
	ReasonSignedAttributes = "signed_attributes"
	ReasonESS              = "ess"
	ReasonSignature        = "signature"
	ReasonChain            = "chain"
	ReasonEKU              = "eku"
	ReasonTime             = "time"
	ReasonRevocation       = "revocation"
	ReasonExtension        = "extension"
)

// VerificationError describes why a time-stamp token was not accepted.
type VerificationError struct {
	Reason string
	Err    error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("timestamp token verification failed (%s): %v", e.Reason, e.Err)
}

func (e *VerificationError) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrVerificationFailed) true for every VerificationError.
func (e *VerificationError) Is(target error) bool { return target == ErrVerificationFailed }

func verificationErrorf(reason, format string, args ...any) error {
	return &VerificationError{Reason: reason, Err: fmt.Errorf(format, args...)}
}

// reasonOf returns the verification reason of err, or "" if err is not a VerificationError.
func reasonOf(err error) string {
	var ve *VerificationError
	if errors.As(err, &ve) {
		return ve.Reason
	}
	return ""
}
