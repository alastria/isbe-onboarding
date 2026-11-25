package certauth

import (
	"context"
	"errors"
	"log/slog"

	"github.com/alastria/isbe-onboarding/internal/certpolicy"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/util/x509util"
	"github.com/alastria/isbe-onboarding/types"
)

// certificateTrust is the policy under which a certificate is accepted, if any.
type certificateTrust int

const (
	// trustRejected: the certificate satisfies no policy.
	trustRejected certificateTrust = iota
	// trustEIDAS: validated by EU DSS against the EU Trusted Lists (unchanged policy).
	trustEIDAS
	// trustManualApproval: not validated as eIDAS, but explicitly approved in the whitelist
	// for this organization and compliant with the configured alternative trust policy.
	trustManualApproval
	// trustUnverified: accepted without validation outside production (test/demo mode, as before).
	trustUnverified
)

func (t certificateTrust) String() string {
	switch t {
	case trustEIDAS:
		return "eidas"
	case trustManualApproval:
		return "manual_approval"
	case trustUnverified:
		return "unverified_non_production"
	default:
		return "rejected"
	}
}

// errManualPolicyNotConfigured is returned for a manually approved certificate that is not
// eIDAS when the alternative trust policy is not configured in production.
var errManualPolicyNotConfigured = errors.New("the trust policy for manually approved certificates is not configured")

// trustDecision is the result of evaluating the trust policies for a certificate.
type trustDecision struct {
	trust certificateTrust

	// Result of the eIDAS validation (EU DSS)
	eidasServiceError    error
	eidasValidationError error

	// The certificate is in the whitelist for its organization identifier
	manuallyApproved bool
	// Why a manually approved certificate failed the alternative policy
	manualPolicyError error
}

// manualPolicyUnavailable reports a temporary failure (revocation status or whitelist
// lookup), so that the user is told to try again later instead of "invalid certificate".
func (d trustDecision) manualPolicyUnavailable() bool {
	return errors.Is(d.manualPolicyError, certpolicy.ErrRevocationUnavailable) || errors.Is(d.manualPolicyError, errWhitelistUnavailable)
}

// accepted reports whether the certificate is accepted under some policy.
func (d trustDecision) accepted() bool {
	return d.trust == trustEIDAS || d.trust == trustManualApproval || d.trust == trustUnverified
}

// errCertificateNotAccepted is returned by the steps of the certificate flow that follow the
// trust evaluation when the certificate of the process was not accepted by it.
var errCertificateNotAccepted = errors.New("the certificate of this authentication process has not been accepted")

// getAcceptedCertificateProcess returns the authentication process only if CertAuth accepted
// its current certificate under a trust policy. It guards the steps after pageRequestEmail.
func (s *CertAuthServer) getAcceptedCertificateProcess(authCode string) (*models.AuthProcess, error) {
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		return nil, err
	}
	if !authProcess.CertificateAccepted() {
		slog.Warn("Certificate flow step requested without an accepted certificate", "auth_code", authCode)
		return nil, errCertificateNotAccepted
	}
	return authProcess, nil
}

var errWhitelistUnavailable = errors.New("the whitelist of approved certificates could not be consulted")

// evaluateCertificateTrust decides under which policy, if any, the certificate is accepted.
//
//  1. eIDAS: the existing EU DSS validation. When it passes, nothing else is evaluated, and
//     this is the only way to get EIDASCertificate = true.
//  2. Manual approval: the certificate has no organizationIdentifier of its own, its exact
//     SHA-256 fingerprint is approved for certData.OrganizationID, and it satisfies the
//     configured alternative trust policy (chain to the CAs of MANUAL_APPROVAL_CA_FILE, validity,
//     key usage, revocation). A whitelisted certificate that fails the policy is rejected in
//     every profile when the policy is configured. In production, the policy must be configured.
//  3. Otherwise the previous behaviour is kept: rejected in production (except the existing
//     test organization), accepted with a warning in the other profiles.
func (s *CertAuthServer) evaluateCertificateTrust(ctx context.Context, certData *models.CertificateData) trustDecision {
	var d trustDecision

	_, d.eidasServiceError, d.eidasValidationError = s.verifyEIDAS(certData.CertificateDER, s.euDSSURL)
	if d.eidasServiceError == nil && d.eidasValidationError == nil {
		d.trust = trustEIDAS
		return d
	}

	approved, err := s.isManuallyApproved(certData)
	if err != nil {
		d.manuallyApproved = true // treat as the manual path, failing closed
		d.manualPolicyError = err
		d.trust = trustRejected
		return d
	}

	if approved {
		d.manuallyApproved = true
		switch {
		case s.manualApproval != nil:
			if _, err := s.manualApproval.Verify(ctx, certData.Certificate); err != nil {
				d.manualPolicyError = err
				d.trust = trustRejected
				return d
			}
			d.trust = trustManualApproval
			return d
		case s.profile == types.PROFILE_ISBE_PRO:
			d.manualPolicyError = errManualPolicyNotConfigured
			d.trust = trustRejected
			return d
		}
		// Outside production, without the policy configured, fall through to the previous behaviour
	}

	if s.profile == types.PROFILE_ISBE_PRO && certData.OrganizationID != "VATES-12345678J" {
		d.trust = trustRejected
		return d
	}
	d.trust = trustUnverified
	return d
}

// isManuallyApproved reports whether the certificate was accepted by CertSec through the
// whitelist: it has no organizationIdentifier of its own and its exact fingerprint is
// approved for the organization identifier that it carries now. The whitelist is consulted
// again here instead of trusting a flag, so the decision is based on the source of truth.
func (s *CertAuthServer) isManuallyApproved(certData *models.CertificateData) (bool, error) {
	if certData.Certificate == nil || certData.OrganizationID == "" {
		return false, nil
	}
	original := x509util.ParseEIDASNameFromATVSequence(certData.Certificate.Subject.Names)
	if original.OrganizationIdentifier != "" {
		return false, nil
	}
	approvedID, err := s.db.GetApprovedOrganizationIdentifier(models.CertificateFingerprint(certData.Certificate))
	if err != nil {
		slog.Error("Whitelist lookup failed", "error", err)
		return false, errl.Errorf("%w: %w", errWhitelistUnavailable, err)
	}
	return approvedID != "" && approvedID == certData.OrganizationID, nil
}
