package certauth

import (
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/alastria/isbe-onboarding/contract"
	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/jpath"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/alastria/isbe-onboarding/internal/tmfservice"
	"github.com/alastria/isbe-onboarding/types"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/utils"

	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"

	"github.com/carlos7ags/folio/document"
	"github.com/carlos7ags/folio/html"
)

const (
	certLoginEndpoint                    = "/cert/login"
	CertificateBackEndpoint              = "/certificate-back"
	sendEmailVerificationEndpoint        = "/request-email-verification"
	verifyEmailCodeEndpoint              = "/verify-email-code"
	presentContractForAcceptanceEndpoint = "/present-contract-for-acceptance"
	contractAcceptedEndpoint             = "/contract-accepted"
)

func (s *CertAuthServer) registerCertificateHandlers() {

	// Presents a screen informing the user that a certificate will be requested.
	s.httpServer.Get(certLoginEndpoint, s.pageCertLogin)
	s.httpServer.Get(certLoginEndpoint+"/en", s.pageCertLogin)

	// Redirected from CertSec after the user has provided a certificate.
	// Presents a screen with the certificate data and requests the email from the user.
	s.httpServer.Get(CertificateBackEndpoint, s.pageRequestEmail)
	s.httpServer.Get(CertificateBackEndpoint+"/en", s.pageRequestEmail)

	// Receives the email address and sends an email to the user to verify if the email is correct.
	// Presents a screen to allow the user to enter the verification code sent to its email.
	s.httpServer.Post(sendEmailVerificationEndpoint, s.sendEmailVerification)
	s.httpServer.Post(sendEmailVerificationEndpoint+"/en", s.sendEmailVerification)

	// Receives the email verification code and verifies it.
	// Presents the contract text with an embedded form so the user can fill missing data.
	s.httpServer.Post(verifyEmailCodeEndpoint, s.verifyEmailCodeAndPresentContractForm)
	s.httpServer.Post(verifyEmailCodeEndpoint+"/en", s.verifyEmailCodeAndPresentContractForm)
	s.httpServer.Post(presentContractForAcceptanceEndpoint, s.pagePresentContractForAcceptance)
	s.httpServer.Post(presentContractForAcceptanceEndpoint+"/en", s.pagePresentContractForAcceptance)

	// Handle consent received, generation of SSO cookie and redirection to Relying Party
	s.httpServer.Post(contractAcceptedEndpoint, s.handleContractAccepted)
	s.httpServer.Post(contractAcceptedEndpoint+"/en", s.handleContractAccepted)

}

// pageCertLogin shows the certificate selection screen
func (s *CertAuthServer) pageCertLogin(c *fiber.Ctx) error {
	slog.Info("CertLoginPage", "from", c.Hostname(), "to", c.IP())
	isEnglish := strings.HasSuffix(c.Path(), "/en")

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("code"))
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	// Present the screen informing the user about the next step
	templateName := "inform_user"
	if isEnglish {
		templateName = "inform_user_en"
	}
	return s.htmlRender.Render(c, templateName, fiber.Map{
		"authCode":   authProcess.Code,
		"certsecURL": s.certSecURL,
	})

}

// pageRequestEmail is invoked from CertSec via HTTP redirection.
// When CertSec receives the certificate from the user's browser, it sets the CertificateData field in the AuthProcess entry
// corresponding to the current authentication process.
// Then CerSec redirects back to us (CertAuth) with the 'code' and possibly an 'error' parameter in the URL
func (s *CertAuthServer) pageRequestEmail(c *fiber.Ctx) error {
	isEnglish := strings.HasSuffix(c.Path(), "/en")
	// Get auth code from query parameter
	authCode := c.Query("code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}
	slog.Info("Certificate received entry", "auth_code", authCode)

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	slog.Info("======== PROFILE ========")
	slog.Info("======== PROFILE ========", "profile", s.profile)
	slog.Info("======== PROFILE ========")

	// Check if CertSec returned some error
	certError := c.Query("error")
	if certError != "" || authProcess.ErrorInProcess != nil {
		err := authProcess.ErrorInProcess
		slog.Error("Error:", "error", err)
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{
			"message": err,
		})
	}

	// Get the certificate data that was set by the certificate authentication process
	certData := authProcess.CertificateData

	// Validate the certificate data
	if certData == nil {
		return errl.Errorf("certificate data is nil")
	}

	// We do not accept personal certificates, which do not have the organizationIdentifier field
	if certData.OrganizationID == "" {
		err = errl.Errorf("personal certificates are not allowed")
		slog.Error(err.Error(), "auth_code", authCode)

		// Present the screen
		templateName := "cert_received_error"
		postAction := sendEmailVerificationEndpoint
		if isEnglish {
			templateName = "cert_received_error_n"
			postAction += "/en"
		}
		return s.htmlRender.Render(c, templateName, fiber.Map{
			"certData":        certData,
			"isPersonal":      true,
			"certType":        certData.CertificateType,
			"subject":         certData.Subject,
			"postAction":      postAction,
			"production":      s.profile == types.PROFILE_ISBE_PRO,
			"serviceError":    false,
			"validationError": false,
		})
	}

	// Check that the certificate is a valid eIDAS one
	_, errService, errValidation := VerifyCertificate(certData.CertificateDER, s.euDSSURL)
	if errService == nil && errValidation == nil {
		certData.EIDASCertificate = true
	} else {
		// Log the validation error with certificate details for debugging
		slog.Warn("Certificate validation failed (proceeding in test/demo mode)", "serviceError", errService, "validationError", errValidation, "subject", certData.Subject)
		// In ISBE_PRO we do not allow non-eIDAS certificates to proceed
		// The UI will show a warning that the certificate is not eIDAS compliant
		if s.profile == types.PROFILE_ISBE_PRO && certData.OrganizationID != "VATES-12345678J" {
			// Present the screen
			templateName := "cert_received_error"
			postAction := sendEmailVerificationEndpoint
			if isEnglish {
				templateName = "cert_received_error_n"
				postAction += "/en"
			}
			return s.htmlRender.Render(c, templateName, fiber.Map{
				"authCode":        authCode,
				"authCodeObj":     authProcess,
				"certData":        certData,
				"certType":        certData.CertificateType,
				"subject":         certData.Subject,
				"postAction":      postAction,
				"production":      s.profile == types.PROFILE_ISBE_PRO,
				"serviceError":    errService != nil,
				"validationError": errValidation != nil,
			})
		}
	}

	// Check if the organization is already registered
	email, formData, _, err := s.db.GetRegistration(certData.OrganizationID)
	if err != nil {
		return errl.Errorf("error retrieving registration email: %w", err)
	}

	if email != "" && certData.OrganizationID != "VATES-12345678J" {

		// The organization is already registered, bypass email validation
		//But first we have to retrieve the powers of the user
		powers, err := s.retrieveManagementPowers(certData)
		if err != nil {
			return errl.Errorf("error retrieving powers: %w", err)
		}

		// Register in the TMF server the new Organization
		request := tmfservice.RegistrationRequest{
			FirstName:     formData.RepresentativeName,
			LastName:      "",
			CompanyName:   formData.OrganizationName,
			Country:       formData.OrganizationCountry,
			VatId:         formData.OrganizationNif,
			StreetAddress: formData.OrganizationAddress,
			PostalCode:    "",
			Email:         formData.RepresentativeEmail,
		}

		createOrg := tmfservice.BuildTMFOrganizationFromRequest(request, certData.CertificateDER)

		// If we are not in Production, delete all existing organizations and create a new one
		// if s.profile != types.ISBE_PRO {
		if true {
			slog.Info("Deleting TMF organizations", "auth_code", authCode, "vat_id", request.VatId)
			err := s.tmfService.TMFDeleteAllOrganizationsByELSI(s.tmfAdminToken, request.VatId)
			if err != nil {
				err = errl.Errorf("deleting TMF organizations: %w", err)
				slog.Error(err.Error(), "auth_code", authCode)
			} else {
				slog.Info("TMF organizations deleted successfully", "auth_code", authCode)
			}
		} else {
			slog.Info("TMF organizations not deleted (production mode)", "auth_code", authCode)
		}

		_, err = s.tmfService.TMFCreateOrganization(s.tmfAdminToken, createOrg)
		if err != nil {
			err = errl.Errorf("creating TMF organization: %w", err)
			slog.Error(err.Error(), "auth_code", authCode)
		} else {
			slog.Info("TMF organization created successfully", "auth_code", authCode)
		}

		// Bypass email validation and return directly to caller
		slog.Debug("bypass email validation", "code", authProcess.Code, "redirect_uri", authProcess.RedirectURI)

		// Store email of the user in the authProcess struct
		authProcess.Email = email
		authProcess.Powers = powers

		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}

		return c.Redirect(redirectURL, fiber.StatusFound)

	}

	// Otherwise, we present the certificate data to the user and must request and validate its email
	slog.Info("Certificate received exit", "auth_code", authCode, "cert_length", len(certData.Certificate.Raw))

	// Present the screen
	templateName := "cert_received"
	postAction := sendEmailVerificationEndpoint
	if isEnglish {
		templateName = "cert_received_en"
		postAction += "/en"
	}
	return s.htmlRender.Render(c, templateName, fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certData":    certData,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"postAction":  postAction,
		"production":  s.profile == types.PROFILE_ISBE_PRO,
	})

}

type EUDSSVerifyCertificateRequest struct {
	Certificate struct {
		EncodedCertificate string `json:"encodedCertificate"`
	} `json:"certificate"`
	TokenExtractionStrategy string `json:"tokenExtractionStrategy"`
}

// VerifyCertificate verifies a certificate using the EUDSS service.
// Returns:
// - body: The raw response body from the service.
// - errService: Error when the call to the service failed (HTTP failure, timeout, non-200 status).
// - errValidation: Error when the service worked but returned validation errors.
func VerifyCertificate(data string, url string) ([]byte, error, error) {
	req := EUDSSVerifyCertificateRequest{
		Certificate: struct {
			EncodedCertificate string `json:"encodedCertificate"`
		}{
			EncodedCertificate: data,
		},
		TokenExtractionStrategy: "NONE",
	}

	jsonReq, err := json.Marshal(req)
	if err != nil {
		return nil, errl.Errorf("failed to marshal EUDSS request: %w", err), nil
	}

	// We use a timeout of 30 seconds for the client
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	var lastErrService error
	var body []byte

	// Retry up to two times (for a maximum total of three calls)
	for i := range 3 {
		switch i {
		case 1:
			time.Sleep(3 * time.Second)
		case 2:
			time.Sleep(5 * time.Second)
		}

		resp, err := client.Post(url, "application/json", bytes.NewBuffer(jsonReq))
		if err != nil {
			lastErrService = errl.Errorf("failed to send EUDSS request (attempt %d): %w", i+1, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErrService = errl.Errorf("EUDSS request failed (attempt %d) with status code %d", i+1, resp.StatusCode)
			resp.Body.Close()
			continue
		}

		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErrService = errl.Errorf("failed to read EUDSS response (attempt %d): %w", i+1, err)
			continue
		}

		// If we reached here, the service call succeeded (HTTP 200 and body read)
		// No more retries needed for service failure
		lastErrService = nil
		break
	}

	if lastErrService != nil {
		return nil, lastErrService, nil
	}

	// Parse response as a map[string]any
	var respMap map[string]any
	if err := json.Unmarshal(body, &respMap); err != nil {
		return nil, errl.Errorf("failed to unmarshal EUDSS response: %w", err), nil
	}

	// Get the simpleCertificateReport object
	simpleCertificateReport := jpath.GetMap(respMap, "simpleCertificateReport")
	if simpleCertificateReport == nil {
		return nil, nil, errl.Errorf("simpleCertificateReport not found in EUDSS response")
	}

	// Get the indication from the simpleCertificateReport object
	indication := jpath.GetString(simpleCertificateReport, "Certificate.Indication")
	if indication != "PASSED" {
		return nil, nil, errl.Errorf("certificate is not eIDAS compliant")
	}

	// Get the ChainItem array
	chainItemArray := jpath.GetList(simpleCertificateReport, "ChainItem")
	if chainItemArray == nil {
		return nil, nil, errl.Errorf("ChainItem not found in EUDSS response")
	}

	// All objects of the list must have a field "Indication": "PASSED"
	for i, chainItem := range chainItemArray {
		indication := jpath.GetString(chainItem, "Indication")
		if indication != "PASSED" {
			// Get the subject object and additional validation info
			subject := jpath.GetMap(chainItem, "subject")
			subIndication := jpath.GetString(chainItem, "SubIndication")

			// Log the subject and validation details as a warning (not blocking in test/demo mode)
			out, _ := json.Marshal(subject)
			slog.Warn("Certificate validation warning - not eIDAS compliant (proceeding in test/demo mode)",
				"chain_index", i,
				"indication", indication,
				"sub_indication", subIndication,
				"subject", string(out))

			// In test/demo mode, return an error to signal non-eIDAS certificate
			// The caller will handle this by allowing the flow to continue with a warning
			if subIndication != "" {
				return nil, nil, errl.Errorf("certificado en la cadena (posición %d) no pasó la validación. Indicación: %s, Sub-indicación: %s", i+1, indication, subIndication)
			}
			return nil, nil, errl.Errorf("certificado en la cadena (posición %d) no pasó la validación. Indicación: %s", i+1, indication)
		}
	}

	return body, nil, nil
}

// sendEmailVerification handles the email verification form submission
func (s *CertAuthServer) sendEmailVerification(c *fiber.Ctx) error {
	isEnglish := strings.HasSuffix(c.Path(), "/en")
	// Get form data
	email := utils.CopyString(c.FormValue("email"))
	authCode := c.FormValue("auth_code")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	if email == "" || authCode == "" {
		err := errl.Errorf("Missing email or authorization code")
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Basic email format validation
	if !isValidEmail(email) {
		err := errl.Errorf("Invalid email format")
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	slog.Info("Email verification requested", "email", email, "auth_code", authCode)

	certData := authProcess.CertificateData
	if certData == nil {
		err := errl.Errorf("certificate data not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	// Generate a random 6-digit verification code
	emailVerificationCode := generateRandomCode()

	// Waiting for verification of the email address
	authProcess.Email = email
	authProcess.EmailVerificationCode = emailVerificationCode

	slog.Info("Verification code generated", "code", emailVerificationCode, "auth_code", authCode)

	// Send the actual email
	err = s.emailService.SendVerificationEmail(email, emailVerificationCode)
	if err != nil {
		// In local profile, we allow the process to continue even if email sending fails
		if s.profile == types.PROFILE_LOCAL {
			slog.Warn("Failed to send verification email (proceeding in local mode)", "error", err, "auth_code", authCode, "email", email)
			// Continue with the flow and show the verification code on screen
		} else {
			// In non-local profiles, email sending is mandatory
			err := errl.Errorf("sendVerificationEmail: %w", err)
			slog.Error(err.Error(), "auth_code", authCode)
			// Disable the error return, until the email server is working again
			// return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
		}
	} else {
		slog.Info("Verification email sent successfully", "email", email, "auth_code", authCode)
	}

	// Render the confirm_email template
	templateName := "verify_email"
	postAction := verifyEmailCodeEndpoint
	if isEnglish {
		templateName = "verify_email_en"
		postAction += "/en"
	}
	return s.htmlRender.Render(c, templateName, fiber.Map{
		"email":            email,
		"authCode":         authCode,
		"verificationCode": emailVerificationCode,            // For testing in local mode
		"emailSendFailed":  err != nil,                       // Flag to show warning message
		"isLocalProfile":   s.profile == types.PROFILE_LOCAL, // Flag to show verification code only in local mode
		"subject":          certData.Subject,
		"postAction":       postAction,
	})
}

// isValidEmail performs basic email format validation
func isValidEmail(email string) bool {
	// Simple regex for basic email validation
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(emailRegex, email)
	return matched
}

// generateRandomCode generates a random 6-digit verification code
func generateRandomCode() string {
	// Generate a random 6-digit number
	a, _ := rand.Int(rand.Reader, big.NewInt(999999))

	return fmt.Sprintf("%06d", a.Uint64())

}

// verifyEmailCodeAndPresentContractForm handles the email verification code verification,
// and presents the contract form to the user.
func (s *CertAuthServer) verifyEmailCodeAndPresentContractForm(c *fiber.Ctx) error {
	isEnglish := strings.HasSuffix(c.Path(), "/en")
	// Get form data
	emailVerificationCode := utils.CopyString(c.FormValue("verification_code"))
	authCode := utils.CopyString(c.FormValue("auth_code"))
	email := utils.CopyString(c.FormValue("email"))

	if emailVerificationCode == "" || authCode == "" || email == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing verification code, authorization code, or email",
		})
	}

	slog.Info("Email verification code verification requested", "email", email, "auth_code", authCode)

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	storedEmailVerificationCode := authProcess.EmailVerificationCode
	if storedEmailVerificationCode == "" {
		err := errl.Errorf("email verification code not found in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Verify the code
	if emailVerificationCode != storedEmailVerificationCode {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid verification code",
		})
	}

	slog.Info("Email verification code verified successfully", "email", email, "auth_code", authCode)

	storedEmail := authProcess.Email
	if storedEmail != email {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Get the current date
	currentDate := time.Now()
	year := currentDate.Year()
	month := currentDate.Month()
	day := currentDate.Day()

	formData := models.ContractForm{
		TodayDay:            day,
		TodayMonth:          int(month),
		TodayYear:           year,
		OrganizationName:    certData.Subject.Organization,
		OrganizationCountry: certData.Subject.Country,
		OrganizationAddress: certData.Subject.StreetAddress,
		OrganizationNif:     certData.Subject.OrganizationIdentifier,
		RepresentativeName:  certData.Subject.CommonName,
		RepresentativeEmail: storedEmail,
	}

	// Render the certificate consent template
	templateName := "contract_form"
	postAction := presentContractForAcceptanceEndpoint
	if isEnglish {
		templateName = "contract_form_en"
		postAction += "/en"
	}
	return s.htmlRender.Render(c, templateName, fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"certType":    certData.CertificateType,
		"subject":     certData.Subject,
		"formData":    formData,
		"postAction":  postAction,
		"countryName": s.countryName(formData.OrganizationCountry),
	})
}

func (s *CertAuthServer) pagePresentContractForAcceptance(c *fiber.Ctx) error {
	isEnglish := strings.HasSuffix(c.Path(), "/en")

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// For some fields, if they are empty replace them with "N/A"
	if formData.NotaryCity == "" {
		formData.NotaryCity = "N/A"
	}
	if formData.NotaryTitle == "" {
		formData.NotaryTitle = "N/A"
	}
	if formData.NotaryName == "" {
		formData.NotaryName = "N/A"
	}
	if formData.NotaryDay == "" {
		formData.NotaryDay = "N/A"
	}
	if formData.NotaryMonth == "" {
		formData.NotaryMonth = "N/A"
	}
	if formData.NotaryYear == "" {
		formData.NotaryYear = "N/A"
	}
	if formData.NotaryProtocolNumber == "" {
		formData.NotaryProtocolNumber = "N/A"
	}

	if formData.RegistryName == "" {
		formData.RegistryName = "N/A"
	}
	if formData.RegistryVolume == "" {
		formData.RegistryVolume = "N/A"
	}
	if formData.RegistryFolio == "" {
		formData.RegistryFolio = "N/A"
	}
	if formData.RegistrySheet == "" {
		formData.RegistrySheet = "N/A"
	}

	certData := authProcess.CertificateData

	// Update the email field in the certificate data
	certData.Subject.EmailAddress = storedEmail

	// Render the contract acceptance template
	templateName := "contract_print"
	postAction := contractAcceptedEndpoint
	if isEnglish {
		templateName = "contract_print_en"
		postAction += "/en"
	}
	return s.htmlRender.Render(c, templateName, fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"formData":    formData,
		"postAction":  postAction,
		"countryName": s.countryName(formData.OrganizationCountry),
	})

}

// countryName returns the real country name (EU/EEA only) fromn the two-letter country code
func (s *CertAuthServer) countryName(countryCode string) string {
	countries := map[string]string{
		"ES": "España",
		"FR": "Francia",
		"DE": "Alemania",
		"IT": "Italia",
		"PT": "Portugal",
		"NL": "Países Bajos",
		"BE": "Bélgica",
		"LU": "Luxemburgo",
		"AT": "Austria",
		"SE": "Suecia",
		"FI": "Finlandia",
		"DK": "Dinamarca",
		"IE": "Irlanda",
		"EL": "Grecia",
		"CY": "Chipre",
		"MT": "Malta",
		"EE": "Estonia",
		"LV": "Letonia",
		"LT": "Lituania",
		"PL": "Polonia",
		"CZ": "República Checa",
		"SK": "Eslovaquia",
		"HU": "Hungría",
		"RO": "Rumanía",
		"BG": "Bulgaria",
		"HR": "Croacia",
		"SI": "Eslovenia",
	}

	country, ok := countries[strings.ToUpper(strings.TrimSpace(countryCode))]
	if !ok {
		return countryCode
	}
	return country
}

func (s *CertAuthServer) getContract(authCode string, authProcess *models.AuthProcess, formData *models.ContractForm, isEnglish bool) ([]byte, error) {

	// Render the certificate consent template
	templateName := "contract_download"
	postAction := contractAcceptedEndpoint
	if isEnglish {
		templateName = "contract_download_en"
		postAction += "/en"
	}
	b, err := s.htmlRender.RenderToBuffer(templateName, fiber.Map{
		"authCode":    authCode,
		"authCodeObj": authProcess,
		"formData":    formData,
		"postAction":  postAction,
	})
	if err != nil {
		return nil, err
	}

	// Save the html to a file for debugging
	err = os.WriteFile("contract.html", b.Bytes(), 0644)
	if err != nil {
		return nil, err
	}

	doc := document.NewDocument(document.PageSizeA4)
	elems, _ := html.Convert(b.String(), nil)
	for _, e := range elems {
		doc.Add(e)
	}
	pdf, err := doc.ToBytes()
	if err != nil {
		return nil, err
	}

	return pdf, nil
}

// handleContractAccepted is the last step, after the user has given consent to proceed.
// We then generate the SSO cookie and redirect to the RP with the auth code.
// The RP will eventually exchange the auth code for ID and access tokens, which will contain user and certificate data.
func (s *CertAuthServer) handleContractAccepted(c *fiber.Ctx) error {
	isEnglish := strings.HasSuffix(c.Path(), "/en")

	// Data for checking the form is valid, before we do anything else
	authCode := utils.CopyString(c.FormValue("auth_code"))
	if authCode == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing authorization code",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		if isEnglish {
			return s.htmlRender.Render(c, "error_en", fiber.Map{"message": err})
		}
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	if authProcess.UILocales == "en" {
		isEnglish = true
	}

	// Parse the formData
	formData := models.ContractForm{}
	if err := c.BodyParser(&formData); err != nil {
		slog.Error("Failed to parse form", "error", err)
		return errl.Errorf("failed to parse form: %w", err)
	}

	// Acondition the VATID. Make sure that it has the prefix 'VATXX-', where XX is the country code.
	if !strings.HasPrefix(formData.OrganizationNif, "VAT") {
		formData.OrganizationNif = "VAT" + strings.ToUpper(formData.OrganizationCountry) + "-" + formData.OrganizationNif
	}

	// Check that we have the email of the representative
	if formData.RepresentativeEmail == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing representative email",
		})
	}

	slog.Info("Email verification code verification requested", "email", formData.RepresentativeEmail, "auth_code", authCode)

	// Sanity check, we already have an email and they have to be the same
	storedEmail := authProcess.Email
	if storedEmail != formData.RepresentativeEmail {
		err := errl.Errorf("email mismatch in authorization request")
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	slog.Debug("Stored email", "email", storedEmail)

	// Generate the PDF contract in memory
	contractDocument, err := contract.Generate(&formData, s.profile, s.certAuthURL, isEnglish)
	if err != nil {
		err = errl.Errorf("generating contract: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Store the company data in the registrations table
	if err := s.db.CreateRegistration(s.tsaService, authProcess.CertificateData, storedEmail, &formData, contractDocument); err != nil {
		err = errl.Errorf("creating registration: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})

	}

	// Register in the TMF server the new Organization
	request := tmfservice.RegistrationRequest{
		FirstName:     formData.RepresentativeName,
		LastName:      "",
		CompanyName:   formData.OrganizationName,
		Country:       formData.OrganizationCountry,
		VatId:         formData.OrganizationNif,
		StreetAddress: formData.OrganizationAddress,
		PostalCode:    "",
		Email:         formData.RepresentativeEmail,
	}

	createOrg := tmfservice.BuildTMFOrganizationFromRequest(request, authProcess.CertificateData.CertificateDER)

	// If we are not in Production, delete all existing organizations
	if s.profile != types.PROFILE_ISBE_PRO {
		slog.Info("Deleting TMF organizations", "auth_code", authCode, "vat_id", request.VatId)
		err := s.tmfService.TMFDeleteAllOrganizationsByELSI(s.tmfAdminToken, request.VatId)
		if err != nil {
			err = errl.Errorf("deleting TMF organizations: %w", err)
			slog.Error(err.Error(), "auth_code", authCode)
		}
	}

	_, err = s.tmfService.TMFCreateOrganization(s.tmfAdminToken, createOrg)
	if err != nil {
		err = errl.Errorf("creating TMF organization: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
	}

	// Notify the contract management system that the registration is complete
	if powers, err := s.notifyManagement(&formData, contractDocument); err != nil {
		err = errl.Errorf("notifying management: %w", err)
		slog.Error(err.Error(), "auth_code", authCode)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": err.Error(),
		})
	} else {
		authProcess.Powers = powers
		slog.Info("Management notified successfully", "powers", powers)
	}

	// Generate a random unique identifier for the SSO session
	ssoSessionID := generateRandomString()

	// Create the SSO session data to be held in the server-side cache
	ssoSession := &models.SSOSession{
		SessionID:       ssoSessionID,
		Email:           storedEmail,
		CertificateData: authProcess.CertificateData,
		Powers:          authProcess.Powers,
	}

	// Store the SSO session in the cache (valid for 24 hours)
	s.ssoCache.Set(ssoSessionID, ssoSession, 24*time.Hour)

	// Generate SSO cookie
	ssoCookie, err := s.generateSSOCookie(ssoSessionID, ssoSession.CertificateData)
	if err != nil {
		slog.Error("failed to generate sso cookie", "error", err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Set SSO cookie
	c.Cookie(ssoCookie)

	// Redirect (302) to RP with auth code
	slog.Info("User consent processed successfully", "email", storedEmail, "auth_code", authCode)
	// href="{{ .authCodeObj.RedirectURI }}?code={{ .authCode }}&state={{ .authCodeObj.State }}"
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authCode)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	return c.Redirect(redirectURL, fiber.StatusFound)

}

func (s *CertAuthServer) notifyManagement(contractForm *models.ContractForm, fileToSend []byte) (string, error) {

	organizationIdentifier := contractForm.OrganizationNif

	// Structs for the data to be sent
	type Role struct {
		Principal bool `json:"principal"`
		Basic     bool `json:"basic"`
		Developer bool `json:"developer"`
		OpExec    bool `json:"op_exec"`
	}

	// OrganizationIdentifier and SelectedRole will be added as form fields.
	type requestBody struct {
		OrganizationIdentifier string `json:"organization_identifier"`
		SelectedRole           Role   `json:"selected_role"`
	}

	// Enforce the constraints on customer acceptance of the contract and anexes
	// The base has to be signed, and at least one of the anexes has to be signed
	if contractForm.ContractCheckBase != "on" {
		return "", fmt.Errorf("contract check base not accepted")
	}
	if contractForm.ContractCheckBasic != "on" && contractForm.ContractCheckDeveloper != "on" {
		return "", fmt.Errorf("contract check basic or developer not accepted")
	}

	role := Role{
		Principal: true,
	}

	if contractForm.ContractCheckBasic == "on" {
		role.Basic = true
	}

	if contractForm.ContractCheckDeveloper == "on" {
		role.Developer = true
	}

	// Prepare the multipart payload
	bodyBuf := &bytes.Buffer{}
	writer := multipart.NewWriter(bodyBuf)

	// 1. Add OrganizationIdentifier
	if err := writer.WriteField("organization_identifier", organizationIdentifier); err != nil {
		return "", fmt.Errorf("failed to write organization_identifier: %w", err)
	}

	// 2. Add SelectedRole
	// Using the example values from the comments as defaults
	roleBytes, err := json.Marshal(role)
	if err != nil {
		return "", fmt.Errorf("failed to marshal role: %w", err)
	}
	if err := writer.WriteField("selected_role", string(roleBytes)); err != nil {
		return "", fmt.Errorf("failed to write selected_role: %w", err)
	}

	// 3. Add Contract File (fileToSend). The file is a PDF file.
	// Using "contract" as the field name and "contract.pdf" as the filename
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, "contract", "contract.pdf"))
	h.Set("Content-Type", "application/pdf")
	part, err := writer.CreatePart(h)
	if err != nil {
		return "", fmt.Errorf("failed to create form part: %w", err)
	}
	if _, err := part.Write(fileToSend); err != nil {
		return "", fmt.Errorf("failed to write file content: %w", err)
	}

	// Close the writer to finalize the boundary
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	slog.Info("Sending POST to main portal", "url", s.managementURL)

	// Do a DELETE request to delete the organization from the main portal
	deleteURL := s.managementURL + "/organization/" + organizationIdentifier
	deleteReq, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create delete request: %w", err)
	}
	slog.Info("Deleted organization from Management portal", "url", deleteURL)

	// Set the API key in the header
	deleteReq.Header.Set("X-Api-Key", s.managementAPIKey)
	slog.Debug("API key", "X-Api-Key", s.managementAPIKey)

	deleteClient := &http.Client{}
	deleteResp, err := deleteClient.Do(deleteReq)
	if err != nil {
		return "", fmt.Errorf("failed to send delete request: %w", err)
	}
	defer deleteResp.Body.Close()

	// Print the buffer that we are sending
	b := bodyBuf.String()
	slog.Info("Sending POST to main portal", "url", s.managementURL)
	slog.Info("Request body", "body", b)

	// Create and send the HTTP request
	req, err := http.NewRequest("POST", s.managementURL, bodyBuf)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Api-Key", s.managementAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("main portal returned non-success status: %d", resp.StatusCode)
	}

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse into a map[string]any
	var response map[string]any
	if err := json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	// Print the response map as a pretty-printed indented JSON
	jsonResponse, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response body: %w", err)
	}
	fmt.Println(string(jsonResponse))

	// Check if the response contains the proper fields

	receivedOrganizationIdentifier := jpath.GetString(response, "organization_identifier")
	if receivedOrganizationIdentifier != organizationIdentifier {
		return "", errl.Errorf("organization identifier mismatch: expected %s, got %s", organizationIdentifier, receivedOrganizationIdentifier)
	}

	receivedPowersString := jpath.GetString(response, "power")
	if receivedPowersString == "" {
		receivedPowersString = jpath.GetString(response, "powers")
	}
	if receivedPowersString == "" {
		return "", errl.Errorf("powers not received")
	}

	return receivedPowersString, nil
}

func (s *CertAuthServer) retrieveManagementPowers(certData *models.CertificateData) (string, error) {

	organizationIdentifier := certData.OrganizationID

	// Create and send the HTTP request
	req, err := http.NewRequest("GET", s.managementURL+"/organization/"+organizationIdentifier, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set the API key in the header
	req.Header.Set("X-Api-Key", s.managementAPIKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("main portal returned non-success status: %d", resp.StatusCode)
	}

	// Read the response body
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse into a map[string]any
	var response map[string]any
	if err := json.Unmarshal(respBody, &response); err != nil {
		return "", fmt.Errorf("failed to parse response body: %w", err)
	}

	// Print the response map as a pretty-printed indented JSON
	jsonResponse, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal response body: %w", err)
	}
	fmt.Println(string(jsonResponse))

	// Check if the response contains the proper fields

	receivedOrganizationIdentifier := jpath.GetString(response, "organization_identifier")
	if receivedOrganizationIdentifier != organizationIdentifier {
		return "", errl.Errorf("organization identifier mismatch: expected %s, got %s", organizationIdentifier, receivedOrganizationIdentifier)
	}

	receivedRole := jpath.GetMap(response, "role")
	if receivedRole == nil {
		return "", errl.Errorf("role not received")
	}

	receivedPolicies := jpath.GetList(receivedRole, "policies")
	if len(receivedPolicies) == 0 {
		return "", errl.Errorf("policies not received")
	}

	// Marshall to a string
	receivedPoliciesString, err := json.Marshal(receivedPolicies)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policies: %w", err)
	}

	return string(receivedPoliciesString), nil
}
