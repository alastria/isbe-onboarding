package certauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/jpath"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/skip2/go-qrcode"
)

func (s *CertAuthServer) registerWalletHandlers() {

	// The page with the QR code to login with the Wallet
	s.httpServer.Get("/wallet/login", s.PageWalletLogin)

	// The JavaScript in the Login page polls the backend to see when the Wallet has sent the
	// Authentication Response, to know when to continue.
	s.httpServer.Get("/wallet/poll", s.APIWalletLoginPagePoll)

	s.httpServer.Get("/wallet/authenticationrequest", s.APIWalletAuthenticationRequest)
	s.httpServer.Post("/wallet/authenticationresponse", s.APIWalletAuthenticationResponse)

}

// PageWalletLogin presents the QR code for Wallet authentication.
// It is called from the main login page of CertAuth.
func (s *CertAuthServer) PageWalletLogin(c *fiber.Ctx) error {
	slog.Info("Landing page", "from", c.Hostname(), "to", c.IP())

	// Retrieve the AuthorizationRequest from the application authentication session
	authCode := c.Query("code")
	authProcess, err := s.getAuthProcess(authCode)
	if err != nil {
		err := errl.Errorf("getAuthProcess: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	verifierURL := s.certAuthURL
	// This is the response url for the wallet
	response_uri := verifierURL + "/wallet/authenticationresponse"

	// We now create an OID4VP Authorization Request to send to the Wallet.
	// Do not confuse this request with the one we received from the RP. they are associated but different.
	// With regards to the RP, we are an OpenID Provider and so we receive from the RP a "standard" OIDC auth request.
	// But for the Wallet we are a RP and the Wallet is the OpenID Provider, speaking the OID4VP protocol.
	// We request a Verifiable Credential from the Wallet, extract relevant info from it and send back to
	// the RP a standard OIDC response, so the RP/Application does not have to be involved with the OID4VP protocol.

	// According to OID4VP, the variable 'state' is used to track the interaction process with the Wallet.
	// We will use the 'authCode' we generated for the authorization process of the RP for this purpose.
	// That is: authCode will be used to track the whole authentication process, even if it is named differently
	// when talking to the Wallet.
	// In this way, when the Wallet sends the OID4VP AuthResponse, we will be able to match the Wallet response with the RP request.
	walletAuthRequest, err := s.createJWTSecuredAuthenticationRequest(response_uri, authCode)
	if err != nil {
		errorCode := "server_error"
		errorDesc := errl.Errorf("failed to create wallet authentication request: %w", err).Error()
		return s.handleAuthorizationError(c, authProcess.RedirectURI, authProcess.State, errorCode, errorDesc)
	}

	// Store in our authentication process object
	authProcess.WalletAuthRequest = walletAuthRequest

	slog.Info("Wallet authentication request created", "wallet_auth_request", walletAuthRequest)

	// Generate the data for the login page as a map
	data, err := dataForWalletLogin(verifierURL, authCode)
	if err != nil {
		errorCode := "server_error"
		errorDesc := errl.Errorf("failed to generate login page data: %w", err).Error()
		return s.handleAuthorizationError(c, authProcess.RedirectURI, authProcess.State, errorCode, errorDesc)
	}

	// Present a screen with the QR code to be scanned by the Wallet
	templateName := "wallet_login"
	if authProcess.UILocales == "en" {
		templateName = "wallet_login_en"
	}

	return s.htmlRender.Render(c, templateName, data)

}

func dataForWalletLogin(verifierURL string, authRequestID string) (map[string]any, error) {

	// Get our URL defined in the config

	// Build the URL that the Wallet will have to call to retriwve the Authentication Request
	request_uri := verifierURL + "/wallet/authenticationrequest" + "?state=" + authRequestID
	request_uri = url.QueryEscape(request_uri)

	// Build the full URI (including the request_uri) for the same-device use
	sameDeviceWallet := "https://eudiwallet.mycredential.eu"
	samedevice_uri := sameDeviceWallet + "?request_uri=" + request_uri

	// Build the full URI (including the request_uri) for the cross-device use (mobile)
	openid4PVURL := "openid4vp://"
	crossdevice_uri := openid4PVURL + "?request_uri=" + request_uri

	// Create the QR code for cross-device Authentication Request
	png, err := qrcode.Encode(crossdevice_uri, qrcode.Medium, 256)
	if err != nil {
		return nil, errl.Errorf("cannot create QR code: %w", err)
	}

	// Convert the image data to a dataURL
	base64Img := base64.StdEncoding.EncodeToString(png)
	base64Img = "data:image/png;base64," + base64Img

	data := fiber.Map{
		"AuthRequestID": authRequestID,
		"QRcode":        base64Img,
		"Samedevice":    samedevice_uri,
	}

	return data, nil

}

// APIWalletLoginPagePoll is the endpoint called periodically by the Wallet Login page to check
// if the authentication request has been processed or is still pending.
func (s *CertAuthServer) APIWalletLoginPagePoll(c *fiber.Ctx) error {

	// Get state from query parameter
	authReqId := c.Query("state")
	if authReqId == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing state value",
		})
	}

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authReqId)
	if err != nil {
		slog.Error("Invalid state", "state", authReqId)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": errl.Errorf("Invalid authorization code").Error(),
		})
	}

	if authProcess.FinishedWalletAuth {
		// The authentication request has been processed, so we redirect to the caller
		// with the auth code and the state.
		redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
		if authProcess.State != "" {
			redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
		}
		return c.Redirect(redirectURL, fiber.StatusFound)

	} else {
		// The authentication request is still pending, so we return "pending" to the Wallet Login page, which
		// will call this endpoint again after a short delay.
		return c.SendString("pending")

	}

}

// APIWalletAuthenticationRequest is the endpoint that the Wallet calls to retrieve the
// OID4VP Authentication Request object
func (s *CertAuthServer) APIWalletAuthenticationRequest(c *fiber.Ctx) error {

	// Retrieve the AuthorizationRequest from the application authentication session
	authProcess, err := s.getAuthProcess(c.Query("state"))
	if err != nil {
		err := errl.Errorf("getAuthProcess for state: %w", err)
		slog.Error(err.Error())
		return s.htmlRender.Render(c, "error", fiber.Map{"message": err})
	}

	slog.Info("sending back the WalletAuthentication request")

	// Get the Wallet AuthRequest
	walletAuthRequest := authProcess.WalletAuthRequest

	c.Response().Header.Add("Content-Type", "application/oauth-authz-req+jwt")
	return c.Send([]byte(walletAuthRequest))

}

// APIWalletAuthenticationResponse is the endpoint that the Wallet calls to send the
// Authentication Response with the LEARCredential
func (s *CertAuthServer) APIWalletAuthenticationResponse(c *fiber.Ctx) error {

	// Get state from query parameter
	authReqId := c.FormValue("state")

	// Retrieve the Authentication Process object from the cache
	authProcess, err := s.getAuthProcess(authReqId)
	if err != nil {
		err := errl.Errorf("getAuthProcess for state: %w", err)
		slog.Error(err.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing vp_token",
		})
	}

	// The state parameter is used to identify the in-memory AutRequest that was sent to the wallet
	slog.Info("APIWalletAuthenticationResponse", "stateKey", authReqId)

	// Get the vp_token field
	vp_token := c.FormValue("vp_token")
	if len(vp_token) == 0 {
		slog.Error("Mising vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Missing vp_token",
		})
	}

	// Decode VP token from B64Url to get a JWT
	vpJWT, err := base64.RawURLEncoding.DecodeString(vp_token)
	if err != nil {
		err = errl.Errorf("error decoding vp_token: %w", err)
		slog.Error("Error decoding VP", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// The VP object is a JWT, signed with the private key associated to the user did:key
	// We must verify the signature and decode the JWT payload to get the VerifiablePresentation
	// TODO: We do not check the signature.
	var pc = jwt.MapClaims{}
	tokenParser := jwt.NewParser()
	_, _, err = tokenParser.ParseUnverified(string(vpJWT), &pc)
	if err != nil {
		err = errl.Errorf("parsing vp_token: %w", err)
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	fmt.Print(pc["vp"])

	// Parse the VP object into a map
	vp := jpath.GetMap(pc, "vp")
	if vp == nil {
		err := errl.Errorf("error parsing the VP object")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Get the list of credentials in the VP
	credentials := jpath.GetList(vp, "verifiableCredential")
	if len(credentials) == 0 {
		err := errl.Errorf("no credentials found in VP")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// TODO: for the moment, we accept only the first credential inside the VP
	firstCredentialJWT, _ := credentials[0].(string)
	if len(firstCredentialJWT) == 0 {
		err := errl.Errorf("invalid credential in VP")
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// The credential is in 'jwt_vc_json' format (which is a JWT)
	// TODO: verify the signature of the credential against the public key of the issuer, which must be in a Trusted List of Issuers
	var credMap = jwt.MapClaims{}
	_, _, err = tokenParser.ParseUnverified(firstCredentialJWT, &credMap)
	if err != nil {
		err := errl.Errorf("error parsing the JWT:%s", errl.Error(err))
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// Serialize the credential into a JSON string
	serialCredential, err := json.Marshal(credMap)
	if err != nil {
		err := errl.Errorf("error serialising the credential:%s", errl.Error(err))
		slog.Error("Error parsing vp_token", "vp_token", vp_token)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": err.Error(),
		})
	}
	slog.Info("credential", "cred", string(serialCredential))

	// TODO: Invoke the PDP (Policy Decision Point) to authenticate/authorize this request

	// Update the internal AuthProcess with the LEARCredential received from the Wallet and signal we are finished.
	authProcess.CredentialData = credMap
	authProcess.FinishedWalletAuth = true

	// Redirect to the caller sending the auth code and the state
	redirectURL := fmt.Sprintf("%s?code=%s", authProcess.RedirectURI, authProcess.Code)
	if authProcess.State != "" {
		redirectURL += fmt.Sprintf("&state=%s", authProcess.State)
	}

	// Send reply to the Wallet, so it can show a success screen
	resp := map[string]string{
		"authenticatorRequired": "no",
		"type":                  "login",
		"email":                 "email",
		"redirectURL":           redirectURL,
	}

	return c.JSON(resp)

}
