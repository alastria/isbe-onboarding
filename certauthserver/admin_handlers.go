package certauth

import (
	"log/slog"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/basicauth"
)

func (s *CertAuthServer) registerAdminHandlers(adminPassword string) {

	admin := s.httpServer.Group("/admin")

	// Protect the admin area with basic auth
	adminAuth := basicauth.New(basicauth.Config{
		Users: map[string]string{
			"admin": adminPassword,
		},
		Realm: "Admin Area",
	})

	admin.Use(adminAuth)

	admin.Get("/admin", s.AdminDashboard)

	admin.Get("/rp", s.ListRP)
	admin.Post("/rp", s.CreateRP)
	admin.Put("/rp/:id", s.UpdateRP)
	admin.Delete("/rp/:id", s.DeleteRP)

	admin.Get("/registrations", s.UpdateRegistrations)

}

// AdminDashboard handles admin dashboard
func (s *CertAuthServer) AdminDashboard(c *fiber.Ctx) error {
	// TODO: Implement admin dashboard
	return c.SendStatus(fiber.StatusNotImplemented)
}

// ListRP lists all relying parties
func (s *CertAuthServer) ListRP(c *fiber.Ctx) error {
	rps, err := s.db.ListRelyingParties()
	if err != nil {
		return errl.Errorf("failed to list relying parties: %w", err)
	}

	return c.JSON(rps)
}

// CreateRP creates a new relying party
func (s *CertAuthServer) CreateRP(c *fiber.Ctx) error {
	// TODO: Implement RP creation
	return c.SendStatus(fiber.StatusNotImplemented)
}

// UpdateRP updates an existing relying party
func (s *CertAuthServer) UpdateRP(c *fiber.Ctx) error {
	// TODO: Implement RP update
	return c.SendStatus(fiber.StatusNotImplemented)
}

// DeleteRP deletes a relying party
func (s *CertAuthServer) DeleteRP(c *fiber.Ctx) error {
	// TODO: Implement RP deletion
	return c.SendStatus(fiber.StatusNotImplemented)
}

// GetRegistrationContract retrieves the contract document for a given organization identifier.
func (s *CertAuthServer) GetRegistrationContract(c *fiber.Ctx) error {
	// TODO: Implement contract retrieval
	return c.SendStatus(fiber.StatusNotImplemented)
}

func (s *CertAuthServer) UpdateRegistrations(c *fiber.Ctx) error {

	// Retrieve all registrations
	registrations, err := s.db.GetRegistrations()
	if err != nil {
		return errl.Errorf("failed to get registrations: %w", err)
	}

	// Update each registration whoch has a nil contract_document
	for _, registration := range registrations {
		if registration.ContractDocumentName != "" {
			continue
		}

		slog.Info("Updating registration", "org_id", registration.ContractForm.OrganizationNif)
		err := s.db.UpdateRegistration(s.tsaService, registration.EidasCert, registration.ContractForm, s.certAuthURL)
		if err != nil {
			return errl.Errorf("failed to update registration: %w", err)
		}
		slog.Info("Registration updated", "org_id", registration.ContractForm.OrganizationNif)
	}

	return c.SendStatus(fiber.StatusOK)
}
