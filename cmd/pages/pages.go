package main

import (
	"embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/alastria/isbe-onboarding/internal/errl"
	"github.com/alastria/isbe-onboarding/internal/html"
	"github.com/alastria/isbe-onboarding/internal/models"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/utils"
)

var viewsfs embed.FS

func main() {

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fmt.Println(wd)

	// The engine to display the screens (HTML) to the users
	htmlrender, err := html.NewRendererFiber(true, viewsfs, "certauthserver/views", ".hbs")
	if err != nil {
		slog.Error("Failed to initialize template engine", "error", err)
		panic(err)
	}

	app := fiber.New(fiber.Config{
		AppName:                 "Go template development",
		ServerHeader:            "CertAuth",
		EnableTrustedProxyCheck: false,
		ReadTimeout:             30 * time.Second,
		WriteTimeout:            30 * time.Second,
	})

	// Recovers from panics anywhere in the stack chain and handles the control to the centralized ErrorHandler
	app.Use(recover.New())

	app.Get("/page/:name", func(c *fiber.Ctx) error {
		slog.Info("Rendering page", "name", c.Params("name"))
		name := c.Params("name")

		// Get the current date
		currentDate := time.Now()
		year := currentDate.Year()
		month := currentDate.Month()
		day := currentDate.Day()

		subject := fiber.Map{
			"OrganizationIdentifier": "VATES-12345678K",
			"Organization":           "Good Air S.L.",
			"Email":                  "jesus@alastria.io",
		}

		authProcess := fiber.Map{
			"Code":        "12345678",
			"RedirectURI": "https://example.com/redirect",
			"State":       "state",
		}

		formData := models.ContractForm{
			TodayDay:               day,
			TodayMonth:             int(month),
			TodayYear:              year,
			OrganizationName:       "Good Air S.L.",
			OrganizationCountry:    "España",
			OrganizationAddress:    "C/ Alberto Aguilera, 23 (Universidad Pontificia de Comillas-ICADE), 28015-Madrid (España)",
			OrganizationNif:        "G87936159",
			RegistryName:           "Registro Mercantil de Madrid",
			RegistryVolume:         "1234",
			RegistryFolio:          "5678",
			RegistrySheet:          "91011",
			RepresentativeTitle:    "Dña.",
			RepresentativeName:     "Ana López",
			RepresentativeEmail:    "ana.lopez@alastria.io",
			NotaryCity:             "Madrid",
			NotaryTitle:            "Notario",
			NotaryName:             "Juan Pérez",
			NotaryDay:              "15",
			NotaryMonth:            "Diciembre",
			NotaryYear:             "2024",
			NotaryProtocolNumber:   "123456",
			ContractCheckBase:      "",
			ContractCheckBasic:     "",
			ContractCheckDeveloper: "",
		}

		data := fiber.Map{
			"authCode":    authProcess["Code"],
			"authCodeObj": authProcess,
			"subject":     subject,
			"email":       "jesus@alastria.io",
			"formData":    formData,
			"postAction":  "/page/form",
		}

		err := htmlrender.Render(c, name, data)
		return err
	})

	// Handle form submission
	app.Post("/page/form", func(c *fiber.Ctx) error {
		slog.Info("Form received")

		formData := models.ContractForm{}
		if err := c.BodyParser(&formData); err != nil {
			slog.Error("Failed to parse form", "error", err)
			return errl.Errorf("failed to parse form: %w", err)
		}

		// anexo1 := utils.CopyString(c.FormValue("contract_anexo_1"))
		// anexo2 := utils.CopyString(c.FormValue("contract_anexo_2"))
		// anexo3 := utils.CopyString(c.FormValue("contract_anexo_3"))
		// fmt.Println("Anexo1", anexo1)
		// fmt.Println("Anexo2", anexo2)
		// fmt.Println("Anexo3", anexo3)

		out, err := json.MarshalIndent(formData, "", "  ")
		if err != nil {
			slog.Error("Failed to marshal form data", "error", err)
			return errl.Errorf("failed to marshal form data: %w", err)
		}
		fmt.Println(string(out))

		authCode := utils.CopyString(c.FormValue("auth_code"))
		email := utils.CopyString(c.FormValue("email"))

		currentDate := time.Now()
		year := currentDate.Year()
		month := currentDate.Month()
		day := currentDate.Day()
		currentDateMap := map[string]int{
			"year":  year,
			"month": int(month),
			"day":   day,
		}

		data := fiber.Map{
			"authCode":   authCode,
			"date":       currentDateMap,
			"email":      email,
			"formData":   formData,
			"postAction": "/page/form",
		}

		return htmlrender.Render(c, "contract_print", data)
	})

	app.Static("/static", "./certauthserver/views/assets")

	if err := app.Listen(":8080"); err != nil {
		fmt.Println(err)
	}

}
