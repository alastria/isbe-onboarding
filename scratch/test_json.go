package main

import (
	"encoding/json"
	"fmt"

	"github.com/alastria/isbe-onboarding/internal/tmfservice"
)

func main() {
	org := tmfservice.Organization{
		ID: "123",
		Organization_Common: tmfservice.Organization_Common{
			Name: "Test Org",
			Type: "organization",
		},
	}
	data, _ := json.MarshalIndent(org, "", "  ")
	fmt.Println("Organization JSON:")
	fmt.Println(string(data))

	orgCreate := tmfservice.Organization_Create{
		Organization_Common: tmfservice.Organization_Common{
			Name: "Create Org",
		},
		TradingName: "Trading Name",
	}
	data, _ = json.MarshalIndent(orgCreate, "", "  ")
	fmt.Println("\nOrganization_Create JSON:")
	fmt.Println(string(data))
}
