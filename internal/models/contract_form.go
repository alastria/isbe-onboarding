package models

type ContractForm struct {
	TodayDay               int    `form:"today_day" json:"today_day"`
	TodayMonth             int    `form:"today_month" json:"today_month"`
	TodayYear              int    `form:"today_year" json:"today_year"`
	OrganizationName       string `form:"organization_name" json:"organization_name"`
	OrganizationCountry    string `form:"organization_country" json:"organization_country"`
	OrganizationAddress    string `form:"organization_address" json:"organization_address"`
	OrganizationNif        string `form:"organization_nif" json:"organization_nif"`
	RegistryName           string `form:"registry_name" json:"registry_name"`
	RegistryVolume         string `form:"registry_volume" json:"registry_volume"`
	RegistryFolio          string `form:"registry_folio" json:"registry_folio"`
	RegistrySheet          string `form:"registry_sheet" json:"registry_sheet"`
	RepresentativeTitle    string `form:"representative_title" json:"representative_title"`
	RepresentativeName     string `form:"representative_name" json:"representative_name"`
	RepresentativeEmail    string `form:"representative_email" json:"representative_email"`
	NotaryCity             string `form:"notary_city" json:"notary_city"`
	NotaryTitle            string `form:"notary_title" json:"notary_title"`
	NotaryName             string `form:"notary_name" json:"notary_name"`
	NotaryDay              string `form:"notary_day" json:"notary_day"`
	NotaryMonth            string `form:"notary_month" json:"notary_month"`
	NotaryYear             string `form:"notary_year" json:"notary_year"`
	NotaryProtocolNumber   string `form:"notary_protocol_number" json:"notary_protocol_number"`
	ContractCheckBase      string `form:"contract_base" json:"contract_base"`
	ContractCheckBasic     string `form:"contract_basic" json:"contract_basic"`
	ContractCheckDeveloper string `form:"contract_developer" json:"contract_developer"`
}
