package piiscanner

// Domain represents functional domain categories for PII entities
type Domain string

const (
	DomainBanking    Domain = "Banking"
	DomainNationalID Domain = "NationalID"
	DomainEmployment Domain = "Employment"
	DomainCorporate  Domain = "Corporate"
	DomainPersonal   Domain = "Personal"
	DomainDigital    Domain = "Digital"
	DomainTransport  Domain = "Transport"
	DomainInsurance  Domain = "Insurance"
	DomainLending    Domain = "Lending"
)

// EntityDomainMap maps each of the PII labels to its domain category
var EntityDomainMap = map[PIILabel]Domain{
	// National ID Domain
	PIILabel_AdharcardNumber:      DomainNationalID,
	PIILabel_PANNumber:            DomainNationalID,
	PIILabel_PassportNumber:       DomainNationalID,
	PIILabel_VoterID:              DomainNationalID,
	PIILabel_DrivingLicenceNumber: DomainNationalID,
	PIILabel_RationCard:           DomainNationalID,
	PIILabel_ABHANumber:           DomainNationalID,
	PIILabel_Nationality:          DomainNationalID,

	// Banking & Financial Domain
	PIILabel_BankAccountNumber:  DomainBanking,
	PIILabel_IFSC:               DomainBanking,
	PIILabel_MICRCode:           DomainBanking,
	PIILabel_CreditCard:         DomainBanking,
	PIILabel_CVV:                DomainBanking,
	PIILabel_ChequeNumber:       DomainBanking,
	PIILabel_UPIID:              DomainBanking,
	PIILabel_CIFNumber:          DomainBanking,
	PIILabel_DematAccountNumber: DomainBanking,

	// Transport Domain
	PIILabel_FASTagID:       DomainTransport,
	PIILabel_VehicleNumber:  DomainTransport,

	// Insurance Domain
	PIILabel_InsurancePolicyNumber: DomainInsurance,

	// Lending Domain
	PIILabel_LoanAccountNumber: DomainLending,

	// Employment Domain
	PIILabel_UAN:         DomainEmployment,
	PIILabel_ESIC:        DomainEmployment,
	PIILabel_EPFMemberID: DomainEmployment,

	// Corporate Domain
	PIILabel_GSTIN:            DomainCorporate,
	PIILabel_TAN:              DomainCorporate,
	PIILabel_CIN:              DomainCorporate,
	PIILabel_SEBIRegistration: DomainCorporate,

	// Personal & Demographics Domain
	PIILabel_Name:      DomainPersonal,
	PIILabel_Email:     DomainPersonal,
	PIILabel_Phone:     DomainPersonal,
	PIILabel_Address:   DomainPersonal,
	PIILabel_BirthDate: DomainPersonal,
	PIILabel_Gender:    DomainPersonal,

	// Digital & Technical Domain
	PIILabel_IPAddress:  DomainDigital,
	PIILabel_MacAddress: DomainDigital,
	PIILabel_Username:   DomainDigital,
	PIILabel_OAuthToken: DomainDigital,
	PIILabel_Location:   DomainDigital,
}

// Phase3Entities defines bounded fixed-length fallback IDs subjected to Phase 3 domain gating
var Phase3Entities = map[PIILabel]bool{
	PIILabel_CVV:            true,
	PIILabel_ChequeNumber:   true,
	PIILabel_PassportNumber: true,
	PIILabel_MICRCode:       true,
	PIILabel_VoterID:        true,
	PIILabel_ABHANumber:     true,
	PIILabel_UAN:            true,
	PIILabel_Location:       true,
}
