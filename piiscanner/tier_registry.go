package piiscanner

// This is a custom type instead of directly using string we are using Entitytier as our string
type EntityTier string

const (
	Tier1 EntityTier = "Tier1"
	Tier2 EntityTier = "Tier2"
	Tier3 EntityTier = "Tier3"
)

var EntityTierMap = map[PIILabel]EntityTier{
	// Tier 1 Entities (These are unique entities some of these have validtors and some has unique value regex)
	PIILabel_AdharcardNumber: Tier1,
	PIILabel_CreditCard:      Tier1,
	PIILabel_GSTIN:           Tier1,
	PIILabel_PANNumber:       Tier1,
	PIILabel_Email:           Tier1,
	PIILabel_UPIID:           Tier1,
	PIILabel_IFSC:            Tier1,
	PIILabel_IPAddress:       Tier1,
	PIILabel_MacAddress:      Tier1,
	PIILabel_VehicleNumber:   Tier1,
	PIILabel_CIN:             Tier1,

	// Tier 2 Entities
	PIILabel_PassportNumber:       Tier2,
	PIILabel_DrivingLicenceNumber: Tier2,
	PIILabel_DematAccountNumber:   Tier2,
	PIILabel_TAN:                  Tier2,
	PIILabel_UAN:                  Tier2,
	PIILabel_ABHANumber:           Tier2,
	PIILabel_EPFMemberID:          Tier2,
	PIILabel_SEBIRegistration:     Tier2,
	PIILabel_Phone:                Tier2,

	// Tier 3 Entities (These are very broad and generic entities we can't allow them to directly pariticipate for obfuscated columns)
	// These are helped by domain gating
	PIILabel_VoterID:      Tier3,
	PIILabel_CVV:          Tier3,
	PIILabel_ChequeNumber: Tier3,
	PIILabel_MICRCode:     Tier3,
	PIILabel_CIFNumber:    Tier3,
	PIILabel_ESIC:         Tier3,
	PIILabel_RationCard:   Tier3,
	PIILabel_Address:      Tier3,
	PIILabel_Gender:       Tier3,
	PIILabel_OAuthToken:   Tier3,
	PIILabel_Location:     Tier3,
}

// returns assaigned tier of the label default is tier 3
func GetEntityTier(label PIILabel) EntityTier {
	if Tier, ok := EntityTierMap[label]; ok {
		return Tier
	}
	return Tier3
}

func TierRank(tier EntityTier) int {
	switch tier {
	case Tier1:
		return 3
	case Tier2:
		return 2
	case Tier3:
		return 1
	default:
		return 0
	}

}
