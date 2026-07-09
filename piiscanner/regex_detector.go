package piiscanner

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

func luhnValid(number string) bool {
	sum := 0
	alternate := false

	for i := len(number) - 1; i >= 0; i-- {
		d := int(number[i] - '0')

		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}

		sum += d
		alternate = !alternate
	}

	return sum%10 == 0
}

// Region constants for PII detector region gating.
const (
	// loads indian PII entities (Aadhaar, PAN, DL, Passport, VoterID etc.)
	RegionIndia = "india"
	// loads US PII entities (SSN, ITIN, ZipCode, US DL patterns etc.)
	RegionUS = "us"
	// loads UK PII entities (NHSNumber etc.)
	RegionUK = "uk"
	// RegionGlobal is default — loads all entities regardless of region.
	RegionGlobal = "global"
)

type RegexWithWeight struct {
	Regexp                *regexp.Regexp
	Weight                float64
	Region                string // empty means global
	RequiresColumnContext bool   // if true, only activates when column name also matches
}

var verhoeffD = [10][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
	{2, 3, 4, 0, 1, 7, 8, 9, 5, 6},
	{3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
	{4, 0, 1, 2, 3, 9, 5, 6, 7, 8},
	{5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
	{6, 5, 9, 8, 7, 1, 0, 4, 3, 2},
	{7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
	{8, 7, 6, 5, 9, 3, 2, 1, 0, 4},
	{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
}

var verhoeffP = [8][10]int{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
	{1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
	{5, 8, 0, 3, 7, 9, 6, 1, 4, 2},
	{8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
	{9, 4, 5, 3, 1, 2, 6, 8, 7, 0},
	{4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
	{2, 7, 9, 3, 8, 0, 6, 4, 1, 5},
	{7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
}

// for aadhaar validation
func verhoeffValid(num string) bool {
	c := 0
	for i, j := len(num)-1, 0; i >= 0; i, j = i-1, j+1 {
		digit := int(num[i] - '0')
		if digit < 0 || digit > 9 {
			return false
		}
		c = verhoeffD[c][verhoeffP[j%8][digit]]
	}
	return c == 0
}

// gstinValid validates a GSTIN using the mod-36 check digit algorithm
func gstinValid(gstin string) bool {
	if len(gstin) != 15 {
		return false
	}
	gstin = strings.ToUpper(gstin)
	chars := "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charMap := make(map[byte]int)
	for i, c := range chars {
		charMap[byte(c)] = i
	}
	sum := 0
	for i := 0; i < 14; i++ {
		val, ok := charMap[gstin[i]]
		if !ok {
			return false
		}
		if i%2 == 0 {
			sum += val
		} else {
			product := val * 2
			sum += product/36 + product%36
		}
	}
	checkVal := (36 - sum%36) % 36
	expectedCheck := chars[checkVal]
	return gstin[14] == expectedCheck
}

// baseRegexDetector is a base helper for regex detectors.
// It contains a map of PIILabel for list of regexes. And also check
// all regexes for each PIILabel and return the first match.
//
// To Create Any new regex detector, you can embed this struct and
// implement Init() method which populate the map with PIILabel and
// list of regexes.

type baseRegexDetector struct {
	m                map[PIILabel][]RegexWithWeight
	hasColumnContext bool // when true, requiresColumnContext patterns are active
}

func (r *baseRegexDetector) Name() string {
	return "regex"
}
func regionMatches(entryRegion, detectorRegion string) bool {
	// if detector has no region set, load everything
	if detectorRegion == "" {
		return true
	}
	// if entry has no region, it's global — always load
	if entryRegion == "" {
		return true
	}
	// load if regions match
	return entryRegion == detectorRegion
}
func (r *baseRegexDetector) filterByRegion(region string) {
	if region == "" {
		return // no filtering needed, load everything
	}
	filtered := make(map[PIILabel][]RegexWithWeight)
	for label, regexes := range r.m {
		var kept []RegexWithWeight
		for _, rx := range regexes {
			if regionMatches(rx.Region, region) {
				kept = append(kept, rx)
			}
		}
		if len(kept) > 0 {
			filtered[label] = kept
		}
	}
	r.m = filtered
}

// Detect checks the word against all regexes for each PIILabel and
// returns the first match.
func (r *baseRegexDetector) Detect(ctx context.Context, word string, hasColumnContext bool) ([]PiiLabelWithWeight, error) {
	if r.m == nil {
		return nil, fmt.Errorf("regex detector not initialized")
	}

	word = strings.ToLower(word)

	var out []PiiLabelWithWeight

	for label, regexes := range r.m {
		for _, v := range regexes {
			if v.RequiresColumnContext && !hasColumnContext {
				continue
			}
			if v.Regexp.MatchString(word) {

				if label == PIILabel_CreditCard {

					cleaned := strings.NewReplacer(
						" ", "",
						"-", "",
						"+", "",
					).Replace(word)

					if !luhnValid(cleaned) {
						continue
					}
				}
				if label == PIILabel_AdharcardNumber {

					cleaned := strings.NewReplacer(
						" ", "",
						"-", "",
					).Replace(word)

					if !verhoeffValid(cleaned) {
						continue
					}
				}
				if label == PIILabel_GSTIN {
					cleaned := strings.ToUpper(strings.TrimSpace(word))
					if !gstinValid(cleaned) {
						continue
					}
				}

				out = append(out, PiiLabelWithWeight{
					PIILabel: label,
					Weight:   v.Weight,
				})

				break
			}
		}
	}

	return out, nil
}

// regexColumnDetector is a detector which uses regexes to detect
// PIILabels for columns.
//
// It uses some common regexes for some known column name patterns.
type regexColumnDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexColumnDetector returns a new regex column detector
func NewRegexColumnDetector() Detector {
	return NewRegexColumnDetectorForRegion("")
}

// NewRegexColumnDetectorForRegion returns a new regex column detector
// that only loads regexes matching the given region.
// Use RegionIndia, RegionUS, RegionUK, or empty string for all regions.
func NewRegexColumnDetectorForRegion(region string) Detector {
	return &regexColumnDetector{
		baseRegexDetector: &baseRegexDetector{},
		region:            region,
	}
}

// Init populates the map with PIILabel and list of regexes for
// known column name patterns.
func (r *regexColumnDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Username: {
			{
				Regexp: regexp.MustCompile(`(?i)^(user[\s_-]?name|user)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(user|login).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Name: {
			{
				Regexp: regexp.MustCompile(`(?i)^(first[\s_-]?name|f[\s_-]?name|last[\s_-]?name|l[\s_-]?name|full[\s_-]?name|full[\s_-]?name|maiden[\s_-]?name|nick[\s_-]?name|person)$`),
				Weight: 1.0,
			},
			{
				// because exact match with column name "name" is low confidence match
				Regexp: regexp.MustCompile(`(?i)^(name)$`),
				Weight: 0.3,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(first[\s_-]?name|f[\s_-]?name|last[\s_-]?name|l[\s_-]?name|full[\s_-]?name|full[\s_-]?name|maiden[\s_-]?name|nick[\s_-]?name|person)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(_name|name).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Email: {
			{
				Regexp: regexp.MustCompile(`(?i)^(mail|email|email[\s_-]?address|e[\s_-]?mail)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(mail).*$`),
				Weight: 0.5,
			},
		},
		PIILabel_Phone: {
			{
				Regexp: regexp.MustCompile(`(?i)^(phone|phone[\s_-]?number|phone[\s_-]?no|phone[\s_-]?num|tele[\s_-]?phone|tele[\s_-]?phone[\s_-]?num|tele[\s_-]?phone[\s_-]?no)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(phone[\s_-]?number|phone[\s_-]?no|phone[\s_-]?num|tele[\s_-]?phone|tele[\s_-]?phone[\s_-]?num|tele[\s_-]?phone[\s_-]?no)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(phone).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_IPAddress: {
			{
				Regexp: regexp.MustCompile(`(?i)^(ip|ip[\s_-]?address|ip[\s_-]?address[\s_-]?v4|ip[\s_-]?address[\s_-]?v6)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(ip[\s_-]?address|ip[\s_-]?address[\s_-]?v4|ip[\s_-]?address[\s_-]?v6)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*([\s_-]ip[\s_-]).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_MacAddress: {
			{
				Regexp: regexp.MustCompile(`(?i)^(mac|mac[\s_-]?address)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*([\s_-]?mac[\s_-]?).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_Address: {
			{
				Regexp: regexp.MustCompile(`(?i)^(address|city|state|county|country|zone|borough)$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(address|city|state|county|country|zone|borough).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_PANNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(pan|permanent|tax|taxpayer|personal|unique)[-_\s]?(num|identification|number|code|no|card|#|id)?\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(pan|permanent|tax|taxpayer|personal|unique)[-_\s]?(account|num|payer|identification|number|code|no|card|id|#)[-_\s]?(num|identification|number|id|code|no|card|#|id)?[-_\s]?(pan)?\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\bpermanent[-_\s]?account[-_\s]?(num|number|code|no|card|#|id)[-_\s]?(pan)?\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(num|number|account)[-_\s]?(PAN|pan)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*[-_\s]pan[-_\s].*$`),
				Weight: 0.4,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(tax)[-_\s]?(number|id|no|#|num)`),
				Weight: 0.4,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(^pan|pan$)`),
				Weight: 0.3,
				Region: RegionIndia,
			},
		},

		PIILabel_DrivingLicenceNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(driver|driving|licence|license|dl)[\s_-]?(identity|number|id|no|card|#)?\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(driver|driving)[\s_-]?(licence|license)`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(driver|driving|licence|license|dl)[\s_-]?(identity|number|id|no|card|#)?`),
				Weight: 0.5,
			},
		},
		PIILabel_Password: {
			{
				Regexp: regexp.MustCompile(`(?i)^(password|pass|passphrase|passkey)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(password|passphrase|passkey)`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*pass.*$`),
				Weight: 0.3,
			},
		},
		PIILabel_CreditCard: {
			{
				Regexp: regexp.MustCompile(`(?i)^(credit[\s-_]?card|cc[\s-_]?number|cc[\s-_]?num|credit[\s-_]?card[\s-_]?num|credit[\s-_]?card[\s-_]?number)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(credit[\s-_]?card|cc[\s-_]?number|cc[\s-_]?num|credit[\s-_]?card[\s-_]?num|credit[\s-_]?card[\s-_]?number)\b`),
				Weight: 0.8,
			},
		},

		PIILabel_BirthDate: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(date[\s-_]?of[\s-_]?birth|dob|birth[\s-_]?day|date[\s-_]?of[\s-_]?death|birth[\s-_]?date).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_Location: {
			{
				Regexp: regexp.MustCompile(`(?i)^(lat|long|lng|latitude|longitude|location)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(location|latitude|longitude).*$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(geo|lat|long|lng).*$`),
				Weight: 0.3,
			},
		},
		PIILabel_OAuthToken: {
			{
				Regexp: regexp.MustCompile(`(?i)^(oauth|oauth[\s-_]?token|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?verifier|oauth[\s-_]?verifier|oauth[\s-_]?verifier[\s-_]?secret|oauth[\s-_]?verifier[\s-_]?secret)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(oauth|oauth[\s-_]?token|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?token[\s-_]?secret|oauth[\s-_]?verifier|oauth[\s-_]?verifier|oauth[\s-_]?verifier[\s-_]?secret|oauth[\s-_]?verifier[\s-_]?secret)`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(token|oauth)`),
				Weight: 0.4,
			},
		},

		PIILabel_Nationality: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(nationality).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_Gender: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gender).*$`),
				Weight: 1.0,
			},
		},
		PIILabel_BankAccountNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(?:bank|checking|savings)?[-_\s]?(?:account|acct|acnt|ac|acc)[-_\s]?(?:number|num|no|#)?[-_\s]?(?:#)?\b`),
				Weight: 0.7,
			},
		},
		PIILabel_DematAccountNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(demat|demat_account|demat_no|demat_number|bo_id|beneficiary_owner|beneficiary_owner_id)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_ChequeNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(cheque|check)([\s_-]?(no|num|number))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_CIFNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(cif|cif_no|cif_number|customer_cif)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_LoanAccountNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(loan_account|loan_account_number|loan_ac|loan_acc|loan_no|loan_number|loan_id)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_InsurancePolicyNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(policy_number|policy_no|policy_num|insurance_policy|insurance_policy_number|insurance_policy_no|policy_id)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_FASTagID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(fastag|fastag_id|fastag_number|fastag_no|fastag_account)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_UPIID: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(upi[\s_-]?id|vpa|virtual[\s_-]?payment[\s_-]?address).*$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(upi).*$`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_CVV: {
			{
				Regexp: regexp.MustCompile(`(?i)^(cvv|cvc|cid|cvn|csc)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^(card[\s_-]?cvv|card[\s_-]?cvc|card[\s_-]?cid|card[\s_-]?code|card[\s_-]?security[\s_-]?code)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)(security[\s_-]?code|verification[\s_-]?code|card[\s_-]?verification)$`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(cvv|cvc|cid|cvn|csc).*$`),
				Weight: 0.5,
			},
		},
		PIILabel_TAN: {
			{
				Regexp: regexp.MustCompile(`(?i)^(tan|tan_number|tan_no|tds_tan|tcs_tan|tax_deduction_account_number|tax_collection_account_number)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(tan|tds_tan|tcs_tan)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_CIN: {
			{
				Regexp: regexp.MustCompile(`(?i)^(cin|cin_number|cin_no|company_cin|corporate_identification_number|company_identification_number)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)\b(cin|company_cin|company_id|corp_id)\b`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_MICRCode: {
			{
				Regexp: regexp.MustCompile(`(?i)^(micr|micr_code|micr_no|micrcode|bank_micr|cheque_micr|branch_micr)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^(micr[\s_-]|[\s_-]micr|bank[\s_-]micr|cheque[\s_-]micr|branch[\s_-]micr).*$`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_GSTIN: {
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gstin|gst).*$`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_AdharcardNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(aadhaar|aadhar|adhaar|adhar|uid)([\s_-]?(no|num|number|id|card))?\b`),
				Weight: 1.0,
			},
		},
		PIILabel_PassportNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(passport)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
			},
		},
		PIILabel_ABHANumber: {
			{
				Regexp: regexp.MustCompile(`(?i)^(abha|abha_number|abha_no|health_id|healthid|health_identifier|abdm_id|abdm_identifier)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(abha|abdm|health_id|healthid).*$`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_UAN: {
			{
				Regexp: regexp.MustCompile(`(?i)^(uan|uan_number|uan_no|epf_uan|employee_uan|universal_account_number)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(uan|epf).*$`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_EPFMemberID: {
			{
				Regexp: regexp.MustCompile(`(?i)^(epf|epf_number|epf_no|epf_member_id|member_id|pf_number|pf_no|provident_fund_number)$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(epf|pf|provident).*$`),
				Weight: 0.5,
				Region: RegionIndia,
			},
		},
		PIILabel_VoterID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b(voter|epic)([\s_-]?(id|no|num|number|card))?\b`),
				Weight: 1.0,
			},
		},
		PIILabel_IFSC: {
			{
				// IFSC column names
				Regexp: regexp.MustCompile(`(?i)\b(ifsc)([\s_-]?(no|num|number|code|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_ESIC: {
			{
				Regexp: regexp.MustCompile(`(?i)^(esic|esic_number|esic_no|esi_number|esi_no|esic_id)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_RationCard: {
			{
				Regexp: regexp.MustCompile(`(?i)^(ration_card|ration_card_no|ration_card_number|ration_no|rc_number)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_SEBIRegistration: {
			{
				Regexp: regexp.MustCompile(`(?i)^(sebi|sebi_reg|sebi_registration|sebi_no|sebi_number|sebi_id)([\s_-]?(no|num|number|id))?\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
	}
	r.filterByRegion(r.region)
	return nil
}

// regexValueDetector is a detector which uses regexes to detect
// PIILabels for values.
//
// It uses some common regexes for some known value patterns.
type regexValueDetector struct {
	*baseRegexDetector
	region string
}

// NewRegexValueDetector returns a new regex value detector
func NewRegexValueDetector() Detector {
	return NewRegexValueDetectorForRegion("")
}

// NewRegexValueDetectorForRegion returns a new regex value detector
// that only loads regexes matching the given region.
// Use RegionIndia, RegionUS, RegionUK, or empty string for all regions.
func NewRegexValueDetectorForRegion(region string) Detector {
	return &regexValueDetector{
		baseRegexDetector: &baseRegexDetector{},
		region:            region,
	}
}

// Init populates the map with PIILabel and list of regexes for
// known value patterns.
func (r *regexValueDetector) Init() error {
	r.m = map[PIILabel][]RegexWithWeight{
		PIILabel_Email: {
			{
				Regexp: regexp.MustCompile(`\b[\w][\w+.-]+(@|%40)[a-z\d-]+(\.[a-z\d-]+)*\.[a-z]+\b`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)([A-Za-z0-9!#$%&'*+\/=?^_{|.}~-]+@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)`),
				Weight: 1.0,
			},
		},
		PIILabel_PANNumber: {
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{3}[AaBbCcFfGgHhJjLlPpTt]{1}[A-Za-z]{1}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`\b([A-Za-z]{5}[0-9]{4}[A-Za-z]{1})\b`),
				Weight: 0.85,
				Region: RegionIndia,
			},
			// {
			// 	Regexp: regexp.MustCompile(`\b((?=.*?[a-zA-Z])(?=.*?[0-9]{4})[\w@#$%^?~-]{10})\b`),
			// 	Weight: 0.05,
			//        Region: RegionIndia,
			// },
		},
		PIILabel_AdharcardNumber: {
			{
				Regexp: regexp.MustCompile(`\b\d{12}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`\b\d{4}[- ]\d{4}[- ]\d{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
		},
		PIILabel_BankAccountNumber: {
			{
				// India: safe lengths - no collision with phone/aadhaar/card
				// includes 9-digit as Indian bank accounts use 9 digits
				// RequiresColumnContext to avoid collision with MICR (9-digit) and CIF (8-11 digit)
				Regexp:                regexp.MustCompile(`^\d{9}$|^\d{11}$|^\d{14}$|^\d{15}$|^\d{17}$|^\d{18}$`),
				Weight:                0.6,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_DematAccountNumber: {
			{
				// NSDL BO ID
				Regexp: regexp.MustCompile(`\bin\d{14}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
			{
				// CDSL BO ID
				Regexp:                regexp.MustCompile(`\b\d{16}\b`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_ChequeNumber: {
			{
				// Indian cheque numbers are typically 6 digits.
				// Require column context to avoid matching OTPs, PINs, invoice IDs, etc.
				Regexp:                regexp.MustCompile(`^\d{6}$`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_CIFNumber: {
			{
				// Typical Indian bank CIF numbers.
				Regexp:                regexp.MustCompile(`^\d{8,11}$`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_LoanAccountNumber: {
			{
				// Indian loan account numbers (bank specific)
				Regexp:                regexp.MustCompile(`^[A-Za-z0-9]{10,20}$`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_InsurancePolicyNumber: {
			{
				// Indian insurance policy numbers (insurer specific)
				Regexp:                regexp.MustCompile(`^[A-Za-z0-9]{8,20}$`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_FASTagID: {
			{
				// FASTag identifiers are issuer specific.
				Regexp:                regexp.MustCompile(`^[A-Za-z0-9]{10,24}$`),
				Weight:                0.3,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_UPIID: {
			{
				Regexp: regexp.MustCompile(`(?i)^[\w.\-]{2,}@(ybl|ibl|axl|okaxis|okhdfcbank|okicici|oksbi|paytm|ptsbi|pthdfc|ptaxis|ptyes|apl|rapl|yapl|waaxis|waicici|wahdfcbank|wasbi|yesg|yescred|yespop|superyes|ikwik|mvhdfc|fkaxis|indie|federal|fifederal|icici|axisb|hsbc|idbi|indianbank|allbank|kotak|kotak811|barodampay|pnb|unionbank|canara|bob|sbi|hdfcbank|icicibank|axisbank|idfcfirst|idfc|rbl|bandhan|yesbank|indus|indusind|au|aubank|equitas|ujjivan|airtel|freecharge|famapp|slice|cred|groww|jupiter|mobikwik|amazonpay|flipkart|phonepe|gpay|bhim)$`),
				Weight: 1.2,
				Region: RegionIndia,
			},
		},
		PIILabel_CVV: {
			{
				Regexp:                regexp.MustCompile(`^[0-9]{3,4}$`),
				Weight:                0.9,
				RequiresColumnContext: true,
			},
		},
		PIILabel_TAN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{4}[0-9]{5}[A-Z]\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
		},
		PIILabel_CIN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[LU][0-9]{5}(?:AN|AP|AR|AS|BR|CH|CG|DD|DL|DN|GA|GJ|HP|HR|JH|JK|KA|KL|LA|LD|MH|ML|MN|MP|MZ|NL|OD|PB|PY|RJ|SK|TN|TR|TS|UK|UP|WB)(?:18|19|20|21)[0-9]{2}[A-Z]{3}[0-9]{6}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_DrivingLicenceNumber: {
			{
				// indian driving license regex
				Regexp: regexp.MustCompile(`(?i)^((?:ap|ar|as|br|cg|ch|dl|ga|gj|hp|hr|jh|jk|ka|kl|la|mh|ml|mn|mp|mz|nl|od|pb|py|rj|sk|tn|tr|ts|uk|up|wb|an|dd|dn)[\s_-]?[0-9]{2}[\s_-]?(?:19|20)[0-9]{2}[\s_-]?[0-9]{7})$`),
				Weight: 1,
				Region: RegionIndia,
			},
		},

		PIILabel_Gender: {
			{
				Regexp: regexp.MustCompile(`(?i)^(male|female|girl|boy|other|prefer[\s-_]?not[\s-_]?to[\s-_]?say|prefer[\s-_]?not[\s-_]?to[\s-_]?disclose|not[\s-_]?specified|transgender|non[\s-_]?binary)$`),
				Weight: 1.0,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^.*(gender).*$`),
				Weight: 0.5,
			},
			{
				Regexp: regexp.MustCompile(`(?i)^(m|f|n)$`),
				Weight: 0.3,
			},
		},

		PIILabel_Phone: {
			{
				// India mobile - bare 10 digit
				Regexp: regexp.MustCompile(`^[6-9][0-9]{9}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// India mobile - 0 prefix
				Regexp: regexp.MustCompile(`^0[6-9][0-9]{9}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// India mobile - 91 prefix
				Regexp: regexp.MustCompile(`^91[6-9][0-9]{9}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				// India mobile - +91 prefix
				Regexp: regexp.MustCompile(`^\+91[\s-]?[6-9][0-9]{4}[\s-]?[0-9]{5}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_CreditCard: {
			{
				// 16-digit cards with separators (Visa, MC, RuPay, Discover)
				Regexp: regexp.MustCompile(`\b([234568]\d{3}[\s\-]*\d{4}[\s\-]*\d{4}[\s\-]*\d{4})\b`),
				Weight: 1.0,
			},
			{
				// 16-digit cards plain (no separator)
				Regexp: regexp.MustCompile(`\b[234568]\d{15}\b`),
				Weight: 1.0,
			},
			{
				// 15-digit Amex: 4-6-5 or 4-4-3 format or plain
				Regexp: regexp.MustCompile(`\b(3[47]\d{2}[\s\-]\d{4,6}[\s\-]\d{3,5})\b`),
				Weight: 1.0,
			},
			{
				// 15-digit Amex plain
				Regexp: regexp.MustCompile(`\b3[47]\d{13}\b`),
				Weight: 1.0,
			},
		},
		PIILabel_VoterID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{3}\d{7}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
		},
		PIILabel_IFSC: {
			{
				// IFSC: 4 letters + 0 + 6 alphanumeric
				Regexp: regexp.MustCompile(`(?i)^[A-Z]{4}0[A-Z0-9]{6}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_MICRCode: {
			{
				// MICR: 9-digit City(3)+Bank(3)+Branch(3). Column context required.
				Regexp:                regexp.MustCompile(`\b\d{9}\b`),
				Weight:                0.7,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_PassportNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)^[A-HJ-NPR-WYZ][\s-]?[1-9][0-9]{6}$`),
				Weight: 1.0,
				Region: RegionIndia,
			},
		},
		PIILabel_ABHANumber: {
			{
				Regexp: regexp.MustCompile(`\b\d{2}-\d{4}-\d{4}-\d{4}\b`),
				Weight: 1.0,
				Region: RegionIndia,
			},
			{
				Regexp: regexp.MustCompile(`\b\d{14}\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
		},
		PIILabel_UAN: {
			{
				Regexp:                regexp.MustCompile(`\b[1-9][0-9]{11}\b`),
				Weight:                0.95,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_EPFMemberID: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{2}[A-Z]{3}[0-9]{7}[0-9]{5,10}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_GSTIN: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_VehicleNumber: {
			{
				Regexp: regexp.MustCompile(`(?i)\b[A-Z]{2}[\\ -]?[0-9]{2}[\\ -]?[A-Z]{1,2}[\\ -]?[0-9]{4}\b`),
				Weight: 0.8,
				Region: RegionIndia,
			},
		},

		PIILabel_IPAddress: {
			{
				Regexp: regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)(:\d{1,5})?\b`), //ipv4
				Weight: 1.0,
			},
			// regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})|(([0-9a-fA-F]{1,4}:){1,7}|:):((:[0-9a-fA-F]{1,4}){1,7}|:))$`),
		},
		PIILabel_MacAddress: {
			{
				Regexp: regexp.MustCompile(`\b[0-9a-fA-F]{2}(?:(?::|%3A)[0-9a-fA-F]{2}){5}\b`),
				Weight: 1.0,
			},
		},
		PIILabel_OAuthToken: {
			{
				Regexp: regexp.MustCompile(`ya29\..{60,200}`), // google oauth token
				Weight: 0.3,
			},
		},

		PIILabel_Address: {
			{
				Regexp: regexp.MustCompile(`(?i)\b\d+\b.{4,60}\b(st|street|ave|avenue|road|rd|drive|dr)\b`),
				Weight: 0.8,
			},
			{
				Regexp: regexp.MustCompile(`\d{1,4} [a-zA-Z0-9]{1,20}( (street|st|avenue|ave|road|rd|highway|hwy|square|sq|trail|trl|drive|dr|court|ct|park|parkway|pkwy|circle|cir|boulevard|blvd))\W?(\s|$)`),
				Weight: 0.8,
			},
		},
		PIILabel_ESIC: {
			{
				// ESIC: 17-digit format XX-XX-XXXXXX-XXX-XXXX
				Regexp: regexp.MustCompile(`\b\d{2}[-\s]\d{2}[-\s]\d{6}[-\s]\d{3}[-\s]\d{4}\b`),
				Weight: 0.9,
				Region: RegionIndia,
			},
		},
		PIILabel_RationCard: {
			{
				// Ration card: state code + alphanumeric
				Regexp:                regexp.MustCompile(`(?i)^[A-Z]{2}[-/]?\d{10,15}$`),
				Weight:                0.7,
				Region:                RegionIndia,
				RequiresColumnContext: true,
			},
		},
		PIILabel_SEBIRegistration: {
			{
				// SEBI: INZ/INH/INP + 9 digits e.g. INZ000123456
				Regexp: regexp.MustCompile(`(?i)\b(INZ|INH|INP|INR|INA|INM|INQ)\d{9}\b`),
				Weight: 0.95,
				Region: RegionIndia,
			},
		},
		PIILabel_BirthDate: {
			{
				// Common date formats: DD/MM/YYYY, DD-MM-YYYY, YYYY-MM-DD, DD.MM.YYYY
				Regexp:                regexp.MustCompile(`\b(0[1-9]|[12]\d|3[01])[\/\-\.](0[1-9]|1[0-2])[\/\-\.](19|20)\d{2}\b|\b(19|20)\d{2}[\/\-\.](0[1-9]|1[0-2])[\/\-\.](0[1-9]|[12]\d|3[01])\b`),
				Weight:                0.7,
				RequiresColumnContext: true,
			},
		},
		PIILabel_Location: {
			{
				// Latitude/Longitude coordinate pair: 18.9220, 72.8347
				Regexp:                regexp.MustCompile(`^[-+]?([1-8]?\d(\.\d+)?|90(\.0+)?),\s*[-+]?(180(\.0+)?|((1[0-7]\d)|([1-9]?\d))(\.\d+)?)$`),
				Weight:                0.9,
				RequiresColumnContext: true,
			},
		},
	}
	r.filterByRegion(r.region)
	return nil
}
