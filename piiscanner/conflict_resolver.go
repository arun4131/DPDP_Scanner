package piiscanner

import (
	"sort"
)

type ConflictResolver struct{}

// NewConflictResolver creates a new ConflictResolver instance
func NewConflictResolver() *ConflictResolver {
	return &ConflictResolver{}
}

// ResolveColumnConflicts evaluates all candidate findings for a column and returns
// the resolved, filtered, and suppressed winning list of findings.
func (c *ConflictResolver) ResolveColumnConflicts(
	tableName string,
	columnName string,
	hasColumnMatch bool,
	dominantDomain Domain,
	candidates []PIIDataWithWeightString,
) []PIIDataWithWeightString {

	if len(candidates) == 0 {
		return candidates
	}

	var filtered []PIIDataWithWeightString

	for _, item := range candidates {
		// Ensure Tier is populated
		if item.Tier == "" {
			item.Tier = GetEntityTier(item.Label)
		}

		// Rules for findings without trusted context. A matching outer column
		// provides context for the whole column; an embedded key provides context
		// only for the entity detected under that key.
		if !hasColumnMatch && !item.ContextMatched {
			// Rule 1: Cap Tier 2 and Tier 3 findings at Medium on obfuscated
			// columns. Explicit embedded-key context is exempt regardless of weight.
			if item.Tier == Tier2 || item.Tier == Tier3 {
				if item.Weight >= 0.70 {
					item.Weight = 0.69
					item.Confidence = "Medium"
					item.ConfidenceIcon = "🟡"
				}
			}

			// Rule 2: Applying Domain Gating on un-keyed Tier 3 candidates (Weight < 1.0)
			if item.Tier == Tier3 && item.Weight < 1.0 {
				candidateDomain := EntityDomainMap[item.Label]
				if candidateDomain != "" && candidateDomain != DomainPersonal {
					if dominantDomain == "" || candidateDomain != dominantDomain {
						// Drop un-keyed Tier 3 candidate if table domain is unknown or conflicts
						continue
					}
				}
			}
		}

		filtered = append(filtered, item)
	}

	if len(filtered) == 0 {
		return filtered
	}

	// Rule 3: Rank candidates by Confidence -> Tier -> Match Density -> Weight
	sort.Slice(filtered, func(i, j int) bool {
		rankI := confidenceRank(filtered[i].Confidence)
		rankJ := confidenceRank(filtered[j].Confidence)
		if rankI != rankJ {
			return rankI > rankJ
		}

		tierI := TierRank(filtered[i].Tier)
		tierJ := TierRank(filtered[j].Tier)
		if tierI != tierJ {
			return tierI > tierJ
		}

		var densityI, densityJ float64
		if filtered[i].ScanedValueCount > 0 {
			densityI = float64(filtered[i].MatchedCount) / float64(filtered[i].ScanedValueCount)
		}
		if filtered[j].ScanedValueCount > 0 {
			densityJ = float64(filtered[j].MatchedCount) / float64(filtered[j].ScanedValueCount)
		}
		if densityI != densityJ {
			return densityI > densityJ
		}

		return filtered[i].Weight > filtered[j].Weight
	})

	// Rule 4: Primary Winner Suppression (performed per DetectorType so Meta Scan and Data Scan remain intact)
	var finalOutput []PIIDataWithWeightString

	for _, dt := range []DetectorType{DetectorType_ColumnDetector, DetectorType_ValueDetector} {
		var sub []PIIDataWithWeightString
		for _, item := range filtered {
			if item.DetectorType == dt {
				sub = append(sub, item)
			}
		}
		if len(sub) == 0 {
			continue
		}

		topConfidence := sub[0].Confidence
		if topConfidence == "High" {
			for _, item := range sub {
				if item.Confidence == "High" {
					finalOutput = append(finalOutput, item)
				}
			}
		} else if topConfidence == "Medium" {
			for _, item := range sub {
				if item.Confidence == "High" || item.Confidence == "Medium" {
					finalOutput = append(finalOutput, item)
				}
			}
		} else {
			finalOutput = append(finalOutput, sub...)
		}
	}

	return finalOutput
}

func confidenceRank(conf string) int {
	switch conf {
	case "High":
		return 3
	case "Medium":
		return 2
	case "Low":
		return 1
	default:
		return 0
	}
}
