package piiscanner

import (
	"sort"
)

type ConflictResolver struct{}

// NewConflictResolver creates a new conflictresolver instance.
func NewConflictResolver() *ConflictResolver {
	return &ConflictResolver{}
}

// ResolveColumnConflicts solves conflicts and filters the final results.
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
		// To get it's tier .
		if item.Tier == "" {
			item.Tier = GetEntityTier(item.Label)
		}

		// This case is for no column name match or for obfuscated columns.
		// values matched a known pattern or value regex.
		if !hasColumnMatch && !item.ContextMatched {
			// Makes the highest confidence as medium for tier 2 ,3 entities for unkown columns.
			if item.Tier == Tier2 || item.Tier == Tier3 {
				if item.Weight >= 0.70 {
					item.Weight = 0.69
					item.Confidence = "Medium"
					item.ConfidenceIcon = "🟡"
				}
			}

			// Domain gating is used for Tier 3 entities becasue of their generic pattern.
			// Domain gating helps to reduce fp's occuring with these tier 3 entities.
			if item.Tier == Tier3 && item.Weight < 1.0 {
				candidateDomain := EntityDomainMap[item.Label]
				if candidateDomain != "" && candidateDomain != DomainPersonal {
					if dominantDomain == "" || candidateDomain != dominantDomain {
						// An unknown or conflicting domain is not enough support.
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

	// Ranking the strongest evidence first. Because label is the final tie-breaker so
	// repeated scans produce the same order.
	sort.Slice(filtered, func(i, j int) bool {
		rankI := confidenceRank(filtered[i].Confidence)
		rankJ := confidenceRank(filtered[j].Confidence)
		if rankI != rankJ {
			return rankI > rankJ
		}

		if filtered[i].ContextMatched != filtered[j].ContextMatched {
			return filtered[i].ContextMatched
		}

		tierI := TierRank(filtered[i].Tier)
		tierJ := TierRank(filtered[j].Tier)
		if tierI != tierJ {
			return tierI > tierJ
		}

		// A confidence band can contain different scores, so compare the exact
		// weight next.
		if filtered[i].Weight != filtered[j].Weight {
			return filtered[i].Weight > filtered[j].Weight
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

		// Keep the result stable when every other signal is tied.
		return filtered[i].Label < filtered[j].Label
	})

	// Resolve metadata and value findings separately because they are reported in
	// different scan sections.
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

		// sub keeps the strongest-to-weakest order from filtered.
		if hasColumnMatch {
			// A known physical column represents one field, so it gets one winner.
			finalOutput = append(finalOutput, sub[0])
			continue
		}

		// The worker has already resolved conflicts for candidates with match
		// positions. Keep those winners and use the confidence fallback only for
		// detectors that do not provide positions.
		var unresolved []PIIDataWithWeightString
		for _, item := range sub {
			if item.ProvenanceResolved {
				finalOutput = append(finalOutput, item)
				continue
			}
			unresolved = append(unresolved, item)
		}
		if len(unresolved) == 0 {
			continue
		}

		topConfidence := unresolved[0].Confidence
		for _, item := range unresolved {
			if item.Confidence == topConfidence {
				finalOutput = append(finalOutput, item)
			}
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
