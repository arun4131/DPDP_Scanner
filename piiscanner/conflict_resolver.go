package piiscanner

import "sort"

func ResolveConflicts(hascolumnmatch bool, Tabledomain Domain, candidates []PIIDataWithWeightString) []PIIDataWithWeightString {

	filtered := []PIIDataWithWeightString{}

	for _, candidate := range candidates {
		if candidate.Tier == "" {
			candidate.Tier = GetEntityTier(candidate.Label)
		}

		// if column name does not match and it also not matched inside documents
		if !hascolumnmatch && !candidate.ContextMatched {
			// reduce weight of tier2 , 3 entities.
			if candidate.Tier == Tier2 || candidate.Tier == Tier3 {
				if candidate.Weight >= 0.70 {
					candidate.Weight = 0.69
					candidate.Confidence = "Medium"
					candidate.ConfidenceIcon = "🟡"
				}
			}

			// apply domain gating.
			if candidate.Tier == Tier3 {
				candidateDomain := EntityDomainMap[candidate.Label]

				if candidateDomain == "" ||
					Tabledomain == "" ||
					candidateDomain != Tabledomain {
					continue
				}
			}
		}

		filtered = append(filtered, candidate)
	}

	sortingTheCandidates(filtered)

	// if only column name is not matching then return filtered.
	if !hascolumnmatch {
		return filtered
	}

	finalResults := []PIIDataWithWeightString{}

	for _, detectorType := range []DetectorType{DetectorType_ColumnDetector, DetectorType_ValueDetector} {
		for _, candidate := range filtered {
			if candidate.DetectorType == detectorType {
				finalResults = append(finalResults, candidate)
				break
			}
		}
	}

	return finalResults
}

// sorts the candidates
func sortingTheCandidates(candidates []PIIDataWithWeightString) {
	sort.Slice(candidates, func(i, j int) bool {
		return sorting(candidates[i], candidates[j])
	})
}

// sorts two elements.
func sorting(first PIIDataWithWeightString, second PIIDataWithWeightString) bool {
	if first.Weight != second.Weight {
		return first.Weight > second.Weight
	}

	if first.ContextMatched != second.ContextMatched {
		return first.ContextMatched
	}

	return first.Label < second.Label
}
