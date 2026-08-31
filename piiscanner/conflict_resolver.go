package piiscanner

import "sort"

const (
	highConfidenceWeight   = 0.70
	mediumConfidenceWeight = 0.69
)

// ResolveConflicts filters the candidates and returns the final results.
func ResolveConflicts(
	hasColumnMatch bool,
	dominantDomain Domain,
	candidates []PIIDataWithWeightString,
) []PIIDataWithWeightString {
	candidates = filterCandidates(
		candidates,
		hasColumnMatch,
		dominantDomain,
	)

	if len(candidates) == 0 {
		return nil
	}

	sortCandidates(candidates)

	return selectResults(candidates, hasColumnMatch)
}

// filterCandidates applies noise reduction when context is unavailable.
func filterCandidates(
	candidates []PIIDataWithWeightString,
	hasColumnMatch bool,
	dominantDomain Domain,
) []PIIDataWithWeightString {
	filtered := make(
		[]PIIDataWithWeightString,
		0,
		len(candidates),
	)

	for _, candidate := range candidates {
		if candidate.Tier == "" {
			candidate.Tier = GetEntityTier(candidate.Label)
		}

		hasContext := hasColumnMatch ||
			candidate.ContextMatched

		if !hasContext {
			candidate = confidenceReduction(candidate)

			if !domainGating(candidate, dominantDomain) {
				continue
			}
		}

		filtered = append(filtered, candidate)
	}

	return filtered
}

// confidenceReduction prevents generic patterns from becoming High confidence.
func confidenceReduction(
	candidate PIIDataWithWeightString,
) PIIDataWithWeightString {
	isGenericTier := candidate.Tier == Tier2 || candidate.Tier == Tier3

	if isGenericTier &&
		candidate.Weight >= highConfidenceWeight {
		candidate.Weight = mediumConfidenceWeight
		candidate.Confidence = "Medium"
		candidate.ConfidenceIcon = "🟡"
	}

	return candidate
}

// domainGating checks whether a Tier 3 finding belongs to the table domain.
func domainGating(
	candidate PIIDataWithWeightString,
	dominantDomain Domain,
) bool {
	if candidate.Tier != Tier3 {
		return true
	}

	candidateDomain := EntityDomainMap[candidate.Label]

	if candidateDomain == "" ||candidateDomain == DomainPersonal {
		return true
	}

	return dominantDomain != "" && candidateDomain == dominantDomain
}

// sortCandidates places the strongest candidate first.
func sortCandidates(
	candidates []PIIDataWithWeightString,
) {
	sort.Slice(candidates, func(i, j int) bool {
		first := candidates[i]
		second := candidates[j]

		if first.Weight != second.Weight {
			return first.Weight > second.Weight
		}

		if first.ContextMatched != second.ContextMatched {
			return first.ContextMatched
		}

		return first.Label < second.Label
	})
}

// selectResults handles normal columns and container columns separately.
func selectResults(
	candidates []PIIDataWithWeightString,
	hasColumnMatch bool,
) []PIIDataWithWeightString {
	var results []PIIDataWithWeightString

	detectorTypes := []DetectorType{
		DetectorType_ColumnDetector,
		DetectorType_ValueDetector,
	}

	for _, detectorType := range detectorTypes {
		group := candidatesForDetector(
			candidates,
			detectorType,
		)

		if len(group) == 0 {
			continue
		}

		if hasColumnMatch {
			// A normal column contains one logical field.
			results = append(results, group[0])
			continue
		}

		// Document and unknown columns were already resolved field by field.
		results = append(results, group...)
	}

	return results
}

func candidatesForDetector(
	candidates []PIIDataWithWeightString,
	detectorType DetectorType,
) []PIIDataWithWeightString {
	var matching []PIIDataWithWeightString

	for _, candidate := range candidates {
		if candidate.DetectorType == detectorType {
			matching = append(matching, candidate)
		}
	}

	return matching
}
