package piiscanner

import "testing"

func TestPiiLabelMapPreservesContext(t *testing.T) {
	labels := NewPiiLabelMap()
	labels.Add("regex", PIILabel_PANNumber, 1.0, false)
	labels.Add("regex", PIILabel_PANNumber, 1.0, true)

	got := labels["regex"][PIILabel_PANNumber]
	if !got.ContextMatched {
		t.Fatal("context provenance was lost during aggregation")
	}
	if got.Weight != 2.0 || got.Count != 2 {
		t.Fatalf("aggregation changed unexpectedly: %#v", got)
	}
}

func TestResolveColumnConflictsUsesExplicitContextNotWeight(t *testing.T) {

	candidates := []PIIDataWithWeightString{
		{
			Label:          PIILabel_Email,
			Confidence:     "High",
			ConfidenceIcon: "🔴",
			Weight:         1.0,
			Tier:           Tier1,
			DetectorType:   DetectorType_ValueDetector,
		},
		{
			Label:          PIILabel_CVV,
			Confidence:     "High",
			ConfidenceIcon: "🔴",
			Weight:         1.0,
			Tier:           Tier3,
			DetectorType:   DetectorType_ValueDetector,
		},
	}

	got := ResolveConflicts(false, "", candidates)
	if len(got) != 1 || got[0].Label != PIILabel_Email {
		t.Fatalf("weight-only match bypassed context and domain protections: %#v", got)
	}
}

func TestResolveColumnConflictsHonorsEmbeddedKeyContext(t *testing.T) {
	candidate := PIIDataWithWeightString{
		Label:            PIILabel_CVV,
		Confidence:       "High",
		ConfidenceIcon:   "🔴",
		Weight:           1.0,
		Tier:             Tier3,
		ContextMatched:   true,
		DetectorType:     DetectorType_ValueDetector,
		ScanedValueCount: 1,
		MatchedCount:     1,
	}

	got := ResolveConflicts(false, "", []PIIDataWithWeightString{candidate})
	if len(got) != 1 {
		t.Fatalf("embedded-key context finding was removed: %#v", got)
	}
	if got[0].Confidence != "High" || got[0].Weight != 1.0 {
		t.Fatalf("embedded-key context finding was capped: %#v", got[0])
	}
}

func TestResolveColumnConflictsCapsWeightOneWithoutContext(t *testing.T) {
	candidate := PIIDataWithWeightString{
		Label:          PIILabel_PassportNumber,
		Confidence:     "High",
		ConfidenceIcon: "🔴",
		Weight:         1.0,
		Tier:           Tier2,
		DetectorType:   DetectorType_ValueDetector,
	}

	got := ResolveConflicts(false, "", []PIIDataWithWeightString{candidate})
	if len(got) != 1 {
		t.Fatalf("candidate unexpectedly removed: %#v", got)
	}
	if got[0].Confidence != "Medium" || got[0].Weight != 0.69 {
		t.Fatalf("weight-one candidate without context was not capped: %#v", got[0])
	}
}

func TestResolveColumnConflictsPrefersAadhaarOverUANAtHighConfidence(t *testing.T) {
	candidates := []PIIDataWithWeightString{
		{
			Label:          PIILabel_AdharcardNumber,
			Confidence:     "High",
			ConfidenceIcon: "🔴",
			// Aadhaar has both column and value evidence.
			Weight:           1.0,
			Tier:             Tier1,
			ContextMatched:   true,
			DetectorType:     DetectorType_ValueDetector,
			ScanedValueCount: 5068,
			MatchedCount:     5068,
		},
		{
			Label:            PIILabel_UAN,
			Confidence:       "High",
			ConfidenceIcon:   "🔴",
			Weight:           0.95,
			Tier:             Tier2,
			DetectorType:     DetectorType_ValueDetector,
			ScanedValueCount: 5068,
			MatchedCount:     5068,
		},
	}

	got := ResolveConflicts(true, DomainNationalID, candidates)
	if len(got) != 1 {
		t.Fatalf("resolved findings=%d, want 1: %#v", len(got), got)
	}
	if got[0].Label != PIILabel_AdharcardNumber {
		t.Fatalf("winner=%s, want %s", got[0].Label, PIILabel_AdharcardNumber)
	}
}

func TestResolveColumnConflictsKeepsIndependentDocumentKeyFindings(t *testing.T) {
	candidates := []PIIDataWithWeightString{
		{
			Label:            PIILabel_EPFMemberID,
			Confidence:       "High",
			ConfidenceIcon:   "🔴",
			Weight:           1.0,
			Tier:             Tier2,
			ContextMatched:   true,
			DetectorType:     DetectorType_ValueDetector,
			ScanedValueCount: 3024,
			MatchedCount:     3024,
		},
		{
			Label:            PIILabel_UAN,
			Confidence:       "High",
			ConfidenceIcon:   "🔴",
			Weight:           1.0,
			Tier:             Tier2,
			ContextMatched:   true,
			DetectorType:     DetectorType_ValueDetector,
			ScanedValueCount: 3024,
			MatchedCount:     3024,
		},
	}

	got := ResolveConflicts(false, DomainEmployment, candidates)
	if len(got) != 2 {
		t.Fatalf("resolved document findings=%d, want 2: %#v", len(got), got)
	}
	if !containsResolvedLabel(got, PIILabel_EPFMemberID) {
		t.Fatalf("resolved findings do not contain %s: %#v", PIILabel_EPFMemberID, got)
	}
	if !containsResolvedLabel(got, PIILabel_UAN) {
		t.Fatalf("resolved findings do not contain %s: %#v", PIILabel_UAN, got)
	}
}

func TestResolveColumnConflictsKeepsExtractedLabelsAcrossConfidenceBands(t *testing.T) {
	candidates := []PIIDataWithWeightString{
		{
			Label:          PIILabel_PANNumber,
			Confidence:     "Medium",
			ConfidenceIcon: "🟡",
			Weight:         0.45,
			Tier:           Tier1,
			ContextMatched: true,
			DetectorType:   DetectorType_ValueDetector,
		},
		{
			Label:          PIILabel_AdharcardNumber,
			Confidence:     "Low",
			ConfidenceIcon: "🔵",
			Weight:         0.20,
			Tier:           Tier1,
			ContextMatched: true,
			DetectorType:   DetectorType_ValueDetector,
		},
		{
			Label:          PIILabel_Email,
			Confidence:     "Low",
			ConfidenceIcon: "🔵",
			Weight:         0.28,
			Tier:           Tier1,
			DetectorType:   DetectorType_ValueDetector,
		},
	}

	got := ResolveConflicts(false, DomainNationalID, candidates)
	if len(got) != 3 {
		t.Fatalf("resolved findings=%d, want 3: %#v", len(got), got)
	}
	for _, label := range []PIILabel{PIILabel_PANNumber, PIILabel_AdharcardNumber, PIILabel_Email} {
		if !containsResolvedLabel(got, label) {
			t.Fatalf("resolved findings do not contain %s: %#v", label, got)
		}
	}
}

func containsResolvedLabel(labels []PIIDataWithWeightString, want PIILabel) bool {
	_, ok := findResolvedLabel(labels, want)
	return ok
}

func findResolvedLabel(labels []PIIDataWithWeightString, want PIILabel) (PIIDataWithWeightString, bool) {
	for _, label := range labels {
		if label.Label == want {
			return label, true
		}
	}
	return PIIDataWithWeightString{}, false
}
