package piiscanner

import "testing"

func TestPiiLabelMapPreservesContextProvenance(t *testing.T) {
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
	resolver := NewConflictResolver()

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

	got := resolver.ResolveColumnConflicts("users", "value_01", false, "", candidates)
	if len(got) != 1 || got[0].Label != PIILabel_Email {
		t.Fatalf("weight-only match bypassed obfuscated-column protection: %#v", got)
	}
}

func TestResolveColumnConflictsHonorsEmbeddedKeyContext(t *testing.T) {
	resolver := NewConflictResolver()
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

	got := resolver.ResolveColumnConflicts("payments", "payload", false, "", []PIIDataWithWeightString{candidate})
	if len(got) != 1 {
		t.Fatalf("embedded-key context finding was removed: %#v", got)
	}
	if got[0].Confidence != "High" || got[0].Weight != 1.0 {
		t.Fatalf("embedded-key context finding was capped: %#v", got[0])
	}
}

func TestResolveColumnConflictsCapsWeightOneWithoutContext(t *testing.T) {
	resolver := NewConflictResolver()
	candidate := PIIDataWithWeightString{
		Label:          PIILabel_PassportNumber,
		Confidence:     "High",
		ConfidenceIcon: "🔴",
		Weight:         1.0,
		Tier:           Tier2,
		DetectorType:   DetectorType_ValueDetector,
	}

	got := resolver.ResolveColumnConflicts("users", "value_01", false, "", []PIIDataWithWeightString{candidate})
	if len(got) != 1 {
		t.Fatalf("candidate unexpectedly removed: %#v", got)
	}
	if got[0].Confidence != "Medium" || got[0].Weight != 0.69 {
		t.Fatalf("weight-one candidate without context was not capped: %#v", got[0])
	}
}
