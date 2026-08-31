package piiscanner

import (
	"context"
	"testing"
)

func TestLogicalValuePrefersContextualFASTagOverCreditCard(t *testing.T) {
	detector := NewRegexValueDetector()
	if err := detector.Init(); err != nil {
		t.Fatalf("initialize regex detector: %v", err)
	}

	value := "341610000000004" // Luhn-valid and therefore also card-shaped.
	columnContext := ColumnContext{PIILabel_FASTagID: true}
	raw, err := detector.Detect(context.Background(), value, columnContext)
	if err != nil {
		t.Fatalf("detect raw candidates: %v", err)
	}
	if !containsPIILabel(raw, PIILabel_FASTagID) || !containsPIILabel(raw, PIILabel_CreditCard) {
		t.Fatalf("fixture must produce FASTag and CreditCard candidates: %#v", raw)
	}

	resolved, err := detectLogicalValue(context.Background(), detector, value, columnContext)
	if err != nil {
		t.Fatalf("resolve logical value: %v", err)
	}
	assertOnlyLabel(t, resolved, PIILabel_FASTagID)
}

func TestLogicalValuePrefersContextualAadhaarOverUAN(t *testing.T) {
	detector := NewRegexValueDetector()
	if err := detector.Init(); err != nil {
		t.Fatalf("initialize regex detector: %v", err)
	}

	resolved, err := detectLogicalValue(
		context.Background(),
		detector,
		"123456789010",
		ColumnContext{PIILabel_AdharcardNumber: true},
	)
	if err != nil {
		t.Fatalf("resolve logical value: %v", err)
	}
	assertOnlyLabel(t, resolved, PIILabel_AdharcardNumber)
}

func TestLogicalValueKeepsNonOverlappingEmailAndPhone(t *testing.T) {
	detector := NewRegexValueDetector()
	if err := detector.Init(); err != nil {
		t.Fatalf("initialize regex detector: %v", err)
	}

	resolved, err := detectFieldValue(
		context.Background(),
		detector,
		"contact person@example.com or 9876543210",
		nil,
		true,
	)
	if err != nil {
		t.Fatalf("resolve logical value: %v", err)
	}
	if !containsPIILabel(resolved, PIILabel_Email) {
		t.Fatalf("email was lost: %#v", resolved)
	}
	if !containsPIILabel(resolved, PIILabel_Phone) {
		t.Fatalf("phone was lost: %#v", resolved)
	}
}

func TestStructuredCellResolvesEachExtractedValueIndependently(t *testing.T) {
	ctx := context.Background()
	manager := NewTableScanManager().
		WithColumnDetector(NewRegexColumnDetector()).
		WithDetectorFactory(func() []Detector { return []Detector{NewRegexValueDetector()} })
	if err := manager.Start(ctx, 1); err != nil {
		t.Fatalf("start manager: %v", err)
	}

	if err := manager.PushValue(ScanInput{
		Tablename:  "vehicles",
		ColumnName: "vehicle_metadata",
		Value:      `{"fastag":"341610000000004","vehicle":"MH02BA0001"}`,
	}); err != nil {
		t.Fatalf("push structured value: %v", err)
	}

	output, err := manager.Output()
	if err != nil {
		t.Fatalf("get output: %v", err)
	}
	labels := output["vehicles"].PiiDataMap["vehicle_metadata"].ValueMap["regex"]
	if _, ok := labels[PIILabel_FASTagID]; !ok {
		t.Fatalf("FASTag winner missing: %#v", labels)
	}
	if _, ok := labels[PIILabel_VehicleNumber]; !ok {
		t.Fatalf("vehicle winner missing: %#v", labels)
	}
	if _, ok := labels[PIILabel_CreditCard]; ok {
		t.Fatalf("overlapping CreditCard candidate survived: %#v", labels)
	}
}

func TestRecognizedScalarColumnBypassesKeyValueExtraction(t *testing.T) {
	ctx := context.Background()
	manager := NewTableScanManager().
		WithColumnDetector(NewRegexColumnDetector()).
		WithDetectorFactory(func() []Detector { return []Detector{NewRegexValueDetector()} })
	if err := manager.Start(ctx, 1); err != nil {
		t.Fatalf("start manager: %v", err)
	}

	if err := manager.PushValue(ScanInput{
		Tablename:  "network_activity",
		ColumnName: "device_mac",
		Value:      "0a:be:ef:00:00:01",
	}); err != nil {
		t.Fatalf("push MAC value: %v", err)
	}

	output, err := manager.Output()
	if err != nil {
		t.Fatalf("get output: %v", err)
	}
	labels := output["network_activity"].PiiDataMap["device_mac"].ValueMap["regex"]
	mac, ok := labels[PIILabel_MacAddress]
	if !ok {
		t.Fatalf("complete scalar MAC value was not detected: %#v", labels)
	}
	if mac.Count != 1 || !mac.ContextMatched {
		t.Fatalf("MAC aggregation=%#v, want one contextual match", mac)
	}
}

func assertOnlyLabel(t *testing.T, labels []PiiLabelWithWeight, want PIILabel) {
	t.Helper()
	if len(labels) != 1 || labels[0].PIILabel != want {
		t.Fatalf("resolved labels=%#v, want only %s", labels, want)
	}
}
