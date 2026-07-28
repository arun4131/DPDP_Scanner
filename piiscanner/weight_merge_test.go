package piiscanner

import (
	"testing"
)

// buildScanner constructs a databasePiiScanner with pre-populated
// TableScanManager output — no real DB needed.
//
//   table:      table name
//   column:     column name
//   colWeight:  weight the column regex gave (simulates column name match)
//   matchCount: how many values matched the value regex
//   totalRows:  total values scanned
//   perHitWeight: weight per value regex hit (e.g. 0.6 for BankAccountNumber)
func buildScanner(table, column string, label PIILabel, colWeight float64, matchCount, totalRows int, perHitWeight float64) *databasePiiScanner {
	tsm := &TableScanManager{
		outputChan: make(chan ScanOutput),
		valueCount: map[string]map[string]int{
			table: {column: totalRows},
		},
		output: map[string]TableScannerOutput{
			table: {
				TableName: table,
				PiiDataMap: map[string]PiiData{
					column: {
						// Column detector result
						ColumnMap: PiiLabelMap{
							"regex": {
								label: WeightWithCount{Weight: colWeight, Count: 1},
							},
						},
						// Value detector result: matchCount hits × perHitWeight
						ValueMap: PiiLabelMap{
							"regex": {
								label: WeightWithCount{
									Weight: float64(matchCount) * perHitWeight,
									Count:  matchCount,
								},
							},
						},
					},
				},
			},
		},
	}

	cnf := &Config{
		runOption: RunOption_DataScan,
		Database:  "testdb",
		Schema:    "public",
	}

	return &databasePiiScanner{
		tableScanManager: tsm,
		cnf:              cnf,
	}
}

// TestWeightMerge_LowMatchRate — 1 out of 10000 rows matched.
// With the old bug: finalWeight = (1.0+1.0)/2 = 1.0 → High ❌
// With the fix:     finalWeight = (1.0+0.00006)/2 ≈ 0.50 → Medium ✅
func TestWeightMerge_LowMatchRate(t *testing.T) {
	scanner := buildScanner(
		"public.transactions", "bank_account_number",
		PIILabel_BankAccountNumber,
		1.0,   // column weight — "bank_account_number" matched perfectly
		1,     // only 1 value matched
		10000, // out of 10000 rows
		0.6,   // BankAccountNumber value regex weight
	)

	output, err := scanner.GetResults()
	if err != nil {
		t.Fatalf("GetResults error: %v", err)
	}

	findings := output.Data["public.transactions"]["bank_account_number"]
	var valueFindings []PIIDataWithWeightString
	for _, f := range findings {
		if f.DetectorType == DetectorType_ValueDetector {
			valueFindings = append(valueFindings, f)
		}
	}

	if len(valueFindings) == 0 {
		t.Fatal("expected value detector findings, got none")
	}

	f := valueFindings[0]
	t.Logf("1/10000 match → weight=%.5f confidence=%s", f.Weight, f.Confidence)

	if f.Confidence == "High" {
		t.Errorf("BUG STILL EXISTS: 1/10000 match reported as High (weight=%.4f). Expected Medium or Low.", f.Weight)
	}
}

// TestWeightMerge_HighMatchRate — 90 out of 100 rows matched.
// Both old and new: finalWeight = (1.0+0.54)/2 = 0.77 → High ✅
func TestWeightMerge_HighMatchRate(t *testing.T) {
	scanner := buildScanner(
		"public.transactions", "bank_account_number",
		PIILabel_BankAccountNumber,
		1.0, // column weight
		90,  // 90 values matched
		100, // out of 100 rows
		0.6, // per hit weight
	)

	output, err := scanner.GetResults()
	if err != nil {
		t.Fatalf("GetResults error: %v", err)
	}

	findings := output.Data["public.transactions"]["bank_account_number"]
	var valueFindings []PIIDataWithWeightString
	for _, f := range findings {
		if f.DetectorType == DetectorType_ValueDetector {
			valueFindings = append(valueFindings, f)
		}
	}

	if len(valueFindings) == 0 {
		t.Fatal("expected value detector findings, got none")
	}

	f := valueFindings[0]
	t.Logf("90/100 match → weight=%.5f confidence=%s", f.Weight, f.Confidence)

	if f.Confidence != "High" {
		t.Errorf("expected High confidence for 90/100 match, got %s (weight=%.4f)", f.Confidence, f.Weight)
	}
}

// TestWeightMerge_WeakColumnLowMatch — column weight is 0.5, only 5/100 matched.
// Old bug: finalWeight = (0.5+1.0)/2 = 0.75 → High ❌
// Fix:     finalWeight = (0.5+0.03)/2 = 0.265 → Low ✅
func TestWeightMerge_WeakColumnLowMatch(t *testing.T) {
	scanner := buildScanner(
		"public.payments", "acct_ref",
		PIILabel_BankAccountNumber,
		0.5, // medium column weight — "acct_ref" partially matched
		5,   // only 5 values matched
		100, // out of 100 rows
		0.6,
	)

	output, err := scanner.GetResults()
	if err != nil {
		t.Fatalf("GetResults error: %v", err)
	}

	findings := output.Data["public.payments"]["acct_ref"]
	var valueFindings []PIIDataWithWeightString
	for _, f := range findings {
		if f.DetectorType == DetectorType_ValueDetector {
			valueFindings = append(valueFindings, f)
		}
	}

	if len(valueFindings) == 0 {
		t.Fatal("expected value detector findings, got none")
	}

	f := valueFindings[0]
	t.Logf("5/100 match, colWeight=0.5 → weight=%.5f confidence=%s", f.Weight, f.Confidence)

	if f.Confidence == "High" {
		t.Errorf("BUG STILL EXISTS: 5/100 match with medium column weight reported as High (weight=%.4f)", f.Weight)
	}
}

// TestWeightMerge_NoColumnMatch — column "xyz" gave 0 weight, 50/100 values matched.
// finalWeight = (0 + 0.30)/2 — but colWeight < 0.4, so no merge.
// finalWeight = 0.30 → Low
func TestWeightMerge_NoColumnMatch(t *testing.T) {
	scanner := buildScanner(
		"public.misc", "xyz",
		PIILabel_BankAccountNumber,
		0.0, // column gave no signal
		50,  // 50 values matched
		100,
		0.6,
	)

	output, err := scanner.GetResults()
	if err != nil {
		t.Fatalf("GetResults error: %v", err)
	}

	findings := output.Data["public.misc"]["xyz"]
	var valueFindings []PIIDataWithWeightString
	for _, f := range findings {
		if f.DetectorType == DetectorType_ValueDetector {
			valueFindings = append(valueFindings, f)
		}
	}

	if len(valueFindings) == 0 {
		t.Fatal("expected value detector findings, got none")
	}

	f := valueFindings[0]
	t.Logf("50/100 match, colWeight=0.0 → weight=%.5f confidence=%s", f.Weight, f.Confidence)

	// colWeight 0.0 < 0.4, so merge logic doesn't fire.
	// finalWeight = 50 * 0.6 / 100 = 0.30 → Low
	if f.Confidence != "Low" {
		t.Errorf("expected Low confidence when column gave no signal, got %s (weight=%.4f)", f.Confidence, f.Weight)
	}
}
