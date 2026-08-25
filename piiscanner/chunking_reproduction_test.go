package piiscanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

// containsTokenDetector is deliberately simple: it lets this reproduction
// isolate the scanner's chunk accounting without depending on a PII regex.
type containsTokenDetector struct{}

func (containsTokenDetector) Name() string { return "chunk-reproduction" }
func (containsTokenDetector) Init() error  { return nil }
func (containsTokenDetector) Detect(_ context.Context, value string, _ ColumnContext) ([]PiiLabelWithWeight, error) {
	if strings.Contains(value, "REPRO_TOKEN") {
		return []PiiLabelWithWeight{{PIILabel: PIILabel_Phone, Weight: 1.0}}, nil
	}
	return nil, nil
}

type noMatchColumnDetector struct{}

func (noMatchColumnDetector) Name() string { return "no-column-match" }
func (noMatchColumnDetector) Init() error  { return nil }
func (noMatchColumnDetector) Detect(context.Context, string, ColumnContext) ([]PiiLabelWithWeight, error) {
	return nil, nil
}

func TestChunkedCellCountsEntityOnce(t *testing.T) {
	ctx := context.Background()
	manager := NewTableScanManager().
		WithColumnDetector(noMatchColumnDetector{}).
		WithDetectorFactory(func() []Detector {
			return []Detector{containsTokenDetector{}}
		})

	if err := manager.Start(ctx, 1); err != nil {
		t.Fatalf("start manager: %v", err)
	}

	// This is one database cell, but it is longer than 512 bytes and contains
	// the same entity marker in two different chunks.
	value := "REPRO_TOKEN " + strings.Repeat("ordinary_word ", 80) + "REPRO_TOKEN"
	chunks := detectionSegments(value, detectionChunkSize)
	for index, chunk := range chunks {
		t.Logf("input chunk %d: bytes=%d containsToken=%t", index+1, len(chunk), strings.Contains(chunk, "REPRO_TOKEN"))
	}
	if err := manager.PushValue(ScanInput{
		Tablename:  "reproduction_table",
		ColumnName: "payload",
		Value:      value,
	}); err != nil {
		t.Fatalf("push value: %v", err)
	}

	output, err := manager.Output()
	if err != nil {
		t.Fatalf("get output: %v", err)
	}

	result := output["reproduction_table"].PiiDataMap["payload"].ValueMap["chunk-reproduction"][PIILabel_Phone]
	scannedValues := manager.valueCount["reproduction_table"]["payload"]

	t.Logf("one original cell became: matchedCount=%d scannedValueCount=%d accumulatedWeight=%.1f",
		result.Count, scannedValues, result.Weight)

	if result.Count != 1 {
		t.Fatalf("one original cell was counted %d times after chunking", result.Count)
	}
	if result.Weight > 1.0 {
		t.Fatalf("one original cell accumulated impossible weight %.1f", result.Weight)
	}
}

func TestLongStructuredCellsAreParsedBeforeChunking(t *testing.T) {
	longJSON := `{"padding":"` + strings.Repeat("ordinary words ", 45) + `", "cvv":"312"}`
	longXML := `<root><padding>` + strings.Repeat("ordinary words ", 45) + `</padding><cvv>312</cvv></root>`
	longQuery := `padding=` + strings.Repeat("x", 650) + `&cvv=312`
	base64JSON := `{"padding":"` + strings.Repeat("x", 650) + `","cvv":"312"}`
	longBase64 := wrapAt(base64.StdEncoding.EncodeToString([]byte(base64JSON)), 76)

	values := map[string]string{
		"long_json":   longJSON,
		"long_xml":    longXML,
		"long_query":  longQuery,
		"long_base64": longBase64,
	}
	ctx := context.Background()
	manager := NewTableScanManager().
		WithColumnDetector(NewRegexColumnDetector()).
		WithDetectorFactory(func() []Detector {
			return []Detector{NewRegexValueDetector()}
		})
	if err := manager.Start(ctx, 1); err != nil {
		t.Fatalf("start manager: %v", err)
	}
	for column, value := range values {
		if len(value) <= detectionChunkSize {
			t.Fatalf("invalid %s fixture: length=%d", column, len(value))
		}
		if err := manager.PushValue(ScanInput{
			Tablename:  "structured_reproduction",
			ColumnName: column,
			Value:      value,
		}); err != nil {
			t.Fatalf("push %s: %v", column, err)
		}
	}

	output, err := manager.Output()
	if err != nil {
		t.Fatalf("get output: %v", err)
	}
	for column := range values {
		result := output["structured_reproduction"].PiiDataMap[column].ValueMap["regex"][PIILabel_CVV]
		if result.Count != 1 {
			t.Errorf("%s CVV match count=%d, want 1", column, result.Count)
		}
		if !result.ContextMatched {
			t.Errorf("%s lost embedded-key context", column)
		}
		if result.Weight != 1.0 {
			t.Errorf("%s weight=%v, want 1.0", column, result.Weight)
		}
	}
}

func wrapAt(value string, width int) string {
	var out strings.Builder
	for len(value) > width {
		out.WriteString(value[:width])
		out.WriteByte('\n')
		value = value[width:]
	}
	out.WriteString(value)
	return out.String()
}
