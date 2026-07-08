package piiscanner

import (
	"context"
	"fmt"
	"strings"
)

type ScanInput struct {
	Tablename  string
	ColumnName string
	Value      string
}

type ScanOutput struct {
	Type string
	ScanInput
	Detector string
	Labels   []PiiLabelWithWeight
}

type TableScanWorker struct {
	inputChan  chan ScanInput
	outputChan chan ScanOutput

	detectors []Detector
}

func NewTableScanWorker(inputChan chan ScanInput, outputChan chan ScanOutput, detectors []Detector) *TableScanWorker {
	return &TableScanWorker{
		inputChan:  inputChan,
		outputChan: outputChan,
		detectors:  detectors,
	}
}

func (t *TableScanWorker) Start(ctx context.Context) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	for data := range t.inputChan {
		if data.Value == "" || data.Value == "<nil>" {
			continue
		}

		// detectorLoop:
		for _, detector := range t.detectors {
			hasColumnContext := false
			column := strings.ToLower(data.ColumnName)
			if strings.Contains(column, "driver") ||
				strings.Contains(column, "licence") ||
				strings.Contains(column, "license") ||
				strings.Contains(column, "dl") ||
				strings.Contains(column, "cif") ||
				strings.Contains(column, "account") ||
				strings.Contains(column, "cheque") ||
				strings.Contains(column, "micr") ||
				strings.Contains(column, "loan") ||
				strings.Contains(column, "insurance") ||
				strings.Contains(column, "policy") ||
				strings.Contains(column, "fastag") ||
				strings.Contains(column, "demat") ||
				strings.Contains(column, "cvv") ||
				strings.Contains(column, "card") {
				hasColumnContext = true
			}
			labels, err := detector.Detect(ctx, data.Value, hasColumnContext)
			if err != nil {
				return fmt.Errorf("error detecting pii data: from %s (%v)", detector.Name(), err)
			}

			// for _, v := range labels {
			// 	if v.Weight == 1.0 {
			// 		t.outputChan <- ScanOutput{
			// 			Type:      "value",
			// 			ScanInput: data,
			// 			Labels:    labels,
			// 		}
			// 		break detectorLoop
			// 	}

			t.outputChan <- ScanOutput{
				Type:      "value",
				ScanInput: data,
				Detector:  detector.Name(),
				Labels:    labels,
			}
		}
	}

	return nil
}
