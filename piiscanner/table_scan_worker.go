package piiscanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
)

const detectionChunkSize = 512

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

	detectors      []Detector
	columnDetector Detector

	// cache column context results — same column name always gives same result
	columnContextCache   map[string]ColumnContext
	columnContextCacheMu sync.RWMutex
}

func NewTableScanWorker(inputChan chan ScanInput, outputChan chan ScanOutput, detectors []Detector) *TableScanWorker {
	return &TableScanWorker{
		inputChan:          inputChan,
		outputChan:         outputChan,
		detectors:          detectors,
		columnContextCache: make(map[string]ColumnContext),
	}
}

// WithColumnDetector sets the column detector used to determine hasColumnContext.
// If not set, hasColumnContext is always false.
func (t *TableScanWorker) WithColumnDetector(d Detector) *TableScanWorker {
	t.columnDetector = d
	return t
}

// getColumnContext checks if the column name matches any column detector pattern.
// Results are cached so the regex only runs once per unique column name.
func (t *TableScanWorker) getColumnContext(ctx context.Context, column string) ColumnContext {
	columnContext := make(ColumnContext)

	if t.columnDetector == nil {
		return columnContext
	}

	t.columnContextCacheMu.RLock()
	if cached, ok := t.columnContextCache[column]; ok {
		t.columnContextCacheMu.RUnlock()
		return cached
	}
	t.columnContextCacheMu.RUnlock()

	labels, err := t.columnDetector.Detect(ctx, column, nil)
	if err != nil {
		return columnContext
	}

	for _, label := range labels {
		columnContext[label.PIILabel] = true
	}

	t.columnContextCacheMu.Lock()
	t.columnContextCache[column] = columnContext
	t.columnContextCacheMu.Unlock()

	return columnContext
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

		// Determine column context once per column name using column detector
		columnContext := t.getColumnContext(ctx, data.ColumnName)

		// Preprocess value (URL/Base64 decode) and extract internal key-value pairs
		processedValue, kvPairs := PreprocessAndExtractKV(data.Value)

		// Merge internal key context if KV pairs exist (e.g. "account", "ifsc", "pan", "aadhaar")
		if len(kvPairs) > 0 {
			mergedContext := make(ColumnContext)
			for label, enabled := range columnContext {
				mergedContext[label] = enabled
			}
			for _, kv := range kvPairs {
				internalCtx := t.getColumnContext(ctx, kv.Key)
				for label, enabled := range internalCtx {
					if enabled {
						mergedContext[label] = true
					}
				}
			}
			columnContext = mergedContext
		}

		scanVal := processedValue
		if scanVal == "" {
			scanVal = data.Value
		}
		scanSegments := detectionSegments(scanVal, detectionChunkSize)

		for _, detector := range t.detectors {
			// Merge labels across every raw-text segment and extracted KV value. The
			// map lives for the complete database cell, so an entity is counted at
			// most once even when it occurs in several chunks.
			merged := make(map[PIILabel]PiiLabelWithWeight)
			for _, segment := range scanSegments {
				rawLabels, err := detector.Detect(ctx, segment, columnContext)
				if err != nil {
					return fmt.Errorf("error detecting pii data: from %s (%v)", detector.Name(), err)
				}
				for _, lbl := range rawLabels {
					lbl.ContextMatched = columnContext[lbl.PIILabel]
					mergeCellLabel(merged, lbl)
				}
			}

			for _, kv := range kvPairs {
				kvCtx := t.getColumnContext(ctx, kv.Key)
				kvLabels, err := detector.Detect(ctx, kv.Value, kvCtx)
				if err != nil {
					continue
				}
				for _, lbl := range kvLabels {
					if kvCtx[lbl.PIILabel] {
						lbl.Weight = 1.0
						lbl.ContextMatched = true
					}
					mergeCellLabel(merged, lbl)
				}
			}

			// Flatten deduplicated map back to slice
			finalLabels := make([]PiiLabelWithWeight, 0, len(merged))
			for _, lbl := range merged {
				finalLabels = append(finalLabels, lbl)
			}

			// Emit a single ScanOutput per row — count is now accurate (1 match per row per label)
			t.outputChan <- ScanOutput{
				Type:      "value",
				ScanInput: data,
				Detector:  detector.Name(),
				Labels:    finalLabels,
			}
		}
	}

	return nil
}

// detectionSegments limits only raw detector input. Structured extraction has
// already consumed the complete cell before this function is called.
func detectionSegments(value string, maxSize int) []string {
	if value == "" {
		return nil
	}
	if len(value) < maxSize {
		return []string{value}
	}

	chunks := utils.Chunks(value, maxSize)
	segments := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		if chunk != "" {
			segments = append(segments, chunk)
		}
	}
	if len(segments) == 0 {
		return []string{value}
	}
	return segments
}

func mergeCellLabel(merged map[PIILabel]PiiLabelWithWeight, label PiiLabelWithWeight) {
	existing, found := merged[label.PIILabel]
	if !found || label.Weight > existing.Weight {
		// Do not lose trusted provenance carried by a lower-weight occurrence.
		label.ContextMatched = label.ContextMatched || existing.ContextMatched
		merged[label.PIILabel] = label
		return
	}
	if label.ContextMatched && !existing.ContextMatched {
		existing.ContextMatched = true
		merged[label.PIILabel] = existing
	}
}
