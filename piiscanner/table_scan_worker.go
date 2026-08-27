package piiscanner

import (
	"context"
	"fmt"
	"sort"
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

		// A recognized physical column is a normal scalar field. Do not run its
		// value through loose key-value extraction: scalar formats such as MAC,
		// IPv6, and timestamps legitimately contain ':' and can look like key/value
		// text. Only unmatched/container columns enter document preprocessing.
		processedValue := data.Value
		var kvPairs []KeyValuePair
		if len(columnContext) == 0 {
			processedValue, kvPairs = PreprocessAndExtractKV(data.Value)
		}

		scanVal := processedValue
		if scanVal == "" {
			scanVal = data.Value
		}
		scanSegments := detectionSegments(scanVal, detectionChunkSize)

		for _, detector := range t.detectors {
			// Preserve candidate provenance until collisions for the same value have
			// been resolved. Structured values are scanned one extracted field at a
			// time; unstructured values are resolved by overlapping match positions.
			merged := make(map[PIILabel]PiiLabelWithWeight)
			if len(kvPairs) > 0 {
				for _, kv := range kvPairs {
					kvCtx := t.getColumnContext(ctx, kv.Key)
					labels, err := detectLogicalValue(ctx, detector, kv.Value, kvCtx)
					if err != nil {
						continue
					}
					for _, label := range labels {
						mergeCellLabel(merged, label)
					}
				}
			} else {
				for _, segment := range scanSegments {
					labels, err := detectLogicalValue(ctx, detector, segment, columnContext)
					if err != nil {
						return fmt.Errorf("error detecting pii data: from %s (%v)", detector.Name(), err)
					}
					for _, label := range labels {
						mergeCellLabel(merged, label)
					}
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

// detectLogicalValue resolves only candidates that refer to the same matched
// value. Non-overlapping matches are independent and are all retained.
func detectLogicalValue(ctx context.Context, detector Detector, value string, columnContext ColumnContext) ([]PiiLabelWithWeight, error) {
	labels, err := detector.Detect(ctx, value, columnContext)
	if err != nil {
		return nil, err
	}
	for index := range labels {
		if columnContext[labels[index].PIILabel] {
			labels[index].Weight = 1.0
			labels[index].ContextMatched = true
		}
	}
	return resolveOccurrenceConflicts(labels), nil
}

// resolveOccurrenceConflicts forms connected groups of overlapping match
// ranges. Each group represents one physical value and produces one winner.
// Candidates without position information remain unresolved for the existing
// column-level resolver.
func resolveOccurrenceConflicts(labels []PiiLabelWithWeight) []PiiLabelWithWeight {
	if len(labels) < 2 {
		if len(labels) == 1 && labels[0].HasMatchPosition {
			labels[0].ProvenanceResolved = true
		}
		return labels
	}

	positioned := make([]PiiLabelWithWeight, 0, len(labels))
	resolved := make([]PiiLabelWithWeight, 0, len(labels))
	for _, label := range labels {
		if label.HasMatchPosition && label.MatchEnd > label.MatchStart {
			positioned = append(positioned, label)
			continue
		}
		resolved = append(resolved, label)
	}

	sort.Slice(positioned, func(i, j int) bool {
		if positioned[i].MatchStart != positioned[j].MatchStart {
			return positioned[i].MatchStart < positioned[j].MatchStart
		}
		if positioned[i].MatchEnd != positioned[j].MatchEnd {
			return positioned[i].MatchEnd > positioned[j].MatchEnd
		}
		return positioned[i].PIILabel < positioned[j].PIILabel
	})

	for start := 0; start < len(positioned); {
		end := start + 1
		groupEnd := positioned[start].MatchEnd
		for end < len(positioned) && positioned[end].MatchStart < groupEnd {
			if positioned[end].MatchEnd > groupEnd {
				groupEnd = positioned[end].MatchEnd
			}
			end++
		}

		winner := positioned[start]
		for index := start + 1; index < end; index++ {
			if strongerOccurrenceCandidate(positioned[index], winner) {
				winner = positioned[index]
			}
		}
		winner.ProvenanceResolved = true
		resolved = append(resolved, winner)
		start = end
	}

	return resolved
}

func strongerOccurrenceCandidate(candidate, current PiiLabelWithWeight) bool {
	if candidate.ContextMatched != current.ContextMatched {
		return candidate.ContextMatched
	}
	candidateConfidence, _ := getConfidenceLabel(candidate.Weight)
	currentConfidence, _ := getConfidenceLabel(current.Weight)
	if confidenceRank(candidateConfidence) != confidenceRank(currentConfidence) {
		return confidenceRank(candidateConfidence) > confidenceRank(currentConfidence)
	}
	if TierRank(GetEntityTier(candidate.PIILabel)) != TierRank(GetEntityTier(current.PIILabel)) {
		return TierRank(GetEntityTier(candidate.PIILabel)) > TierRank(GetEntityTier(current.PIILabel))
	}
	if candidate.Weight != current.Weight {
		return candidate.Weight > current.Weight
	}
	return candidate.PIILabel < current.PIILabel
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
		label.ProvenanceResolved = label.ProvenanceResolved || existing.ProvenanceResolved
		merged[label.PIILabel] = label
		return
	}
	if label.ContextMatched && !existing.ContextMatched {
		existing.ContextMatched = true
	}
	existing.ProvenanceResolved = existing.ProvenanceResolved || label.ProvenanceResolved
	merged[label.PIILabel] = existing
}
