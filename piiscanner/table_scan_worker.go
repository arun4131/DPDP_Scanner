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

// getColumnContext returns the strongest label found in a column name or key.
// Results are cached because the same name always produces the same context.
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

	if strongest, found := strongestColumnMatch(labels); found {
		columnContext[strongest.PIILabel] = true
	}

	t.columnContextCacheMu.Lock()
	t.columnContextCache[column] = columnContext
	t.columnContextCacheMu.Unlock()

	return columnContext
}

func strongestColumnMatch(
	labels []PiiLabelWithWeight,
) (PiiLabelWithWeight, bool) {
	if len(labels) == 0 {
		return PiiLabelWithWeight{}, false
	}

	strongest := labels[0]

	for _, label := range labels[1:] {
		if label.Weight > strongest.Weight {
			strongest = label
			continue
		}

		if label.Weight == strongest.Weight &&
			label.PIILabel < strongest.PIILabel {
			strongest = label
		}
	}

	return strongest, true
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

		logicalFields, documentExtracted := buildLogicalFields(
			data.ColumnName,
			data.Value,
			len(columnContext) == 0,
		)

		isUnstructuredText := len(columnContext) == 0 && !documentExtracted

		for _, detector := range t.detectors {
			merged := make(map[PIILabel]PiiLabelWithWeight)

			for _, field := range logicalFields {
				fieldContext := t.getColumnContext(ctx, field.Key)
				segments := detectionSegments(field.Value, detectionChunkSize)

				for _, segment := range segments {
					labels, err := detectFieldValue(
						ctx,
						detector,
						segment,
						fieldContext,
						isUnstructuredText,
					)
					if err != nil {
						return fmt.Errorf(
							"error detecting PII in %s: %w",
							field.Key,
							err,
						)
					}

					for _, label := range labels {
						mergeStrongestLabel(merged, label)
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

func detectFieldValue(
	ctx context.Context,
	detector Detector,
	value string,
	columnContext ColumnContext,
	isUnstructuredText bool,
) ([]PiiLabelWithWeight, error) {
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

	if isUnstructuredText {
		return resolveOccurrenceConflicts(labels), nil
	}

	return resolveLogicalField(labels), nil
}

func detectLogicalValue(
	ctx context.Context,
	detector Detector,
	value string,
	columnContext ColumnContext,
) ([]PiiLabelWithWeight, error) {
	return detectFieldValue(
		ctx,
		detector,
		value,
		columnContext,
		false,
	)
}

func resolveLogicalField(
	labels []PiiLabelWithWeight,
) []PiiLabelWithWeight {
	if len(labels) == 0 {
		return nil
	}

	winner := labels[0]

	for _, label := range labels[1:] {
		if label.ContextMatched != winner.ContextMatched {
			if label.ContextMatched {
				winner = label
			}
			continue
		}

		if label.Weight > winner.Weight {
			winner = label
			continue
		}

		if label.Weight == winner.Weight &&
			label.PIILabel < winner.PIILabel {
			winner = label
		}
	}

	return []PiiLabelWithWeight{winner}
}

// resolveOccurrenceConflicts forms connected groups of overlapping match
// ranges. Each group represents one physical value and produces one winner.
// Candidates without position information remain unresolved for the existing
// column-level resolver.
func resolveOccurrenceConflicts(labels []PiiLabelWithWeight) []PiiLabelWithWeight {
	if len(labels) < 2 {
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
		resolved = append(resolved, winner)
		start = end
	}

	return resolved
}

func strongerOccurrenceCandidate(
	candidate PiiLabelWithWeight,
	current PiiLabelWithWeight,
) bool {
	if candidate.Weight != current.Weight {
		return candidate.Weight > current.Weight
	}

	// Keep the result stable when both weights are equal.
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

func mergeStrongestLabel(
	merged map[PIILabel]PiiLabelWithWeight,
	label PiiLabelWithWeight,
) {
	existing, found := merged[label.PIILabel]

	if !found || label.Weight > existing.Weight {
		label.ContextMatched =
			label.ContextMatched || existing.ContextMatched

		merged[label.PIILabel] = label
		return
	}

	if label.ContextMatched {
		existing.ContextMatched = true
	}

	merged[label.PIILabel] = existing
}
