package piiscanner

// HOW SPACY DETECTOR WORKS
// SpacyDetector is a detector which uses spacy to detect PIILabels
// for columns and values.
//
// Spacy detector executes a python script which uses spacy to detect
// PIILabels for columns and values.
// Python is located in python/spacy_runner.py
//
// POOL SUPPORT & LAZY CONCURRENCY
// spacyDetector manages a fixed-size pool of Python processes via WithPoolSize(n).
// Instead of one Python process per worker (N × 763 MB RAM), a single shared
// pool of n processes (default 4) is created. All workers share this instance.
// Subprocesses are spawned lazily on the first actual value detection request in Detect(),
// ensuring zero Python processes or RAM overhead for zero-row or excluded tables.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"

	cmdprocessor "github.com/klouddb/dpdpa_pii_db_scanner/pkg/cmd_processor"
)

type pythonResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Data    *Data  `json:"data"`
}

type Data struct {
	Text     string   `json:"text"`
	Entities []Entity `json:"entities"`
}

type Entity struct {
	Text  string `json:"text"`
	Label string `json:"label"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

const spacyFileName = "spacy_runner.py"
const defaultSpacyPoolSize = 4

type spacyDetector struct {
	workDirs      []string
	poolSize      int
	processors    chan *cmdprocessor.CmdProcessor
	allProcessors []*cmdprocessor.CmdProcessor
	initMu        sync.Mutex
	isInit        bool
	pythonPath    string
	scriptPath    string
}

func NewSpacyDetector() *spacyDetector {
	return &spacyDetector{
		poolSize: defaultSpacyPoolSize,
	}
}

func (u *spacyDetector) Name() string {
	return "spacy"
}

func (u *spacyDetector) WithWorkDirs(workDirs []string) *spacyDetector {
	u.workDirs = workDirs
	return u
}

func (u *spacyDetector) WithPoolSize(n int) *spacyDetector {
	if n < 1 {
		n = 1
	}
	u.poolSize = n
	return u
}

// createSingleProcessor spawns and initializes one CmdProcessor instance.
func (u *spacyDetector) createSingleProcessor(ctx context.Context) (*cmdprocessor.CmdProcessor, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cp := cmdprocessor.NewCmdProcessor(u.pythonPath, u.scriptPath)

	cp.SetSkipMethod(func(s string) (bool, error) {
		var out pythonResponse
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return false, fmt.Errorf("unmarshal output (%s) in skip method from python script: %w", s, err)
		}
		switch out.Type {
		case "log":
			return true, nil
		case "error":
			return true, fmt.Errorf("error from python script: %s", out.Message)
		case "output":
			return false, nil
		}
		return true, nil
	})

	cp.SetWaitMethod(func(s string) (bool, error) {
		var out pythonResponse
		if err := json.Unmarshal([]byte(s), &out); err != nil {
			return false, fmt.Errorf("unmarshal output (%s) in wait method from python script: %w", s, err)
		}
		switch out.Type {
		case "log":
			return out.Message != "Successfully loaded model", nil
		case "error":
			return false, fmt.Errorf("python script did not start: %s", out.Message)
		case "output":
			return false, fmt.Errorf("in wait mode we should not get output")
		}
		return true, nil
	})

	if err := cp.Start(ctx); err != nil {
		return nil, fmt.Errorf("start python script: %w", err)
	}

	return cp, nil
}

// Init satisfies the Detector interface. It prepares paths without eagerly spawning Python processes.
func (u *spacyDetector) Init() error {
	u.initMu.Lock()
	defer u.initMu.Unlock()

	python3, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python 3 not found: %w", err)
	}
	u.pythonPath = python3

	fileLocation, err := u.detectWorkingDir()
	if err != nil {
		return err
	}
	u.scriptPath = path.Join(fileLocation, spacyFileName)

	return nil
}

// ensurePoolStarted lazily spawns the Python process pool on the first value detection request.
func (u *spacyDetector) ensurePoolStarted(ctx context.Context) error {
	u.initMu.Lock()
	defer u.initMu.Unlock()

	if u.isInit {
		return nil
	}

	if u.pythonPath == "" || u.scriptPath == "" {
		python3, err := exec.LookPath("python3")
		if err != nil {
			return fmt.Errorf("python 3 not found: %w", err)
		}
		u.pythonPath = python3

		fileLocation, err := u.detectWorkingDir()
		if err != nil {
			return err
		}
		u.scriptPath = path.Join(fileLocation, spacyFileName)
	}

	u.processors = make(chan *cmdprocessor.CmdProcessor, u.poolSize)
	u.allProcessors = make([]*cmdprocessor.CmdProcessor, 0, u.poolSize)

	type result struct {
		cp  *cmdprocessor.CmdProcessor
		err error
	}
	results := make(chan result, u.poolSize)

	for i := 0; i < u.poolSize; i++ {
		go func() {
			cp, err := u.createSingleProcessor(ctx)
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{cp: cp}
		}()
	}

	started := make([]*cmdprocessor.CmdProcessor, 0, u.poolSize)
	var firstErr error

	for i := 0; i < u.poolSize; i++ {
		r := <-results
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
		} else {
			started = append(started, r.cp)
		}
	}

	if firstErr != nil {
		for _, cp := range started {
			if cp != nil {
				_ = cp.Close()
			}
		}
		close(u.processors)
		u.processors = nil
		return fmt.Errorf("failed to initialize spacy pool: %w", firstErr)
	}

	for _, cp := range started {
		u.processors <- cp
		u.allProcessors = append(u.allProcessors, cp)
	}

	u.isInit = true
	return nil
}

// Close gracefully terminates all Python child processes in the pool.
func (u *spacyDetector) Close() error {
	u.initMu.Lock()
	defer u.initMu.Unlock()

	if !u.isInit {
		return nil
	}

	for _, cp := range u.allProcessors {
		if cp != nil {
			_ = cp.Close()
		}
	}

	if u.processors != nil {
		close(u.processors)
		u.processors = nil
	}
	u.allProcessors = nil
	u.isInit = false
	return nil
}

func (u *spacyDetector) detectWorkingDir() (string, error) {
	for _, w := range u.workDirs {
		if _, err := os.Stat(filepath.Join(w, spacyFileName)); err != nil {
			continue
		}
		return w, nil
	}

	return "", fmt.Errorf("spacy file not found in any location %s", strings.Join(u.workDirs, ","))
}

func (u *spacyDetector) Detect(ctx context.Context, word string, columnContext ColumnContext) ([]PiiLabelWithWeight, error) {
	if columnContext != nil {
		if !columnContext[PIILabel_Name] && !columnContext[PIILabel_Address] {
			return nil, nil
		}
	}

	// Lazily spawn Python subprocesses on the first actual value detection call
	if err := u.ensurePoolStarted(ctx); err != nil {
		return nil, fmt.Errorf("spacy detector pool start failed: %w", err)
	}

	u.initMu.Lock()
	if !u.isInit || u.processors == nil {
		u.initMu.Unlock()
		return nil, fmt.Errorf("spacy detector not initialized")
	}
	procChan := u.processors
	u.initMu.Unlock()

	var cp *cmdprocessor.CmdProcessor
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case cp = <-procChan:
		if cp == nil {
			return nil, fmt.Errorf("acquired nil processor")
		}
	}

	// Replace newlines with space to prevent PTY line protocol desynchronization
	sanitizedWord := strings.ReplaceAll(strings.ReplaceAll(word, "\r", " "), "\n", " ")

	out, err := cp.ProcessContext(ctx, sanitizedWord)
	if err != nil {
		// Process failed — close dead processor and attempt to replace it so pool stays healthy
		_ = cp.Close()

		if replacement, repErr := u.createSingleProcessor(ctx); repErr == nil {
			u.initMu.Lock()
			if u.isInit && u.processors != nil {
				for i, existing := range u.allProcessors {
					if existing == cp {
						u.allProcessors[i] = replacement
						break
					}
				}
				select {
				case u.processors <- replacement:
				default:
				}
			} else {
				_ = replacement.Close()
			}
			u.initMu.Unlock()
		}

		return nil, fmt.Errorf("failed to process input: %w", err)
	}

	// Success — safely return processor back to pool channel
	defer func() {
		u.initMu.Lock()
		defer u.initMu.Unlock()
		if u.isInit && u.processors != nil {
			select {
			case u.processors <- cp:
			default:
			}
		}
	}()

	var resp pythonResponse
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %v", err)
	}

	if resp.Data == nil || len(resp.Data.Entities) == 0 {
		return nil, nil
	}

	var labels []PiiLabelWithWeight
	for _, entity := range resp.Data.Entities {
		switch entity.Label {
		case "PERSON":
			labels = append(labels, PiiLabelWithWeight{
				PIILabel:         PIILabel_Name,
				Weight:           0.7,
				MatchStart:       entity.Start,
				MatchEnd:         entity.End,
				HasMatchPosition: entity.End > entity.Start,
			})
		case "GPE":
			labels = append(labels, PiiLabelWithWeight{
				PIILabel:         PIILabel_Address,
				Weight:           0.7,
				MatchStart:       entity.Start,
				MatchEnd:         entity.End,
				HasMatchPosition: entity.End > entity.Start,
			})
		}
	}

	return labels, nil
}
