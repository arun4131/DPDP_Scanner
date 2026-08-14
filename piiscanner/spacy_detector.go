package piiscanner

// HOW SPACY DETECTOR WORKS
// SpacyDetector is a detector which uses spacy to detect PIILabels
// for columns and values.
//
// Spacy detector executes a python script which uses spacy to detect
// PIILabels for columns and values.
// Python is located in python/spacy_runner.py
//
// POOL SUPPORT & CONCURRENCY
// spacyDetector manages a fixed-size pool of Python processes via WithPoolSize(n).
// Instead of one Python process per worker (N × 763 MB RAM), a single shared
// pool of n processes (default 4) is created. All workers share this instance.
// The buffered channel acts as a semaphore so at most n spaCy calls run concurrently.
// Extras block until a slot frees up.
// Init() is thread-safe and idempotent — calling it multiple times (e.g. from multiple
// workers) only initializes the pool once.

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
}

const spacyFileName = "spacy_runner.py"
const defaultSpacyPoolSize = 4

type spacyDetector struct {
	workDirs   []string
	poolSize   int
	processors chan *cmdprocessor.CmdProcessor
	initMu     sync.Mutex
	isInit     bool
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

// Init initializes the spacyDetector process pool.
// Idempotent and thread-safe: if called multiple times, only the first call creates the pool.
func (u *spacyDetector) Init() error {
	u.initMu.Lock()
	defer u.initMu.Unlock()

	if u.isInit {
		return nil
	}

	python3, err := exec.LookPath("python3")
	if err != nil {
		return fmt.Errorf("python 3 not found: %w", err)
	}

	fileLocation, err := u.detectWorkingDir()
	if err != nil {
		return err
	}

	scriptPath := path.Join(fileLocation, spacyFileName)
	u.processors = make(chan *cmdprocessor.CmdProcessor, u.poolSize)

	type result struct {
		cp  *cmdprocessor.CmdProcessor
		err error
	}
	results := make(chan result, u.poolSize)

	for i := 0; i < u.poolSize; i++ {
		go func() {
			cp := cmdprocessor.NewCmdProcessor(python3, scriptPath)

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

			if err := cp.Start(context.TODO()); err != nil {
				results <- result{err: fmt.Errorf("start python script: %w", err)}
				return
			}
			results <- result{cp: cp}
		}()
	}

	for i := 0; i < u.poolSize; i++ {
		r := <-results
		if r.err != nil {
			return r.err
		}
		u.processors <- r.cp
	}

	u.isInit = true
	return nil
}

// Close gracefully terminates all Python child processes in the pool.
func (u *spacyDetector) Close() error {
	u.initMu.Lock()
	defer u.initMu.Unlock()

	if !u.isInit || u.processors == nil {
		return nil
	}

	for i := 0; i < u.poolSize; i++ {
		select {
		case cp := <-u.processors:
			if cp != nil {
				cp.Close()
			}
		default:
		}
	}

	close(u.processors)
	u.processors = nil
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

	if u.processors == nil {
		return nil, fmt.Errorf("spacy detector not initialized")
	}

	cp := <-u.processors
	defer func() { u.processors <- cp }()

	out, err := cp.Process(word)
	if err != nil {
		return nil, fmt.Errorf("failed to process input: %v", err)
	}

	var resp pythonResponse
	err = json.Unmarshal([]byte(out), &resp)
	if err != nil {
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
				PIILabel: PIILabel_Name,
				Weight:   0.7,
			})
		case "GPE":
			labels = append(labels, PiiLabelWithWeight{
				PIILabel: PIILabel_Address,
				Weight:   0.7,
			})
		}
	}

	return labels, nil
}
