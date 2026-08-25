package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
)

// getPythonProcessesRSS returns PID, RSS memory (in MB), and count for all spacy_runner.py processes.
func getPythonProcessesRSS() (int, float64, []string) {
	out, err := exec.Command("ps", "-eo", "pid,rss,command").Output()
	if err != nil {
		return 0, 0, nil
	}

	lines := strings.Split(string(out), "\n")
	var count int
	var totalRSS float64
	var details []string

	for _, line := range lines {
		if strings.Contains(line, "spacy_runner.py") && !strings.Contains(line, "ps -eo") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				pid := fields[0]
				rssKB, err := strconv.ParseFloat(fields[1], 64)
				if err == nil {
					rssMB := rssKB / 1024.0
					totalRSS += rssMB
					count++
					details = append(details, fmt.Sprintf("PID %s: %.2f MB", pid, rssMB))
				}
			}
		}
	}
	return count, totalRSS, details
}

// killAllSpacyProcesses kills any remaining spacy_runner.py processes to ensure a clean baseline.
func killAllSpacyProcesses() {
	_ = exec.Command("pkill", "-f", "spacy_runner.py").Run()
	time.Sleep(500 * time.Millisecond)
}

func testWorkerBatch(workerCount int, detectionsCount int) {
	fmt.Printf("\n======================================================\n")
	fmt.Printf("TEST BATCH: Workers = %d | Target Detections = %d\n", workerCount, detectionsCount)
	fmt.Printf("======================================================\n")

	// 1. Verify Clean Baseline
	procCount, totalRAM, _ := getPythonProcessesRSS()
	if procCount > 0 {
		fmt.Printf("Warning: Found %d lingering processes (%.2f MB). Cleaning up...\n", procCount, totalRAM)
		killAllSpacyProcesses()
		procCount, totalRAM, _ = getPythonProcessesRSS()
	}
	fmt.Printf("[STEP 1] Baseline Check: %d Python Processes, %.2f MB RAM\n", procCount, totalRAM)

	// 2. Initialize Single Shared SpaCy Detector with Fixed Process Pool (PoolSize = workerCount)
	detector := piiscanner.NewSpacyDetector().
		WithPoolSize(workerCount).
		WithWorkDirs([]string{
			"python",
			"../python",
			"../../python",
		})

	initStart := time.Now()
	if err := detector.Init(); err != nil {
		log.Fatalf("Initialization error: %v", err)
	}
	initDuration := time.Since(initStart)

	// Brief pause to allow memory pages to settle after parallel init
	time.Sleep(1 * time.Second)

	// 3. Measure RSS IMMEDIATELY after Model Load
	postInitCount, postInitRAM, postInitDetails := getPythonProcessesRSS()
	fmt.Printf("\n[STEP 2] After Model Load & Settling (Init time: %v):\n", initDuration)
	fmt.Printf("  - Active Python Processes : %d\n", postInitCount)
	fmt.Printf("  - Aggregate RSS RAM       : %.2f MB (%.2f GB)\n", postInitRAM, postInitRAM/1024.0)
	if postInitCount > 0 {
		fmt.Printf("  - Average RAM per Process : %.2f MB\n", postInitRAM/float64(postInitCount))
	}
	fmt.Println("  - Process Breakout:")
	for _, detail := range postInitDetails {
		fmt.Printf("      - %s\n", detail)
	}

	// 4. Run Detections (Heavy workload across workers to touch model memory)
	fmt.Printf("\n[STEP 3] Running %d Detection Queries across %d workers...\n", detectionsCount, workerCount)
	testWords := []string{
		"Rajesh Kumar", "Mumbai, Maharashtra", "Srinivas Rao", "Bengaluru, Karnataka",
		"Amit Patel", "Delhi, NCR", "Priya Sharma", "Hyderabad, Telangana",
	}

	queriesPerWorker := detectionsCount / workerCount
	infStart := time.Now()

	var infWg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		infWg.Add(1)
		go func(idx int) {
			defer infWg.Done()
			ctx := context.Background()
			colCtx := piiscanner.ColumnContext{piiscanner.PIILabel_Name: true}

			for q := 0; q < queriesPerWorker; q++ {
				word := testWords[q%len(testWords)]
				_, _ = detector.Detect(ctx, word, colCtx)
			}
		}(i)
	}
	infWg.Wait()
	infDuration := time.Since(infStart)

	// 5. Measure RSS AFTER Detections
	postInfCount, postInfRAM, postInfDetails := getPythonProcessesRSS()
	fmt.Printf("\n[STEP 4] After %d Detections (Inference time: %v):\n", detectionsCount, infDuration)
	fmt.Printf("  - Active Python Processes : %d\n", postInfCount)
	fmt.Printf("  - Aggregate RSS RAM       : %.2f MB (%.2f GB)\n", postInfRAM, postInfRAM/1024.0)
	if postInfCount > 0 {
		fmt.Printf("  - Average RAM per Process : %.2f MB\n", postInfRAM/float64(postInfCount))
	}
	fmt.Printf("  - RAM Growth Delta        : +%.2f MB (%.2f%% increase)\n",
		postInfRAM-postInitRAM, ((postInfRAM-postInitRAM)/postInitRAM)*100.0)
	fmt.Println("  - Process Breakout:")
	for _, detail := range postInfDetails {
		fmt.Printf("      - %s\n", detail)
	}

	// 6. Stop All Workers & Verify Clean 0 via detector.Close()
	fmt.Printf("\n[STEP 5] Terminating workers & verifying clean shutdown via detector.Close()...\n")
	_ = detector.Close()
	time.Sleep(500 * time.Millisecond)

	cleanCount, cleanRAM, _ := getPythonProcessesRSS()
	fmt.Printf("  - Verified Post-Shutdown Processes: %d | RAM: %.2f MB\n", cleanCount, cleanRAM)
}

func main() {
	fmt.Println("========================================================")
	fmt.Println("=== CONTROLLED SPACY MEMORY & LIFETIME BENCHMARK ===")
	fmt.Println("========================================================")

	// Clean slate before starting
	killAllSpacyProcesses()

	// Test 1 Worker with 2,000 detections
	testWorkerBatch(1, 2000)

	// Test 4 Workers with 2,000 detections
	testWorkerBatch(4, 2000)

	// Test 8 Workers with 2,000 detections
	testWorkerBatch(8, 2000)

	// Test 10 Workers with 2,000 detections
	testWorkerBatch(10, 2000)
}
