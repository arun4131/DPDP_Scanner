package piiscanner

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/utils"
	"github.com/schollz/progressbar/v3"
)

var yesToAll bool

type Config struct {
	runOption RunOption
	// AutoDetect is true when the caller didn't request a fixed scan mode
	// (--piiscanner was left empty). When true, runOption is RunOption_Unset
	// and the real per-table mode (DataScan vs DeepScan) is picked later, in
	// piiTableScanner.processTable, based on that table's row count.
	AutoDetect bool

	useSpacy     bool
	excludeTable utils.Set[string]
	includeTable []string

	Database string
	Schema   string

	printAllResults  bool
	spacyOnly        bool
	PrintSummaryOnly bool
}

func NewConfig(runOption, excludeTable, includeTable, database, schema string, printAllResults, spacyOnly, printSummaryOnly bool) (*Config, error) {
	
	if printAllResults && printSummaryOnly {
		return nil, fmt.Errorf("--print-all and --print-summary are not allowed together")
	}

	if database == "" {
		return nil, errors.New("database name is required")
	}


	var useSpacy bool
	if runOption == RunOption_SpacyScan_String {
		useSpacy = true
		runOption = RunOption_DataScan_String
		printAllResults = true
	}

	if spacyOnly {
		// incase of spacy only we will run data scan only and that also with spacy
		// so if there run option is available then it will create confusion for users
		// that which part is getting priority from run option and spacy only.
		// so in that case we will return error
		if runOption != "" {
			return nil, fmt.Errorf("run option is not allowed with spacy only")
		}

		runOption = RunOption_DataScan_String
		useSpacy = true

		// incase of only spacy we will get all results with 0.3 confidence value
		// default terminal output prints only results with High confidence value which is > 0.7
		// so in case of spacy only we will print all results
		printAllResults = true
	}

	autoDetect := runOption == ""

	r := RunOption_Unset
	if !autoDetect {
		var ok bool
		r, ok = RunOptionMap[runOption]
		if !ok {
			return nil, fmt.Errorf("invalid run option %s, valid options are %s", runOption, strings.Join(RunOptionSlice(), ", "))
		}
	}

	out := &Config{
		runOption:        r,
		AutoDetect:       autoDetect,
		useSpacy:         useSpacy,
		Database:         database,
		Schema:           schema,
		printAllResults:  printAllResults,
		spacyOnly:        spacyOnly,
		PrintSummaryOnly: printSummaryOnly,
	}

	if excludeTable != "" {
		out.excludeTable = utils.NewSetFromSlice(utils.TrimSpaceArray(strings.Split(excludeTable, ",")))
	}

	if includeTable != "" {
		out.includeTable = utils.TrimSpaceArray(strings.Split(includeTable, ","))
	}

	return out, nil
}

type databasePiiScanner struct {
	adapter          DBAdapter
	tableScanManager *TableScanManager

	numOfRunners int
	cnf          *Config
	spinner      *scanningSpinner

	spacyMu  sync.Mutex
	spacyDet *spacyDetector
}

func NewDatabasePiiScanner(adapter DBAdapter, cnf *Config) *databasePiiScanner {
	return &databasePiiScanner{
		adapter:      adapter,
		numOfRunners: runtime.NumCPU(),
		cnf:          cnf,
	}
}

func (d *databasePiiScanner) Close() {
	if d.spinner != nil {
		d.spinner.Stop()
	}
	d.spacyMu.Lock()
	if d.spacyDet != nil {
		_ = d.spacyDet.Close()
	}
	d.spacyMu.Unlock()
}

func (d *databasePiiScanner) pauseSpinner() {
	if d.spinner != nil {
		d.spinner.Pause()
	}
}

func (d *databasePiiScanner) resumeSpinner() {
	if d.spinner != nil {
		d.spinner.Resume()
	}
}

func (d *databasePiiScanner) DetectorFactory() []Detector {
	detectors := []Detector{}

	if !d.cnf.spacyOnly {
		detectors = append(detectors, NewRegexValueDetector())
	}

	if d.cnf.useSpacy {
		d.spacyMu.Lock()
		if d.spacyDet == nil {
			d.spacyDet = NewSpacyDetector().
				WithPoolSize(4).
				WithWorkDirs([]string{"python", "/etc/klouddbshield/python", "../../python"})
		}
		det := d.spacyDet
		d.spacyMu.Unlock()

		detectors = append(detectors, det)
	}

	return detectors
}

func (d *databasePiiScanner) GetTables(ctx context.Context) ([]TableRef, error) {
	if len(d.cnf.includeTable) != 0 {
		tables := make([]TableRef, len(d.cnf.includeTable))
		for i, name := range d.cnf.includeTable {
			tables[i] = TableRef{Schema: d.cnf.Schema, Name: name}
		}
		return tables, nil
	}

	tables, err := d.adapter.ListTables(ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting tables: %v", err)
	}
	return tables, nil
}

type scanningSpinner struct {
	mu        sync.Mutex
	paused    bool
	done      chan struct{}
	stopped   chan struct{}
	closeOnce sync.Once
}

func startScanningSpinner(delay time.Duration) *scanningSpinner {
	s := &scanningSpinner{
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}

	go func() {
		defer close(s.stopped)

		select {
		case <-s.done:
			return
		case <-time.After(delay):
		}

		frames := []string{"", ".", ". .", ". . ."}
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		i := 0
		for {
			select {
			case <-s.done:
				s.mu.Lock()
				fmt.Print("\r" + strings.Repeat(" ", 20) + "\r")
				s.mu.Unlock()
				return
			case <-ticker.C:
				s.mu.Lock()
				if !s.paused {
					fmt.Printf("\r> Scanning %-8s", frames[i%len(frames)])
					i++
				}
				s.mu.Unlock()
			}
		}
	}()

	return s
}

func (s *scanningSpinner) Pause() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.paused {
		s.paused = true
		fmt.Print("\r" + strings.Repeat(" ", 20) + "\r")
	}
}

func (s *scanningSpinner) Resume() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.paused = false
}

func (s *scanningSpinner) Stop() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
	<-s.stopped
}

func (d *databasePiiScanner) Scan(ctx context.Context) error {

	if d.cnf.runOption == RunOption_DeepScan {
		fmt.Println(text.FgCyan.Sprint("For huge databases, scanning all rows may take a considerable amount of time. To speed up"))
		fmt.Println(text.FgCyan.Sprint("the process, consider using the 'datascan' option, which will scan only"))
		fmt.Println(text.FgCyan.Sprint("10,000 rows per table"))
		fmt.Println()
	}

	tables, err := d.GetTables(ctx)
	if err != nil {
		return err
	}

	if len(tables) == 0 {
		fmt.Println("> No tables found in database")
		return nil
	}

	fmt.Println("> Found", len(tables), "tables")

	d.tableScanManager = NewTableScanManager().WithColumnDetector(NewRegexColumnDetector())
	if d.cnf.runOption != RunOption_MetaScan {
		d.tableScanManager.WithDetectorFactory(d.DetectorFactory)
	}

	initFunction := sync.OnceValue(func() error {
		err := d.tableScanManager.Start(ctx, d.numOfRunners)
		if err != nil {
			return err
		}

		fmt.Println("> Started table scan manager with", d.numOfRunners, "runners")
		d.spinner = startScanningSpinner(3 * time.Second)
		return nil
	})

	for _, table := range tables {
		if d.cnf.excludeTable != nil && d.cnf.excludeTable.Contains(table.Name) { // was: .Contains(table)
			continue
		}

		err := initFunction()
		if err != nil {
			return fmt.Errorf("error starting table scan manager: %v", err)
		}

		s := NewTableScanner(table, d.adapter, d.tableScanManager, d.cnf.runOption, d.cnf.AutoDetect, d.cnf.useSpacy, d.pauseSpinner, d.resumeSpinner)
		if err := s.processTable(ctx); err != nil {
			return fmt.Errorf("error processing table %s: %v", table.DisplayName(), err)
		}
	}
	return nil
}

type DatabasePIIScanOutput struct {
	ScanType        string
	SupportedLevels []string
	Data            map[string]TableDetailOutput
}
type TableDetailOutput map[string][]PIIDataWithWeightString

func (o *DatabasePIIScanOutput) HasFindings() bool {
	if o == nil {
		return false
	}
	for _, columns := range o.Data {
		for _, piidatas := range columns {
			if len(piidatas) > 0 {
				return true
			}
		}
	}
	return false
}

type PIIDataWithWeightString struct {
	Label            PIILabel
	Confidence       string
	ConfidenceIcon   string
	Weight           float64
	DetectorType     DetectorType
	DetectorName     string
	ScanedValueCount int
	MatchedCount     int
}

func NewPIIDataWithWeightString(label PIILabel, Weight float64, detectorType DetectorType, detectorName string) *PIIDataWithWeightString {
	confidence, icon := getConfidenceLabel(Weight)
	return &PIIDataWithWeightString{
		Label:          label,
		Confidence:     confidence,
		ConfidenceIcon: icon,
		Weight:         Weight,
		DetectorType:   detectorType,
		DetectorName:   detectorName,
	}
}

func (p *PIIDataWithWeightString) SetScanedValueAndMatchCount(matchCount, scanedValueCount int) {
	p.ScanedValueCount = scanedValueCount
	p.MatchedCount = matchCount
}

func (d *databasePiiScanner) GetResults() (*DatabasePIIScanOutput, error) {
	if d.tableScanManager == nil {
		// this handles the case when no table is scanned
		return nil, nil
	}

	data, err := d.tableScanManager.Output()
	if d.spinner != nil {
		d.spinner.Stop()
	}
	if err != nil {
		return nil, err
	}

	scanType := RunOptionTitleMap[d.cnf.runOption]
	if d.cnf.AutoDetect {
		scanType = AutoScanTitle
	}
	if d.cnf.useSpacy {
		scanType = RunOption_SpacyScan_Title
	}

	output := &DatabasePIIScanOutput{
		ScanType:        scanType,
		SupportedLevels: []string{"High", "Medium", "Low"},
		Data:            make(map[string]TableDetailOutput),
	}

	for _, table := range data {
		output.Data[table.TableName] = make(map[string][]PIIDataWithWeightString)
		for columnName, piiMap := range table.PiiDataMap {
			output.Data[table.TableName][columnName] = []PIIDataWithWeightString{}

			hasColumnMatch := false
			for _, piiData := range piiMap.ColumnMap {
				if len(piiData) > 0 {
					hasColumnMatch = true
					break
				}
			}

			for detector, piiData := range piiMap.ColumnMap {
				for label, pii := range piiData {
					piiDataWithWeight := NewPIIDataWithWeightString(label, pii.Weight, DetectorType_ColumnDetector, detector)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			count := d.tableScanManager.valueCount[table.TableName][columnName]

			// Adaptive Density Threshold for Phase 1:
			// Default to 30% density for unrecognized columns to suppress statistical noise.
			// Exception: if 2+ distinct entity types each appear in ≥10% of rows, the column is
			// clearly a multi-entity container (JSON blob, free-text narrative, CSV dump, raw PII store).
			// Lower the threshold to 10% so minority entities (e.g. Aadhaar at 19%, UPI at 24%,
			// or Phone at 28% when spread across rows) are still surfaced.
			phase1DensityThreshold := 0.30
			if !hasColumnMatch && count > 0 {
				confirmedEntityCount := 0
				for _, piiData := range piiMap.ValueMap {
					for _, pii := range piiData {
						if float64(pii.Count)/float64(count) >= 0.10 {
							confirmedEntityCount++
						}
					}
				}
				if confirmedEntityCount >= 2 {
					phase1DensityThreshold = 0.10
				}
			}

			for detector, piiData := range piiMap.ValueMap {
				for label, pii := range piiData {
					var finalWeight float64
					if count != 0 {
						finalWeight = pii.Weight / float64(count)
					}

					// Unrecognized Column Name Filter:
					if !hasColumnMatch && count > 0 {
						density := float64(pii.Count) / float64(count)
						if density < phase1DensityThreshold {
							continue
						}
					}

					if PiiEntitiesForWeightMergeLogic.Contains(label) {
						columnWeight := piiMap.ColumnMap["regex"][label].Weight
						if columnWeight >= 0.4 {
							finalWeight = (columnWeight + finalWeight) / 2
						}
					}

					piiDataWithWeight := NewPIIDataWithWeightString(label, finalWeight, DetectorType_ValueDetector, detector)
					piiDataWithWeight.SetScanedValueAndMatchCount(pii.Count, count)
					output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
				}
			}

			sort.Slice(output.Data[table.TableName][columnName], func(i, j int) bool {

				return OrderMap[string(output.Data[table.TableName][columnName][i].DetectorType)] >
					OrderMap[string(output.Data[table.TableName][columnName][j].DetectorType)] ||

					OrderMap[output.Data[table.TableName][columnName][i].DetectorName] >
						OrderMap[output.Data[table.TableName][columnName][j].DetectorName] ||

					output.Data[table.TableName][columnName][i].Weight > output.Data[table.TableName][columnName][j].Weight
			})

			// Phase 2 Fallback Scan for Unrecognized Columns
			// Runs for unrecognized column names (hasColumnMatch == false) to find additional text/Category C entities.
			if !hasColumnMatch {
				sampleVals := d.tableScanManager.UnrecognizedValues[table.TableName][columnName]
				if len(sampleVals) > 0 {
					fallbackDetector := NewRegexValueDetector()
					if err := fallbackDetector.Init(); err == nil {
						fallbackContext := ColumnContext{}

						labelHits := make(map[PIILabel]int)
						labelWeights := make(map[PIILabel]float64)

						for _, val := range sampleVals {
							labels, _ := fallbackDetector.Detect(context.TODO(), val, fallbackContext)
							for _, lbl := range labels {
								labelHits[lbl.PIILabel]++
								labelWeights[lbl.PIILabel] += lbl.Weight
							}
						}

						totalSamples := len(sampleVals)

						// Adaptive Density Threshold for Phase 2:
						// Default to 30% density. If Phase 1 already confirmed at least one entity,
						// lower the threshold to 10% so additional entities are surfaced.
						phase2DensityThreshold := 0.30
						if len(output.Data[table.TableName][columnName]) > 0 {
							phase2DensityThreshold = 0.10
						}

						for lbl, hits := range labelHits {
							if hits > 0 {
								density := float64(hits) / float64(totalSamples)
								if density < phase2DensityThreshold {
									continue
								}

								// Prevent duplicate entry if label was already detected in Phase 1
								alreadyExists := false
								for _, existing := range output.Data[table.TableName][columnName] {
									if existing.Label == lbl {
										alreadyExists = true
										break
									}
								}
								if alreadyExists {
									continue
								}

								// Average weight over sampled values (cap at Medium 🟡)
								avgWeight := labelWeights[lbl] / float64(totalSamples)
								if avgWeight >= 0.70 {
									avgWeight = 0.69
								}
								piiDataWithWeight := NewPIIDataWithWeightString(lbl, avgWeight, DetectorType_ValueDetector, "regex")
								piiDataWithWeight.SetScanedValueAndMatchCount(hits, totalSamples)
								output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
							}
						}
					}
				}
			}

			// Phase 3 Deep Fallback Scan for Fixed-Length Numeric / ID Entities
			// Runs for unrecognized column names (hasColumnMatch == false) to find additional fixed-length ID entities.
			if !hasColumnMatch {
				sampleVals := d.tableScanManager.UnrecognizedValues[table.TableName][columnName]
				if len(sampleVals) > 0 {
					fallbackDetector := NewRegexValueDetector()
					if err := fallbackDetector.Init(); err == nil {
						// Bounded Phase 3 context allowing fixed-length/domain-gated entities from Phase3Entities map
						phase3Context := ColumnContext{}
						for k, v := range Phase3Entities {
							phase3Context[k] = v
						}

						// Remove any label that was ALREADY detected in Phase 1 or Phase 2
						for _, existing := range output.Data[table.TableName][columnName] {
							delete(phase3Context, existing.Label)
						}

						if len(phase3Context) == 0 {
							continue
						}

						labelHits := make(map[PIILabel]int)
						labelWeights := make(map[PIILabel]float64)

						for _, val := range sampleVals {
							labels, _ := fallbackDetector.Detect(context.TODO(), val, phase3Context)
							for _, lbl := range labels {
								if phase3Context[lbl.PIILabel] {
									labelHits[lbl.PIILabel]++
									labelWeights[lbl.PIILabel] += lbl.Weight
								}
							}
						}

						totalSamples := len(sampleVals)

						// Adaptive Density Threshold for Phase 3:
						// Default to 30% density. If Phase 1 or 2 already confirmed at least one entity,
						// lower threshold to 10%.
						phase3DensityThreshold := 0.30
						if len(output.Data[table.TableName][columnName]) > 0 {
							phase3DensityThreshold = 0.10
						}

						// Calculate table's dominant domain from previously recognized High/Medium confidence entities
						dominantDomain := getTableDominantDomain(output.Data[table.TableName])

						for lbl, hits := range labelHits {
							if hits > 0 {
								// Phase 3 Domain Gate:
								// Domain-specific Phase 3 fallback IDs (Banking, Employment, NationalID)
								// REQUIRE positive table domain confirmation! If table domain is unknown ("")
								// or conflicts, reject the fallback candidate to prevent false positive noise.
								candidateDomain := EntityDomainMap[lbl]
								if candidateDomain != DomainPersonal && candidateDomain != dominantDomain {
									continue
								}

								density := float64(hits) / float64(totalSamples)
								if density < phase3DensityThreshold {
									continue
								}

								// Prevent duplicate entry if label was already detected in Phase 1 or 2
								alreadyExists := false
								for _, existing := range output.Data[table.TableName][columnName] {
									if existing.Label == lbl {
										alreadyExists = true
										break
									}
								}
								if alreadyExists {
									continue
								}

								// Average weight over sampled values (cap at Medium 🟡)
								avgWeight := labelWeights[lbl] / float64(totalSamples)
								if avgWeight >= 0.70 {
									avgWeight = 0.69
								}
								piiDataWithWeight := NewPIIDataWithWeightString(lbl, avgWeight, DetectorType_ValueDetector, "regex")
								piiDataWithWeight.SetScanedValueAndMatchCount(hits, totalSamples)
								output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
							}
						}
					}
				}
			}

			// Primary Winner Suppression:
			// If a column contains at least one High confidence finding, suppress all secondary lower-confidence
			// findings (Medium/Low) for that same column so noisy secondary hits don't clutter reports.
			hasHigh := false
			for _, item := range output.Data[table.TableName][columnName] {
				if item.Confidence == "High" {
					hasHigh = true
					break
				}
			}

			if hasHigh {
				filtered := make([]PIIDataWithWeightString, 0, len(output.Data[table.TableName][columnName]))
				for _, item := range output.Data[table.TableName][columnName] {
					if item.Confidence == "High" {
						filtered = append(filtered, item)
					}
				}
				output.Data[table.TableName][columnName] = filtered
			} else {
				hasMedium := false
				for _, item := range output.Data[table.TableName][columnName] {
					if item.Confidence == "Medium" {
						hasMedium = true
						break
					}
				}
				if hasMedium {
					filtered := make([]PIIDataWithWeightString, 0, len(output.Data[table.TableName][columnName]))
					for _, item := range output.Data[table.TableName][columnName] {
						if item.Confidence == "Medium" {
							filtered = append(filtered, item)
						}
					}
					output.Data[table.TableName][columnName] = filtered
				}
			}

		}
	}

	// print output to console
	// this code is for testing just to validate the output we are storing here.
	// for table, columnData := range output.Data {
	// 	fmt.Println("Table:", table)
	// 	for column, piiData := range columnData {
	// 		fmt.Println("Column:", column)
	// 		for _, pii := range piiData {
	// 			fmt.Println("Label:", pii.Label, "Confidence:", pii.Confidence, "Weight:", pii.Weight, "DetectorType:", pii.DetectorType, "DetectorName:", pii.DetectorName, "ScanedValueCount:", pii.ScanedValueCount, "MatchedCount:", pii.MatchedCount)
	// 		}
	// 	}
	// }

	return output, nil
}

func getConfidenceLabel(weight float64) (string, string) {
	if weight < 0.4 {
		return "Low", "🔵"
	} else if weight < 0.7 {
		return "Medium", "🟡"
	} else {
		return "High", "🔴"
	}
}

type tableScanner struct {
	table   TableRef
	adapter DBAdapter

	tableScanManager *TableScanManager

	runOption  RunOption
	autoDetect bool
	runSpacy   bool

	pauseSpinner  func()
	resumeSpinner func()
}

func NewTableScanner(table TableRef, adapter DBAdapter, tableScanManager *TableScanManager, runOption RunOption, autoDetect bool, runSpacy bool, pauseSpinner, resumeSpinner func()) *tableScanner {
	return &tableScanner{
		table: table, adapter: adapter,
		tableScanManager: tableScanManager,
		runOption:        runOption,
		autoDetect:       autoDetect,
		runSpacy:         runSpacy,
		pauseSpinner:     pauseSpinner,
		resumeSpinner:    resumeSpinner,
	}
}

func (p *tableScanner) processTable(ctx context.Context) error {
	columns, err := p.processColumns(ctx)
	if err != nil {
		return fmt.Errorf("error processing columns: %v", err)
	}
	if len(columns) == 0 {
		return nil
	}
	if p.runOption == RunOption_MetaScan {
		return nil
	}

	displayName := p.table.DisplayName()
	coloredTableName := text.Bold.Sprint(displayName)

	effectiveOption := p.runOption
	var rowCount int
	if p.autoDetect || p.runOption == RunOption_DataScan || p.runOption == RunOption_DeepScan || p.runOption == RunOption_SpacyScan {
		rowCount, err = p.adapter.RowCount(ctx, p.table)
		if err != nil {
			return fmt.Errorf("error getting row count for table %s: %v", displayName, err)
		}
		if rowCount == 0 {
			return nil
		}
	}

	if p.autoDetect {
		if rowCount < AUTO_SCAN_ROW_THRESHOLD {
			effectiveOption = RunOption_DeepScan
			if p.pauseSpinner != nil {
				p.pauseSpinner()
			}
			fmt.Println(">", coloredTableName, "has", rowCount, "rows - below threshold of", AUTO_SCAN_ROW_THRESHOLD, "rows, running deep scan")
			if p.resumeSpinner != nil {
				p.resumeSpinner()
			}
		} else {
			effectiveOption = RunOption_DataScan
		}
	}

	if p.runOption == RunOption_DataScan && rowCount < AUTO_SCAN_ROW_THRESHOLD {
		if p.pauseSpinner != nil {
			p.pauseSpinner()
		}
		fmt.Println(">", coloredTableName, "has", rowCount, "rows - Data scan may miss results on tables this small; omit --piiscanner or use --piiscanner deepscan for a full scan")
		if p.resumeSpinner != nil {
			p.resumeSpinner()
		}
	}

	var bar *progressbar.ProgressBar
	var barchan chan struct{}
	if effectiveOption == RunOption_DeepScan || effectiveOption == RunOption_SpacyScan {
		showsPrompt := !yesToAll && rowCount > DEEPSCAN_WARNINING_LIMIT && effectiveOption == RunOption_DeepScan
		showsBar := (p.runSpacy && rowCount > DEEPSCAN_SPACY_WARNING_LIMIT) || rowCount > DEEPSCAN_WARNINING_LIMIT

		if (showsPrompt || showsBar) && p.pauseSpinner != nil {
			p.pauseSpinner()
			defer func() {
				if p.resumeSpinner != nil {
					p.resumeSpinner()
				}
			}()
		}

		if showsPrompt {
			fmt.Print("> ", coloredTableName, " has ", rowCount, " rows. Do you want to continue? (yes=Y | no=N | yes to all=A) : ")
			var input string
			fmt.Scanln(&input) //nolint:errcheck
			if strings.ToLower(input) == "n" {
				return nil
			} else if strings.ToLower(input) == "a" {
				yesToAll = true
			} else if strings.ToLower(input) != "y" {
				return fmt.Errorf("invalid input")
			}
		}
		if showsBar {
			bar = progressbar.NewOptions(rowCount,
				progressbar.OptionSetDescription("Processing "+displayName+" table"),
				progressbar.OptionShowCount(),
				progressbar.OptionFullWidth(),
				progressbar.OptionSetItsString("rows"),
				progressbar.OptionShowIts(),
			)

			barchan = make(chan struct{})
			closeChan := make(chan struct{})
			go func() {
				count := 0
				t := time.NewTicker(time.Second)
				for {
					select {
					case <-barchan:
						count++
					case <-t.C:
						bar.Add(count) //nolint:errcheck
						count = 0
					case <-closeChan:
						bar.Finish() //nolint:errcheck
						fmt.Println()
						close(closeChan)
						close(barchan)
						t.Stop()
						return
					}
				}
			}()

			defer func() {
				closeChan <- struct{}{}
			}()
		}
	}

	opts := SampleOptions{Mode: SampleMode_Full}
	if effectiveOption == RunOption_DataScan {
		opts = SampleOptions{Mode: SampleMode_Limited, Size: 10000, Seed: DATASCAN_SAMPLE_SEED}
	}

	onRowScanned := func() {
		if barchan != nil {
			barchan <- struct{}{}
		}
	}

	return p.adapter.StreamValues(ctx, p.table, columns, opts, onRowScanned, func(columnName, value string) error {
		return p.tableScanManager.PushValue(ScanInput{
			Tablename:  displayName,
			ColumnName: columnName,
			Value:      value,
		})
	})
}

// func (p *piiTableScanner) getColumns() ([]string, error) {
// 	stmt, err := p.store.Prepare("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '" + p.tableName + "';")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer stmt.Close()

// 	rows, err := stmt.Query()
// 	if err != nil {
// 		return nil, err
// 	}

// 	defer rows.Close()

// 	var columns []string
// 	for rows.Next() {
// 		var column string
// 		var columnType string
// 		err := rows.Scan(&column, &columnType)
// 		if err != nil {
// 			return nil, err
// 		}

// 		if !IgnoreColumn(column) && !IgnoreColumnType(columnType) {
// 			columns = append(columns, column)
// 		}
// 	}

// 	return columns, nil
// }

func (p *tableScanner) processColumns(ctx context.Context) ([]string, error) {
	rawColumns, err := p.adapter.ListColumns(ctx, p.table)
	if err != nil {
		return nil, err
	}

	columns := FilterColumns(rawColumns)
	if len(columns) == 0 {
		return nil, nil
	}

	for _, column := range columns {
		err := p.tableScanManager.PushColumn(ctx, ScanInput{
			Tablename:  p.table.DisplayName(),
			ColumnName: column,
		})
		if err != nil {
			return nil, fmt.Errorf("error pushing column: %v", err)
		}
	}

	return columns, nil
}

// func (p *piiTableScanner) processValues(_ context.Context, values map[string]interface{}) error {
// 	for column, value := range values {
// 		err := p.tableScanManager.PushValue(ScanInput{
// 			Tablename:  p.tableName,
// 			ColumnName: column,
// 			Value:      value,
// 		})
// 		if err != nil {
// 			return err
// 		}

// 	}

// 	return nil
// }

// getTableDominantDomain calculates the dominant functional domain for a table
// based on recognized High and Medium confidence entities.
func getTableDominantDomain(tableOutput map[string][]PIIDataWithWeightString) Domain {
	domainScores := make(map[Domain]int)
	for _, piiList := range tableOutput {
		for _, item := range piiList {
			if item.Confidence == "High" || item.Confidence == "Medium" {
				domain := EntityDomainMap[item.Label]
				if domain != "" {
					domainScores[domain]++
				}
			}
		}
	}

	var dominant Domain
	maxScore := 0
	for domain, score := range domainScores {
		if score > maxScore {
			maxScore = score
			dominant = domain
		}
	}
	return dominant
}
