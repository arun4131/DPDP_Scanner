package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/klouddb/dpdpa_pii_db_scanner/piiscanner"
	"github.com/klouddb/dpdpa_pii_db_scanner/pkg/postgresdb"
)

type InstanceConfig struct {
	Host        string   `toml:"host"`
	Port        int      `toml:"port"`
	User        string   `toml:"user"`
	Password    string   `toml:"password"`
	Databases   []string `toml:"databases"`
	SSLmode     string   `toml:"sslmode"`
	SSLcert     string   `toml:"sslcert"`
	SSLkey      string   `toml:"sslkey"`
	SSLrootcert string   `toml:"sslrootcert"`
}

type AppConfig struct {
	Instances []InstanceConfig `toml:"instances"`
}

type scanFlags struct {
	runOption    string
	schema       string
	excludeTable string
	includeTable string
	printAll     bool
	printSummary bool
	noTimeout    bool
}

const defaultConfigPath = "/etc/dpdpscanner/config.toml"

// defaultScanTimeout caps how long a single database scan may run before
// being aborted, unless --no-timeout is set. It's referenced directly by
// the --no-timeout flag's help text and by the timeout-suggestion message
// below, so both stay in sync automatically if this value ever changes.
const defaultScanTimeout = 5 * time.Minute

func resolveConfigPath(configDir string) (string, error) {
	if configDir != "" {
		return filepath.Join(configDir, "config.toml"), nil
	}

	if cwdPath := filepath.Join(".", "config.toml"); fileExists(cwdPath) {
		return cwdPath, nil
	}
	if fileExists(defaultConfigPath) {
		return defaultConfigPath, nil
	}

	return "", fmt.Errorf("config.toml not found in current directory or %s; use --config to specify its location, or pass a postgres:// URI as the first argument", defaultConfigPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	configDir := flag.String("config", "", "directory containing config.toml (default: current directory, falling back to /etc/dpdpscanner)")
	runOption := flag.String("piiscanner", "", "scan type: datascan | metascan | deepscan | spacyscan (leave empty for automatic per-table selection)")
	dbFilter := flag.String("database", "", "scan only this database (leave empty to scan all); ignored when a postgres:// URI is given")
	schema := flag.String("schema", "public", "schema to scan")
	excludeTable := flag.String("exclude-table", "", "comma-separated list of tables to exclude")
	includeTable := flag.String("include-table", "", "comma-separated list of tables to include")
	targetHost := flag.String("target-host", "", "scan only this host (leave empty to scan all); ignored when a postgres:// URI is given")
	printAll := flag.Bool("print-all", false, "include low/medium confidence results in terminal, log files, and HTML report (default: high confidence only)")
	printSummary := flag.Bool("print-summary", false, "print summary only")
	noTimeout := flag.Bool("no-timeout", false, fmt.Sprintf("disable the %s per-database scan timeout, useful for very large databases that need more time", defaultScanTimeout))
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [flags] [postgres://user:pass@host:port/dbname]\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Scan PostgreSQL for PII. Use config.toml, or pass a connection URI to skip the config file:\n")
		fmt.Fprintf(flag.CommandLine.Output(), "  %s postgres://user:pass@localhost:5432/mydb?sslmode=disable\n\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	// piiscanner.IsValidRunOption is the single source of truth for what
	// --piiscanner accepts — there's no separate "auto" value to allow for;
	// leaving the flag empty is how you get automatic per-table selection,
	// which piiscanner.NewConfig handles directly.
	if *runOption != "" && !piiscanner.IsValidRunOption(*runOption) {
		opts := piiscanner.RunOptionSlice()
		sort.Strings(opts)
		log.Fatalf("Invalid --piiscanner value: %q. Must be one of: %s", *runOption, strings.Join(opts, ", "))
	}

	sf := scanFlags{
		runOption:    *runOption,
		schema:       *schema,
		excludeTable: *excludeTable,
		includeTable: *includeTable,
		printAll:     *printAll,
		printSummary: *printSummary,
		noTimeout:    *noTimeout,
	}

	args := flag.Args()
	if len(args) > 1 {
		log.Fatalf("unexpected arguments: %v (pass a single postgres:// URI, or none to use config.toml)", args)
	}

	if len(args) == 1 {
		if !postgresdb.IsConnectionURI(args[0]) {
			log.Fatalf("unexpected argument %q (expected a postgres:// or postgresql:// URI)", args[0])
		}
		if *configDir != "" {
			log.Fatal("cannot use --config together with a postgres:// URI")
		}
		if *dbFilter != "" || *targetHost != "" {
			log.Fatal("--database and --target-host are not used with a postgres:// URI; put host and dbname in the URI instead")
		}
		runFromURI(args[0], sf)
		return
	}

	runFromConfig(*configDir, *dbFilter, *targetHost, sf)
}

func runFromURI(uri string, sf scanFlags) {
	pgConf, err := postgresdb.ParseConnectionURI(uri)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n=== Scanning %s / %s ===\n", postgresdb.FormatHostPort(pgConf.Host, pgConf.Port), pgConf.DBName)
	scanOneDatabase(pgConf, sf)
}

func runFromConfig(configDir, dbFilter, targetHost string, sf scanFlags) {
	configPath, err := resolveConfigPath(configDir)
	if err != nil {
		log.Fatal(err)
	}
	var cfg AppConfig
	if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
		log.Fatalf("Failed to load config.toml from %s: %v", configPath, err)
	}
	if len(cfg.Instances) == 0 {
		log.Fatal("No instances defined in config.toml")
	}

	if targetHost != "" {
		hostMatched := false
		for _, inst := range cfg.Instances {
			if inst.Host == targetHost {
				hostMatched = true
				break
			}
		}
		if !hostMatched {
			log.Fatalf("host %q not found in config.toml", targetHost)
		}
	}

	dbMatched := false
	for _, inst := range cfg.Instances {
		if targetHost != "" && inst.Host != targetHost {
			continue
		}

		port := inst.Port
		if port == 0 {
			port = 5432
		}
		for _, database := range inst.Databases {
			if dbFilter != "" && database != dbFilter {
				continue
			}
			dbMatched = true

			fmt.Printf("\n=== Scanning %s:%d / %s ===\n", inst.Host, port, database)

			pgConf := postgresdb.Postgres{
				Host:        inst.Host,
				Port:        strconv.Itoa(port),
				User:        inst.User,
				Password:    inst.Password,
				DBName:      database,
				SSLmode:     inst.SSLmode,
				SSLcert:     inst.SSLcert,
				SSLkey:      inst.SSLkey,
				SSLrootcert: inst.SSLrootcert,
				PingCheck:   true,
			}

			scanOneDatabase(pgConf, sf)
		}
	}
	if dbFilter != "" && !dbMatched {
		log.Fatalf("database %q not found in config.toml", dbFilter)
	}
}

func scanOneDatabase(pgConf postgresdb.Postgres, sf scanFlags) {
	store, _, err := postgresdb.Open(pgConf)
	if err != nil {
		log.Printf("  [SKIP] Could not connect: %v", err)
		return
	}

	cnf, err := piiscanner.NewConfig(&pgConf, sf.runOption, sf.excludeTable, sf.includeTable, pgConf.DBName, sf.schema, sf.printAll, false, sf.printSummary)
	if err != nil {
		store.Close()
		log.Printf("  [SKIP] Config error: %v", err)
		return
	}

	helper := piiscanner.NewPostgresDBHelper(cnf.Schema)
	scanner := piiscanner.NewDatabasePiiScanner(helper, store, cnf)

	var ctx context.Context
	var cancel context.CancelFunc
	if sf.noTimeout {
		ctx, cancel = context.Background(), func() {}
	} else {
		ctx, cancel = context.WithTimeout(context.Background(), defaultScanTimeout)
	}
	err = scanner.Scan(ctx)
	cancel()
	store.Close()

	if err != nil {
		scanner.Close()
		log.Printf("  [SKIP] Scan error: %v", err)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("  Scan of %s stopped after the %s timeout — re-run with --no-timeout to let it finish without a time limit.", pgConf.DBName, defaultScanTimeout)
		}
		return
	}

	output, err := scanner.GetResults()
	if err != nil || output == nil {
		log.Printf("  [SKIP] No results returned")
		return
	}

	piiscanner.PrintTerminalOutput(output, *cnf)
	piiscanner.CreateTabularOutputfile(output, *cnf)
	piiscanner.CreateHTMLReport(output, *cnf, pgConf.Host)
}
