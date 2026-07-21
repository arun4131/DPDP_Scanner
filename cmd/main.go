package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/klouddb/DPA_private/piiscanner"
	"github.com/klouddb/DPA_private/pkg/postgresdb"
)

type InstanceConfig struct {
	Host      string   `toml:"host"`
	Port      int      `toml:"port"`
	User      string   `toml:"user"`
	Password  string   `toml:"password"`
	Databases []string `toml:"databases"`
}

type AppConfig struct {
	Instances []InstanceConfig `toml:"instances"`
}

const defaultConfigPath = "/etc/dpdpscanner/config.toml"

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

	return "", fmt.Errorf("config.toml not found in current directory or %s; use --config to specify its location", defaultConfigPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func main() {
	configDir := flag.String("config", "", "directory containing config.toml (default: current directory, falling back to /etc/dpdpscanner)")
	runOption := flag.String("piiscanner", "", "scan type: datascan | metascan | deepscan")
	dbFilter := flag.String("database", "", "scan only this database (leave empty to scan all)")
	schema := flag.String("schema", "public", "schema to scan")
	excludeTable := flag.String("exclude-table", "", "comma-separated list of tables to exclude")
	includeTable := flag.String("include-table", "", "comma-separated list of tables to include")
	targetHost := flag.String("target-host", "", "scan only this host (leave empty to scan all)")
	printAll := flag.Bool("print-all", false, "print all confidence levels in terminal")
	printSummary := flag.Bool("print-summary", false, "print summary only")
	flag.Parse()

	validOptions := map[string]bool{"datascan": true, "metascan": true, "deepscan": true, "spacyscan": true}
	if *runOption != "" && !validOptions[*runOption] {
		log.Fatalf("Invalid --piiscanner value: %q. Must be datascan, metascan, deepscan, or spacyscan", *runOption)
	}

	if *runOption == "" {
		*runOption = piiscanner.RunOption_Auto_String
	}

	configPath, err := resolveConfigPath(*configDir)
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

	dbMatched := false
	for _, inst := range cfg.Instances {
		if *targetHost != "" && inst.Host != *targetHost {
			continue
		}

		port := inst.Port
		if port == 0 {
			port = 5432
		}
		for _, database := range inst.Databases {
			if *dbFilter != "" && database != *dbFilter {
				continue
			}
			dbMatched = true

			fmt.Printf("\n=== Scanning %s:%d / %s ===\n", inst.Host, port, database)

			pgConf := postgresdb.Postgres{
				Host:      inst.Host,
				Port:      strconv.Itoa(port),
				User:      inst.User,
				Password:  inst.Password,
				DBName:    database,
				SSLmode:   "disable",
				PingCheck: true,
			}

			store, _, err := postgresdb.Open(pgConf)
			if err != nil {
				log.Printf("  [SKIP] Could not connect: %v", err)
				continue
			}

			cnf, err := piiscanner.NewConfig(&pgConf, *runOption, *excludeTable, *includeTable, database, *schema, *printAll, false, *printSummary)
			if err != nil {
				store.Close()
				log.Printf("  [SKIP] Config error: %v", err)
				continue
			}

			helper := piiscanner.NewPostgresDBHelper(cnf.Schema)
			scanner := piiscanner.NewDatabasePiiScanner(helper, store, cnf)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			err = scanner.Scan(ctx)
			cancel()
			store.Close()

			if err != nil {
				log.Printf("  [SKIP] Scan error: %v", err)
				continue
			}

			output, err := scanner.GetResults()
			if err != nil || output == nil {
				log.Printf("  [SKIP] No results returned")
				continue
			}

			piiscanner.PrintTerminalOutput(output, *cnf)
			piiscanner.CreateTabularOutputfile(output, *cnf)
			piiscanner.CreateHTMLReport(output, *cnf, inst.Host)
		}

	}
	if *dbFilter != "" && !dbMatched {
		log.Fatalf("database %q not found in config.toml", *dbFilter)
	}
}
