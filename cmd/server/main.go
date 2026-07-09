package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/klouddb/DPA_private/piiscanner"
	"github.com/klouddb/DPA_private/pkg/postgresdb"
)

// ── Config ────────────────────────────────────────────────────────────────────

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

var appConfig AppConfig

func loadConfig(path string) error {
	_, err := toml.DecodeFile(path, &appConfig)
	return err
}

func findInstance(host string, port int) *InstanceConfig {
	for i := range appConfig.Instances {
		inst := &appConfig.Instances[i]
		p := inst.Port
		if p == 0 {
			p = 5432
		}
		if inst.Host == host && p == port {
			return inst
		}
	}
	return nil
}

// ── API types ─────────────────────────────────────────────────────────────────

type InstanceInfo struct {
	Instance  string   `json:"instance"`
	Databases []string `json:"databases"`
}

type ScanRequest struct {
	Instance  string `json:"instance"`
	Database  string `json:"database"`
	Schema    string `json:"schema"`
	RunOption string `json:"run_option"`
}

type RowResult struct {
	Table    string `json:"table"`
	Column   string `json:"column"`
	Label    string `json:"label"`
	Matched  string `json:"matched"`
	Detector string `json:"detector"`
}

type ScanResponse struct {
	Available bool        `json:"available"`
	Schema    string      `json:"schema"`
	RunOption string      `json:"run_option"`
	Rows      []RowResult `json:"rows"`
	Meta      []RowResult `json:"meta"`
	LowConf   []string    `json:"low_conf"`
	Message   string      `json:"message,omitempty"`
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func handleInstances(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	result := []InstanceInfo{}
	for _, inst := range appConfig.Instances {
		port := inst.Port
		if port == 0 {
			port = 5432
		}
		result = append(result, InstanceInfo{
			Instance:  fmt.Sprintf("%s:%d", inst.Host, port),
			Databases: inst.Databases,
		})
	}
	writeJSON(w, http.StatusOK, result)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	enableCORS(w)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if req.Schema == "" {
		req.Schema = "public"
	}
	if req.RunOption == "" {
		req.RunOption = "datascan"
	}

	parts := strings.Split(req.Instance, ":")
	host := parts[0]
	port := 5432
	if len(parts) == 2 {
		port, _ = strconv.Atoi(parts[1])
	}

	inst := findInstance(host, port)
	if inst == nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "Instance not found in config: " + req.Instance,
		})
		return
	}

	pgConf := postgresdb.Postgres{
		Host:      inst.Host,
		Port:      strconv.Itoa(port),
		User:      inst.User,
		Password:  inst.Password,
		DBName:    req.Database,
		SSLmode:   "disable",
		PingCheck: true,
	}

	store, _, err := postgresdb.Open(pgConf)
	if err != nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "Could not connect: " + err.Error(),
		})
		return
	}
	defer store.Close()

	cnf, err := piiscanner.NewConfig(&pgConf, req.RunOption, "", "", req.Database, req.Schema, false, false, false)
	if err != nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "Config error: " + err.Error(),
		})
		return
	}

	helper := piiscanner.NewPostgresDBHelper(cnf.Schema)
	scanner := piiscanner.NewDatabasePiiScanner(helper, store, cnf)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := scanner.Scan(ctx); err != nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "Scan error: " + err.Error(),
		})
		return
	}

	output, err := scanner.GetResults()
	if err != nil || output == nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "No results returned.",
		})
		return
	}

	resp := ScanResponse{
		Available: true,
		Schema:    req.Schema,
		RunOption: req.RunOption,
		Rows:      []RowResult{},
		Meta:      []RowResult{},
		LowConf:   []string{},
	}

	seen := map[string]bool{}

	for tableName, columns := range output.Data {
		hasHigh := false
		for colName, piiList := range columns {
			for _, pii := range piiList {
				conf := strings.ToLower(pii.Confidence)
				matched := ""
				if pii.ScanedValueCount > 0 {
					matched = fmt.Sprintf("%d/%d", pii.MatchedCount, pii.ScanedValueCount)
				}
				row := RowResult{
					Table:    tableName,
					Column:   colName,
					Label:    string(pii.Label),
					Matched:  matched,
					Detector: pii.DetectorName,
				}
				key := tableName + "|" + colName + "|" + string(pii.Label)
				if conf == "high" {
					if !seen[key] {
						seen[key] = true
						resp.Rows = append(resp.Rows, row)
					}
					hasHigh = true
				} else {
					if !seen[key] {
						seen[key] = true
						resp.Meta = append(resp.Meta, row)
					}
				}
			}
		}
		hasMeta := false
		for _, piiList := range columns {
			for _, pii := range piiList {
				if strings.ToLower(pii.Confidence) != "high" {
					hasMeta = true
				}
			}
		}
		if !hasHigh && !hasMeta {
			resp.LowConf = append(resp.LowConf, tableName)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	if err := loadConfig("config.toml"); err != nil {
		log.Fatalf("Failed to load config.toml: %v", err)
	}
	log.Printf("Loaded %d instance(s) from config.toml", len(appConfig.Instances))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fs := http.FileServer(http.Dir("./front"))
	http.Handle("/", fs)
	http.HandleFunc("/api/instances", handleInstances)
	http.HandleFunc("/api/scan", handleScan)

	log.Printf("Server running at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
