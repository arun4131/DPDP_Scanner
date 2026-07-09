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

	"github.com/klouddb/DPA_private/pkg/postgresdb"
	"github.com/klouddb/DPA_private/piiscanner"
)

// ScanRequest is the JSON body for POST /api/scan
type ScanRequest struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	User     string `json:"user"`
	Password string `json:"password"`
	Database string `json:"database"`
	Schema   string `json:"schema"`
	RunOption string `json:"run_option"` // datascan | metascan | deepscan
}

// RowResult is one row in the frontend table
type RowResult struct {
	Table    string `json:"table"`
	Column   string `json:"column"`
	Label    string `json:"label"`
	Matched  string `json:"matched"`
	Detector string `json:"detector"`
}

// ScanResponse is returned to the frontend
type ScanResponse struct {
	Available bool        `json:"available"`
	Schema    string      `json:"schema"`
	RunOption string      `json:"run_option"`
	Rows      []RowResult `json:"rows"`
	Meta      []RowResult `json:"meta"`
	LowConf   []string    `json:"low_conf"`
	Message   string      `json:"message,omitempty"`
}

func enableCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
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
	if req.Port == "" {
		req.Port = "5432"
	}

	port, _ := strconv.Atoi(req.Port)

	pgConf := postgresdb.Postgres{
		Host:     req.Host,
		Port:     strconv.Itoa(port),
		User:     req.User,
		Password: req.Password,
		DBName:   req.Database,
		SSLmode:  "disable",
		PingCheck: true,
	}

	store, _, err := postgresdb.Open(pgConf)
	if err != nil {
		writeJSON(w, http.StatusOK, ScanResponse{
			Available: false,
			Message:   "Could not connect to database: " + err.Error(),
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

	for tableName, columns := range output.Data {
		isHighConf := false
		for colName, piiList := range columns {
			for _, pii := range piiList {
				conf := strings.ToLower(pii.Confidence)
				matched := ""
				if pii.ScanedValueCount > 0 {
					matched = fmt.Sprintf("%d/%d", pii.MatchedCount, pii.ScanedValueCount)
				}
				detector := string(pii.DetectorName)

				row := RowResult{
					Table:    tableName,
					Column:   colName,
					Label:    string(pii.Label),
					Matched:  matched,
					Detector: detector,
				}

				if conf == "high" {
					resp.Rows = append(resp.Rows, row)
					isHighConf = true
				} else if conf == "medium" || conf == "low" {
					resp.Meta = append(resp.Meta, row)
				}
				_ = isHighConf
			}
		}

		// Tables with no high-conf findings go to LowConf
		hasHigh := false
		for _, piiList := range columns {
			for _, pii := range piiList {
				if strings.ToLower(pii.Confidence) == "high" {
					hasHigh = true
				}
			}
		}
		if !hasHigh {
			resp.LowConf = append(resp.LowConf, tableName)
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Serve frontend static files
	fs := http.FileServer(http.Dir("./front"))
	http.Handle("/", fs)
	http.HandleFunc("/api/scan", handleScan)

	log.Printf("Server running at http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
