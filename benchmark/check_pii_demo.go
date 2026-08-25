package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	connStr := "host=localhost port=5432 user=apple sslmode=disable dbname=pii_demo"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("failed to connect: %v", err)
	}
	defer db.Close()

	rows, err := db.Query("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE';")
	if err != nil {
		log.Fatalf("query failed: %v", err)
	}
	defer rows.Close()

	fmt.Println("\n--- Tables & Row Counts in pii_demo ---")
	for rows.Next() {
		var table string
		rows.Scan(&table)
		var count int
		db.QueryRow("SELECT COUNT(*) FROM \"" + table + "\"").Scan(&count)
		fmt.Printf("- %-30s : %d rows\n", table, count)
	}
}
