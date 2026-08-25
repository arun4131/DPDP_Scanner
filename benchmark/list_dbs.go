package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

func main() {
	ports := []string{"5433", "5432"}
	for _, port := range ports {
		connStr := fmt.Sprintf("host=localhost port=%s user=apple sslmode=disable dbname=postgres", port)
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			continue
		}
		rows, err := db.Query("SELECT datname FROM pg_database WHERE datistemplate = false;")
		if err != nil {
			db.Close()
			continue
		}
		fmt.Printf("\n--- Databases on localhost:%s ---\n", port)
		for rows.Next() {
			var dbname string
			rows.Scan(&dbname)
			fmt.Println("-", dbname)
		}
		rows.Close()
		db.Close()
	}
}
