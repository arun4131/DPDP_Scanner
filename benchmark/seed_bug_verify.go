package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

const (
	dbName   = "bug_verify_db"
	connHost = "host=localhost port=5433 user=apple sslmode=disable"
)

func main() {
	// Connect to default postgres DB to recreate bug_verify_db
	db, err := sql.Open("postgres", connHost+" dbname=postgres")
	if err != nil {
		log.Fatalf("failed to connect to postgres: %v", err)
	}

	_, _ = db.Exec("DROP DATABASE IF EXISTS " + dbName)
	_, err = db.Exec("CREATE DATABASE " + dbName)
	if err != nil {
		log.Fatalf("failed to create database %s: %v", dbName, err)
	}
	db.Close()
	fmt.Printf("> Created database %s\n", dbName)

	// Connect to bug_verify_db
	db, err = sql.Open("postgres", connHost+" dbname="+dbName)
	if err != nil {
		log.Fatalf("failed to connect to %s: %v", dbName, err)
	}
	defer db.Close()

	schemaDDL := `
		CREATE TABLE users (
			id SERIAL PRIMARY KEY,
			bank_account_number VARCHAR(100)
		);
	`
	_, err = db.Exec(schemaDDL)
	if err != nil {
		log.Fatalf("failed to create schema: %v", err)
	}

	tx, err := db.Begin()
	if err != nil {
		log.Fatalf("failed to begin tx: %v", err)
	}

	stmt, err := tx.Prepare("INSERT INTO users (bank_account_number) VALUES ($1)")
	if err != nil {
		log.Fatalf("failed to prepare insert: %v", err)
	}
	defer stmt.Close()

	// Insert 1 valid bank account number at row 1
	_, err = stmt.Exec("912345678901")
	if err != nil {
		log.Fatalf("failed to insert valid row: %v", err)
	}

	// Insert 9,999 non-matching text strings
	for i := 2; i <= 10000; i++ {
		_, err = stmt.Exec(fmt.Sprintf("regular_non_pii_value_%d", i))
		if err != nil {
			log.Fatalf("failed to insert row %d: %v", i, err)
		}
	}

	if err := tx.Commit(); err != nil {
		log.Fatalf("failed to commit transaction: %v", err)
	}

	fmt.Println("> Successfully created bug_verify_db with 10,000 rows (1 match, 9,999 non-matches)!")
}
