package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

const (
	dbName   = "obfuscated_pii_test"
	connHost = "host=localhost port=5433 user=apple sslmode=disable"
)

func main() {
	// Connect to default postgres DB to recreate obfuscated_pii_test
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

	// Connect to obfuscated_pii_test DB
	db, err = sql.Open("postgres", connHost+" dbname="+dbName)
	if err != nil {
		log.Fatalf("failed to connect to %s: %v", dbName, err)
	}
	defer db.Close()

	schemaDDL := `
		CREATE TABLE obfuscated_user_data (
			id SERIAL PRIMARY KEY,
			col_01 VARCHAR(100), -- Bank Account Numbers
			col_02 VARCHAR(10),  -- CVVs
			col_03 VARCHAR(20),  -- Cheque Numbers
			col_04 VARCHAR(30),  -- UAN Numbers
			col_05 VARCHAR(50),  -- FASTag IDs
			col_06 VARCHAR(50),  -- Loan Account Numbers
			col_07 VARCHAR(20),  -- MICR Codes
			col_08 VARCHAR(50),  -- Aadhaar Numbers
			col_09 VARCHAR(20),  -- PAN Numbers
			col_10 VARCHAR(100)  -- Emails
		);
	`
	_, err = db.Exec(schemaDDL)
	if err != nil {
		log.Fatalf("failed to create schema: %v", err)
	}

	stmt, err := db.Prepare(`
		INSERT INTO obfuscated_user_data
		(col_01, col_02, col_03, col_04, col_05, col_06, col_07, col_08, col_09, col_10)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`)
	if err != nil {
		log.Fatalf("failed to prepare insert: %v", err)
	}
	defer stmt.Close()

	for i := 1; i <= 100; i++ {
		bankAcct := fmt.Sprintf("912345678%03d", i)
		cvv := fmt.Sprintf("%03d", (i%900)+100)
		chequeNo := fmt.Sprintf("100%03d", i)
		uan := fmt.Sprintf("100987654%03d", i)
		fastag := fmt.Sprintf("FT1234567890%04d", i)
		loanAcct := fmt.Sprintf("LN-9876543%03d", i)
		micr := fmt.Sprintf("400240%03d", i)
		aadhaar := fmt.Sprintf("2345 6789 %04d", 1000+i)
		pan := fmt.Sprintf("ABCDE%04dF", 1000+i)
		email := fmt.Sprintf("user_%d@example.com", i)

		_, err := stmt.Exec(bankAcct, cvv, chequeNo, uan, fastag, loanAcct, micr, aadhaar, pan, email)
		if err != nil {
			log.Fatalf("failed to insert row %d: %v", i, err)
		}
	}

	fmt.Println("> Successfully seeded 100 rows of obfuscated test data!")
}
