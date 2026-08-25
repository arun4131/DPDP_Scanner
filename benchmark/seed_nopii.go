package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/lib/pq"
)

func main() {
	connStr := "host=localhost port=5432 user=apple dbname=postgres sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to postgres: %v", err)
	}
	defer db.Close()

	// Drop and Create database
	_, _ = db.Exec("DROP DATABASE IF EXISTS nopii_database;")
	_, err = db.Exec("CREATE DATABASE nopii_database WITH ENCODING 'UTF8';")
	if err != nil {
		log.Fatalf("Failed to create database nopii_database: %v", err)
	}
	fmt.Println("Database nopii_database created successfully!")

	// Connect to nopii_database
	nopiiConnStr := "host=localhost port=5432 user=apple dbname=nopii_database sslmode=disable"
	nopiiDB, err := sql.Open("postgres", nopiiConnStr)
	if err != nil {
		log.Fatalf("Failed to connect to nopii_database: %v", err)
	}
	defer nopiiDB.Close()

	// Table 1: Real estate / Property management (3-4 digit apartment/room/flat numbers that look like CVV)
	_, err = nopiiDB.Exec(`
		CREATE TABLE public.property_listings (
			listing_id INT PRIMARY KEY,
			apt_num VARCHAR(10),
			room_no VARCHAR(10),
			flat_number VARCHAR(10),
			floor_num INT,
			building_code VARCHAR(15),
			monthly_rent NUMERIC(10,2)
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create property_listings: %v", err)
	}

	for i := 1; i <= 1000; i++ {
		aptNo := fmt.Sprintf("%03d", (i%900)+100)      // e.g. "101", "204", "899" (3-digit CVV format)
		roomNo := fmt.Sprintf("%04d", (i%8000)+1000)  // e.g. "1204", "4012" (4-digit CVV format)
		flatNo := fmt.Sprintf("F-%03d", (i%900)+100)  // e.g. "F-101"
		bldgCode := fmt.Sprintf("BLD%07d", i)          // e.g. "BLD0000001" (Looks like VoterID format [A-Z]{3}\d{7})
		_, err = nopiiDB.Exec(`INSERT INTO public.property_listings VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			i, aptNo, roomNo, flatNo, (i%30)+1, bldgCode, 15000+(i*10),
		)
		if err != nil {
			log.Fatalf("Failed insert property_listings: %v", err)
		}
	}
	fmt.Println("Table property_listings seeded with 1000 rows.")

	// Table 2: Logistics / Warehouse inventory (6-digit pincodes/OTPs that look like ChequeNumber)
	_, err = nopiiDB.Exec(`
		CREATE TABLE public.warehouse_inventory (
			item_id INT PRIMARY KEY,
			pincode_zone VARCHAR(10),
			batch_otp VARCHAR(10),
			product_serial VARCHAR(20),
			stock_quantity INT,
			shelf_location VARCHAR(15)
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create warehouse_inventory: %v", err)
	}

	for i := 1; i <= 1000; i++ {
		pincode := fmt.Sprintf("%06d", 560000+(i%99))   // 6-digit pin format "560001" (Looks like ChequeNumber \d{6})
		otp := fmt.Sprintf("%06d", (i*7919)%1000000)     // 6-digit OTP
		prodSerial := fmt.Sprintf("PRD%05dZ", i)        // 10-char alphanumeric (Looks like TAN [A-Z]{4}\d{5}[A-Z])
		shelf := fmt.Sprintf("SHF-%04d", i)
		_, err = nopiiDB.Exec(`INSERT INTO public.warehouse_inventory VALUES ($1, $2, $3, $4, $5, $6)`,
			i, pincode, otp, prodSerial, (i*13)%500, shelf,
		)
		if err != nil {
			log.Fatalf("Failed insert warehouse_inventory: %v", err)
		}
	}
	fmt.Println("Table warehouse_inventory seeded with 1000 rows.")

	// Table 3: Healthcare / Patient code tracking (Internal codes that look like VoterID / Passport)
	_, err = nopiiDB.Exec(`
		CREATE TABLE public.hospital_reference_codes (
			ref_id INT PRIMARY KEY,
			doctor_code VARCHAR(15),
			agent_code VARCHAR(15),
			driver_code VARCHAR(15),
			employee_code VARCHAR(15),
			patient_code VARCHAR(15),
			passport_ref_code VARCHAR(15)
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create hospital_reference_codes: %v", err)
	}

	for i := 1; i <= 1000; i++ {
		docCode := fmt.Sprintf("DOC%07d", i)   // 3 letters + 7 digits (VoterID collision)
		agentCode := fmt.Sprintf("AGT%07d", i) // 3 letters + 7 digits
		drvCode := fmt.Sprintf("DRV%07d", i)   // 3 letters + 7 digits
		empCode := fmt.Sprintf("EMP%07d", i)   // 3 letters + 7 digits
		patCode := fmt.Sprintf("PAT%07d", i)   // 3 letters + 7 digits
		passRef := fmt.Sprintf("A%07d", i)     // 1 letter + 7 digits (Passport format)
		_, err = nopiiDB.Exec(`INSERT INTO public.hospital_reference_codes VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			i, docCode, agentCode, drvCode, empCode, patCode, passRef,
		)
		if err != nil {
			log.Fatalf("Failed insert hospital_reference_codes: %v", err)
		}
	}
	fmt.Println("Table hospital_reference_codes seeded with 1000 rows.")

	// Table 4: Banking / Financial system logs (Numeric IDs that look like Bank Accounts, MICR, UAN)
	_, err = nopiiDB.Exec(`
		CREATE TABLE public.system_audit_logs (
			log_id INT PRIMARY KEY,
			check_in_time TIMESTAMP,
			check_out_time TIMESTAMP,
			background_check_id INT,
			quantity_count INT,
			seq_account_id INT,
			seq_loan_id INT,
			seq_policy_id INT,
			seq_user_id INT
		);
	`)
	if err != nil {
		log.Fatalf("Failed to create system_audit_logs: %v", err)
	}

	for i := 1; i <= 1000; i++ {
		_, err = nopiiDB.Exec(`INSERT INTO public.system_audit_logs VALUES (
			$1, NOW(), NOW(), $2, $3, $4, $5, $6, $7
		)`,
			i, i+100, (i*3)%200, i+1000, i+2000, i+3000, i+4000,
		)
		if err != nil {
			log.Fatalf("Failed insert system_audit_logs: %v", err)
		}
	}
	fmt.Println("Table system_audit_logs seeded with 1000 rows.")

	fmt.Println("\n✅ All 4 non-PII test tables created and seeded successfully in nopii_database!")
}
