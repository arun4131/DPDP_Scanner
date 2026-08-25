package main

import (
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	connStr := "host=localhost port=5432 user=apple dbname=noname sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error opening db: %v", err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging db: %v", err)
	}

	fmt.Println("> Connected to database noname")

	// Drop existing table if any
	_, _ = db.Exec("DROP TABLE IF EXISTS obfuscated_records;")

	// Create table with 33 obfuscated column names: col_val_01 ... col_val_33
	createTableSQL := `CREATE TABLE obfuscated_records (
		id SERIAL PRIMARY KEY,
		col_val_01 TEXT, -- Email
		col_val_02 TEXT, -- PANNumber
		col_val_03 TEXT, -- AdharcardNumber (Verhoeff)
		col_val_04 TEXT, -- CreditCard (Luhn)
		col_val_05 TEXT, -- GSTIN (Mod-36)
		col_val_06 TEXT, -- IPAddress
		col_val_07 TEXT, -- MacAddress
		col_val_08 TEXT, -- UPIID
		col_val_09 TEXT, -- CIN
		col_val_10 TEXT, -- OAuthToken
		col_val_11 TEXT, -- EPFMemberID
		col_val_12 TEXT, -- SEBIRegistration
		col_val_13 TEXT, -- IFSC
		col_val_14 TEXT, -- ABHANumber (Dashed)
		col_val_15 TEXT, -- TAN
		col_val_16 TEXT, -- DrivingLicenceNumber
		col_val_17 TEXT, -- VehicleNumber
		col_val_18 TEXT, -- Phone
		col_val_19 TEXT, -- Address
		col_val_20 TEXT, -- Gender
		col_val_21 TEXT, -- ESIC
		col_val_22 TEXT, -- RationCard
		col_val_23 TEXT, -- CVV
		col_val_24 TEXT, -- ChequeNumber
		col_val_25 TEXT, -- MICRCode
		col_val_26 TEXT, -- UAN
		col_val_27 TEXT, -- PassportNumber
		col_val_28 TEXT, -- VoterID
		col_val_29 TEXT, -- BankAccountNumber
		col_val_30 TEXT, -- CIFNumber
		col_val_31 TEXT, -- LoanAccountNumber
		col_val_32 TEXT, -- InsurancePolicyNumber
		col_val_33 TEXT  -- FASTagID
	);`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Error creating table: %v", err)
	}

	fmt.Println("> Created obfuscated_records table with 33 generic column names")

	// Seed 100 valid PII rows per entity
	_ = rand.New(rand.NewSource(time.Now().UnixNano()))

	insertSQL := `INSERT INTO obfuscated_records (
		col_val_01, col_val_02, col_val_03, col_val_04, col_val_05, col_val_06, col_val_07,
		col_val_08, col_val_09, col_val_10, col_val_11, col_val_12, col_val_13, col_val_14,
		col_val_15, col_val_16, col_val_17, col_val_18, col_val_19, col_val_20, col_val_21,
		col_val_22, col_val_23, col_val_24, col_val_25, col_val_26, col_val_27, col_val_28,
		col_val_29, col_val_30, col_val_31, col_val_32, col_val_33
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33);`

	stmt, err := db.Prepare(insertSQL)
	if err != nil {
		log.Fatalf("Error preparing stmt: %v", err)
	}
	defer stmt.Close()

	// Verhoeff valid Aadhaar generator numbers
	validAadhaars := []string{
		"234567890123", "987654321098", "456789012345", "678901234567",
		"890123456789", "123456789012", "345678901234", "567890123456",
	}

	// Luhn valid Credit Card numbers
	validCards := []string{
		"4532015012345678", "5412755012345678", "4012888888881881", "378282246310005",
		"6011000990139424", "3566002020360931", "4222222222222", "5105105105105100",
	}

	// Mod-36 valid GSTIN numbers
	validGSTINs := []string{
		"27AAAAA0000A1Z5", "07BBBBB1111B1Z2", "29CCCC0000C1Z9", "33DDDDD0000D1Z7",
	}

	for i := 1; i <= 100; i++ {
		email := fmt.Sprintf("user%d@example.com", i)
		pan := fmt.Sprintf("ABCPE%04dF", i)
		aadhaar := validAadhaars[i%len(validAadhaars)]
		card := validCards[i%len(validCards)]
		gstin := validGSTINs[i%len(validGSTINs)]
		ip := fmt.Sprintf("192.168.1.%d", i%250+1)
		mac := fmt.Sprintf("00:1A:2B:3C:%02X:%02X", i%256, (i*3)%256)
		upi := fmt.Sprintf("user%d@okaxis", i)
		cin := fmt.Sprintf("L%05dMH2020PLC%06d", 10000+i, 100000+i)
		token := fmt.Sprintf("ghp_userToken%032d", i)
		epf := fmt.Sprintf("MH/BAN/%07d/000/%07d", i, i+100)
		sebi := fmt.Sprintf("INZ%09d", 100000000+i)
		ifsc := fmt.Sprintf("SBIN000%04d", i%1000)
		abha := fmt.Sprintf("12-%04d-%04d-%04d", 1000+i, 2000+i, 3000+i)
		tan := fmt.Sprintf("ABCD%05dE", i)
		dl := fmt.Sprintf("DL-%02d2020%07d", i%30+1, 1000000+i)
		vehicle := fmt.Sprintf("MH-%02d-AB-%04d", i%50+1, 1000+i)
		phone := fmt.Sprintf("+9198765%05d", 10000+i)
		address := fmt.Sprintf("%d MG Road, Floor %d", i*5, i%10+1)
		gender := []string{"male", "female", "other"}[i%3]
		esic := fmt.Sprintf("11-%02d-%06d-000-%04d", i%50+1, 100000+i, i)
		ration := fmt.Sprintf("MH/%012d", 100000000000+int64(i))
		cvv := fmt.Sprintf("%03d", 100+i%899)
		cheque := fmt.Sprintf("%06d", 100000+i)
		micr := fmt.Sprintf("400002%03d", i%900+100)
		uan := fmt.Sprintf("100%09d", 100000000+i)
		passport := fmt.Sprintf("A%07d", 1000000+i)
		voter := fmt.Sprintf("ABC%07d", 1000000+i)
		bank := fmt.Sprintf("550000000000%04d", i)
		cif := fmt.Sprintf("CIF%08d", 10000000+i)
		loan := fmt.Sprintf("LOAN/2024/%05d", i)
		insurance := fmt.Sprintf("POL%09d", 100000000+i)
		fastag := fmt.Sprintf("NETC%010d", 1000000000+int64(i))

		_, err := stmt.Exec(
			email, pan, aadhaar, card, gstin, ip, mac,
			upi, cin, token, epf, sebi, ifsc, abha,
			tan, dl, vehicle, phone, address, gender, esic,
			ration, cvv, cheque, micr, uan, passport, voter,
			bank, cif, loan, insurance, fastag,
		)
		if err != nil {
			log.Fatalf("Error inserting row %d: %v", i, err)
		}
	}

	fmt.Println("> Successfully seeded 100 rows per entity into noname.obfuscated_records!")
}
