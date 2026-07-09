package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/klouddb/DPA_private/piiscanner"
)

var columnContextColumns = map[string]string{
	"BankAccountNumber":     "account_number",
	"ChequeNumber":          "cheque_number",
	"CIFNumber":             "cif_number",
	"LoanAccountNumber":     "loan_account_number",
	"InsurancePolicyNumber": "policy_number",
	"FASTagID":              "fastag_id",
	"CVV":                   "cvv",
	"MICRCode":              "micr_code",
}

func main() {
	file, err := os.Open("india_large.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// value-only detector for all entities
	valDetector := piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
	if err := valDetector.Init(); err != nil {
		log.Fatal(err)
	}

	// column+value scanner only for BankAccount
	bankScanner := piiscanner.NewPiiScanner()
	bankScanner.AddColumnDetector(piiscanner.NewRegexColumnDetectorForRegion(piiscanner.RegionIndia))
	bankScanner.AddValueDetector(piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia))
	if err := bankScanner.Init(); err != nil {
		log.Fatal(err)
	}

	total := 0
	correct := 0
	perLabelTotal := make(map[string]int)
	perLabelCorrect := make(map[string]int)
	fpCount := 0
	fpByLabel := make(map[string]int)

	_, err = reader.Read()
	if err != nil {
		log.Fatal(err)
	}

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}

		value := record[0]
		expected := record[1]

		total++
		perLabelTotal[expected]++

		predicted := "NEG"
		if column, ok := columnContextColumns[expected]; ok {

			label, err := bankScanner.Detect(context.Background(), column, value)
			if err != nil {
				log.Fatal(err)
			}

			if label != "" {
				predicted = string(label)
			}

		} else {

			// use value-only for everything else
			labels, err := valDetector.Detect(context.Background(), value, false)
			if err != nil {
				log.Fatal(err)
			}
			if len(labels) > 0 {
				predicted = string(
					piiscanner.NewPiiLabelMapFromPiiLableWithWeight("regex", labels).GetMax(),
				)
			}
		}

		if predicted == expected {
			correct++
			perLabelCorrect[expected]++
		} else {
			if expected == "NEG" {
				fpByLabel[predicted]++
				if fpCount < 20 {
					fmt.Printf("FALSE POSITIVE: %-25s -> %s\n", value, predicted)
					fpCount++
				}
			}
			if expected == "AdharcardNumber" {
				fmt.Printf("AADHAAR MISS: %-20s -> %s\n", value, predicted)
			}
		}
	}

	fmt.Println("\n========== NEG BREAKDOWN ==========")
	for label, count := range fpByLabel {
		fmt.Printf("%-25s %d\n", label, count)
	}

	fmt.Println("\n========== RESULTS ==========")
	for label, totalCount := range perLabelTotal {
		fmt.Printf("%-25s %4d/%4d\n", label, perLabelCorrect[label], totalCount)
	}
	fmt.Println("-----------------------------")
	fmt.Printf("Overall Accuracy: %.2f%%\n", float64(correct)*100/float64(total))
}
