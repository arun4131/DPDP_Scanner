package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"

	"github.com/klouddb/DPA_private/piiscanner"
)

// entities that need column context to detect by value
var columnContextEntities = map[string]string{
	"BankAccountNumber":      "account_number",
	"ChequeNumber":           "cheque_number",
	"CIFNumber":              "cif_number",
	"LoanAccountNumber":      "loan_account_number",
	"InsurancePolicyNumber":  "policy_number",
	"FASTagID":               "fastag_id",
	"CVV":                    "cvv",
}

func main() {
	file, err := os.Open("india_benchmark.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// value-only detector
	valDetector := piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
	if err := valDetector.Init(); err != nil {
		log.Fatal(err)
	}

	// column+value scanner for ambiguous entities
	scanner := piiscanner.NewPiiScanner()
	scanner.AddColumnDetector(piiscanner.NewRegexColumnDetectorForRegion(piiscanner.RegionIndia))
	scanner.AddValueDetector(piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia))
	if err := scanner.Init(); err != nil {
		log.Fatal(err)
	}

	total, correct, fpCount := 0, 0, 0
	perLabelTotal := make(map[string]int)
	perLabelCorrect := make(map[string]int)
	fpByLabel := make(map[string]int)

	// skip header
	reader.Read()

	for {
		record, err := reader.Read()
		if err != nil {
			break
		}
		value, expected := record[0], record[1]
		total++
		perLabelTotal[expected]++

		predicted := "NEG"

		if col, ok := columnContextEntities[expected]; ok {
			label, err := scanner.Detect(context.Background(), col, value)
			if err != nil {
				log.Fatal(err)
			}
			if label != "" {
				predicted = string(label)
			}
		} else {
			labels, err := valDetector.Detect(context.Background(), value, false)
			if err != nil {
				log.Fatal(err)
			}
			if len(labels) > 0 {
				predicted = string(labels[0].PIILabel)
			}
		}

		if predicted == expected {
			correct++
			perLabelCorrect[expected]++
		} else if expected == "NEG" && predicted != "NEG" {
			fpCount++
			fpByLabel[predicted]++
		}
	}

	// Print false positives
	for label, count := range fpByLabel {
		fmt.Printf("FALSE POSITIVE: %-30s -> %s (%d)\n", "NEG", label, count)
	}

	fmt.Println("\n========== NEG BREAKDOWN ==========")
	for label, count := range fpByLabel {
		fmt.Printf("%-30s %d\n", label, count)
	}

	fmt.Println("\n========== RESULTS ==========")
	for label, tot := range perLabelTotal {
		if label == "NEG" {
			fmt.Printf("%-30s %d/%d\n", label, perLabelCorrect[label], tot)
		} else {
			fmt.Printf("%-30s %d/%d\n", label, perLabelCorrect[label], tot)
		}
	}
	fmt.Println("-----------------------------")
	fmt.Printf("Overall Accuracy: %.2f%%\n", float64(correct)/float64(total)*100)
}
