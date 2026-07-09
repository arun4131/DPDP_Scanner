package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"sort"

	"github.com/klouddb/DPA_private/piiscanner"
)

var columnContextEntities = map[string]string{
	"BankAccountNumber":     "account_number",
	"ChequeNumber":          "cheque_number",
	"CIFNumber":             "cif_number",
	"LoanAccountNumber":     "loan_account_number",
	"InsurancePolicyNumber": "policy_number",
	"FASTagID":              "fastag_id",
	"CVV":                   "cvv",
	"UAN":                   "uan",
}

func main() {
	file, err := os.Open("india_benchmark.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	valDetector := piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
	if err := valDetector.Init(); err != nil {
		log.Fatal(err)
	}

	scanner := piiscanner.NewPiiScanner()
	scanner.AddColumnDetector(piiscanner.NewRegexColumnDetectorForRegion(piiscanner.RegionIndia))
	scanner.AddValueDetector(piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia))
	if err := scanner.Init(); err != nil {
		log.Fatal(err)
	}

	total, correct := 0, 0
	perLabelTotal := make(map[string]int)
	perLabelCorrect := make(map[string]int)
	fpByLabel := make(map[string]int)

	// skip header
	if _, err := reader.Read(); err != nil {
		log.Fatal(err)
	}

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
				sort.Slice(labels, func(i, j int) bool {
					return labels[i].Weight > labels[j].Weight
				})
				predicted = string(labels[0].PIILabel)
			}
		}

		if predicted == expected {
			correct++
			perLabelCorrect[expected]++
		} else if expected == "NEG" && predicted != "NEG" {
			fpByLabel[predicted]++
		}
	}

	fmt.Println("\n========== NEG BREAKDOWN ==========")
	for label, count := range fpByLabel {
		fmt.Printf("%-30s %d\n", label, count)
	}

	fmt.Println("\n========== RESULTS ==========")
	for label, tot := range perLabelTotal {
		fmt.Printf("%-30s %d/%d\n", label, perLabelCorrect[label], tot)
	}
	fmt.Println("-----------------------------")
	fmt.Printf("Overall Accuracy: %.2f%%\n", float64(correct)/float64(total)*100)
}
