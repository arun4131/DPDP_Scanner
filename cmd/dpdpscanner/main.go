package main

import (
	"fmt"
	"os"

	"github.com/klouddb/DPA_private/piiscanner"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("DPDP PII Scanner — India DPDP Act 2023 Compliance")
		fmt.Println("Usage: dpdpscanner <database>")
		os.Exit(1)
	}
	fmt.Println("DPDP PII Scanner starting...")
	_ = piiscanner.NewRegexValueDetectorForRegion(piiscanner.RegionIndia)
}
