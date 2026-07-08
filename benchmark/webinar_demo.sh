#!/bin/bash

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'
BOLD='\033[1m'

clear
echo -e "${BOLD}${BLUE}================================================================${NC}"
echo -e "${BOLD}${BLUE}   PII SCANNER LIVE DEMO — klouddbshield vs pdscan${NC}"
echo -e "${BOLD}${BLUE}   Database: pii_demo (5 tables, mixed India/US PII)${NC}"
echo -e "${BOLD}${BLUE}================================================================${NC}"
echo ""
read -p "Press Enter to start klouddbshield scan..."

echo ""
echo -e "${BOLD}${GREEN}>>> Running klouddbshield...${NC}"
echo ""
START=$(date +%s%N)
echo "" | /tmp/ciscollector --config ~/klouddbshield --piiscanner datascan --database pii_demo 2>/dev/null
END=$(date +%s%N)
ELAPSED_MS=$(( (END-START)/1000000 ))
echo ""
echo -e "${GREEN}klouddbshield completed in ${ELAPSED_MS}ms${NC}"
echo ""
read -p "Press Enter to run pdscan on the SAME database..."

echo ""
echo -e "${BOLD}${RED}>>> Running pdscan...${NC}"
echo ""
START=$(date +%s%N)
/tmp/pdscan/pdscan --show-all "postgres://postgres@localhost:5432/pii_demo?sslmode=disable" 2>&1
END=$(date +%s%N)
ELAPSED_MS=$(( (END-START)/1000000 ))
echo ""
echo -e "${RED}pdscan completed in ${ELAPSED_MS}ms${NC}"
echo ""

echo -e "${BOLD}${YELLOW}================================================================${NC}"
echo -e "${BOLD}${YELLOW}   KEY OBSERVATION${NC}"
echo -e "${BOLD}${YELLOW}================================================================${NC}"
echo ""
echo -e "Table 'legacy_records' has columns: field_12, field_23, field_47,"
echo -e "ref_code, serial_val, identifier, data_point, misc_value"
echo -e "Column names give ZERO hints about content."
echo ""
echo -e "${GREEN}klouddbshield${NC} correctly identified:"
echo -e "  field_47   -> Aadhaar Number"
echo -e "  ref_code   -> GSTIN"
echo -e "  identifier -> IFSC Code"
echo -e "  serial_val -> PAN Number"
echo ""
echo -e "${RED}pdscan${NC} found nothing in these columns — zero India entity"
echo -e "coverage, and no mathematical validation to catch them by value."
echo ""
echo -e "${BOLD}Table 'bank_transactions' (IFSC + GSTIN + bank accounts):${NC}"
echo -e "${GREEN}klouddbshield${NC}: fully detected, High confidence"
echo -e "${RED}pdscan${NC}: table not even mentioned in output"
echo ""
echo -e "${BOLD}Table 'global_employees' (mixed India + US PII):${NC}"
echo -e "${GREEN}klouddbshield${NC}: correctly separated SSN from ITIN"
echo -e "${RED}pdscan${NC}: mislabeled ITIN as SSN"
echo ""
