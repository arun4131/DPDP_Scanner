# DPDP Scanner — Architecture, Fixes & Phase 2 Fallback Engine Guide

## Table of Contents
1. [System Overview & Detection Pipeline](#1-system-overview--detection-pipeline)
2. [Fix 1: Weight-Merge Confidence Inflation Bug](#2-fix-1-weight-merge-confidence-inflation-bug)
   - [Problem Overview](#problem-overview-1)
   - [Root Cause Breakdown](#root-cause-breakdown-1)
   - [Code Solution](#code-solution-1)
   - [Mathematical Proof & Test Verification](#mathematical-proof--test-verification-1)
3. [Fix 2: Single-Pass Fallback Engine for Obfuscated Columns](#3-fix-2-single-pass-fallback-engine-for-obfuscated-columns)
   - [The Obfuscated Schema Blind Spot](#the-obfuscated-schema-blind-spot)
   - [Architectural Solution: 2-Phase Hybrid Scanner](#architectural-solution-2-phase-hybrid-scanner)
   - [Detailed File-by-File Code Breakdown](#detailed-file-by-file-code-breakdown)
   - [Benchmark Results on Obfuscated Schemas](#benchmark-results-on-obfuscated-schemas)
4. [Fix 3: Phase 1 False-Positive Elimination & Phase 2 Architectural Confidence Cap](#4-fix-3-phase-1-false-positive-elimination--phase-2-architectural-confidence-cap)
   - [Problem Statement & The "Enterprise Reference Code" Issue](#problem-statement--the-enterprise-reference-code-issue)
   - [Root Cause & Why Ambiguous Formats Collide](#root-cause--why-ambiguous-formats-collide)
   - [Architectural Rules & Solutions](#architectural-rules--solutions)
   - [Code Changes in `regex_detector.go` and `database_scanner.go`](#code-changes-in-regex_detectorgo-and-database_scannergo)
   - [Empirical Test Verification](#empirical-test-verification)
5. [Complete Entity Classification Reference Table](#5-complete-entity-classification-reference-table)

---

## 1. System Overview & Detection Pipeline

The **DPDP Scanner** is an enterprise database PII scanning engine designed to detect personal data under India's Digital Personal Data Protection (DPDP) Act.

### How Confidence Scoring Works
The scanner classifies PII findings into 3 confidence buckets based on a calculated `Weight` score ($W \in [0.0, 1.0]$):

| Confidence Label | Color Indicator | Weight Range | Meaning |
|---|---|---|---|
| **High** | 🔴 Red | $W \ge 0.70$ | High certainty PII. Immediate compliance action required. |
| **Medium** | 🟡 Yellow | $0.50 \le W < 0.70$ | Probable PII or obfuscated match needing verification. |
| **Low** | 🔵 Blue | $W < 0.50$ | Low probability match or partial pattern collision. |

---

## 2. Fix 1: Weight-Merge Confidence Inflation Bug

### Problem Overview 1
In earlier versions, when scanning a table column whose name matched a PII pattern (e.g. `bank_account_number`), if **only 1 row out of 10,000** matched the data pattern, the scanner still reported the column as **High Confidence 🔴 (1.0)**.

This caused severe false alarms where a column with `Matched: 1/10000` was flagged at maximum risk.

### Root Cause Breakdown 1
During a scan, the value-match ratio weight is correctly calculated as:
$$\text{finalWeight} = \frac{\text{ValueRegexWeight}}{\text{TotalRowCount}}$$

For 1 match out of 10,000 rows with a value weight of $0.6$:
$$\text{finalWeight} = \frac{0.6}{10000} = 0.00006$$

However, in `piiscanner/database_scanner.go`, the merge logic contained a formula bug:

```go
// ❌ BUGGY CODE (before fix):
if PiiEntitiesForWeightMergeLogic.Contains(label) {
    columnWeight := piiMap.ColumnMap["regex"][label].Weight // e.g. 1.0
    if columnWeight >= 0.4 {
        finalWeight = (columnWeight + 1.0) / 2  // ❌ Hardcoded 1.0 overwrote finalWeight!
    }
}
```

Because `1.0` was hardcoded instead of using the actual calculated `finalWeight`, the equation became:
$$\text{finalWeight} = \frac{1.0 + 1.0}{2} = 1.0 \quad \Rightarrow \quad \text{\textbf{High Confidence 🔴}}$$

### Code Solution 1
**File:** `piiscanner/database_scanner.go` (line 336)

```diff
 if PiiEntitiesForWeightMergeLogic.Contains(label) {
     columnWeight := piiMap.ColumnMap["regex"][label].Weight
     if columnWeight >= 0.4 {
-        finalWeight = (columnWeight + 1.0) / 2
+        finalWeight = (columnWeight + finalWeight) / 2
     }
 }
```

### Mathematical Proof & Test Verification 1
With the fix, the merged weight correctly factors in the row match density:
$$\text{finalWeight} = \frac{1.0 + 0.00006}{2} = 0.50003 \quad \Rightarrow \quad \text{\textbf{Medium Confidence 🟡}}$$

#### Automated Unit Test (`piiscanner/weight_merge_test.go`):
- `1/10,000` matches on `bank_account_number` $\rightarrow$ Result: **0.50003 (Medium 🟡)** ✅
- `90/100` matches on `bank_account_number` $\rightarrow$ Result: **0.77000 (High 🔴)** ✅

---

## 3. Fix 2: Single-Pass Fallback Engine for Obfuscated Columns

### The Obfuscated Schema Blind Spot
To prevent massive false positives during database streaming, ambiguous PII entities (like `BankAccountNumber`, `CVV`, `ChequeNumber`, `UAN`, `MICRCode`) have `RequiresColumnContext: true`. This means their regexes only activate when the column name matches a known keyword.

**The Blind Spot:** If a database used generic column names (`col_01`, `field_x`, `temp_val`, `abc`), the column regex matched nothing. As a result, the scanner **skipped those value regexes completely**, rendering it 100% blind to bank accounts or CVVs stored in obfuscated columns.

---

### Architectural Solution: 2-Phase Hybrid Scanner

We designed a **2-Phase Single-Pass Detection Engine** that achieves full schema coverage with **zero additional SQL queries**:

```
                       DATABASE SCAN (Phase 1)
                                  │
                    Does column name match regex?
                     /                         \
             YES    /                           \   NO
                   /                             \
     Normal Stream Scanner            1. Buffer sample values (max 100)
    (All active regexes run)             in memory (UnrecognizedValues)
                  │                               │
                  └───────────────┬───────────────┘
                                  │
                      EVALUATION (Phase 2)
                                  │
                 Did Phase 1 yield High/Med findings?
                     /                         \
             YES    /                           \   NO (Unrecognized Column)
                   /                             \
           Output Result                2. Execute Fallback Engine
                                       (Test buffered values against
                                        ALL Column-Context entities)
                                                   │
                                          Append Capped Findings
```

---

### Detailed File-by-File Code Breakdown

#### 1. `piiscanner/table_scan_manager.go` (Memory Buffering)
During row streaming in Phase 1, `TableScanManager` buffers up to 100 raw values per column in memory:

```go
type TableScanManager struct {
    // ...
    UnrecognizedValues map[string]map[string][]string // tableName -> columnName -> []sampleValues
    unrecognizedMu     sync.Mutex
}

func (t *TableScanManager) PushValue(input StreamInput) {
    // ...
    t.unrecognizedMu.Lock()
    if t.UnrecognizedValues[input.Tablename] == nil {
        t.UnrecognizedValues[input.Tablename] = make(map[string][]string)
    }
    if len(t.UnrecognizedValues[input.Tablename][input.ColumnName]) < 100 {
        t.UnrecognizedValues[input.Tablename][input.ColumnName] = append(
            t.UnrecognizedValues[input.Tablename][input.ColumnName], input.Value,
        )
    }
    t.unrecognizedMu.Unlock()
}
```

#### 2. `piiscanner/database_scanner.go` (Phase 2 Fallback Execution)
If Phase 1 finishes with zero High or Medium confidence findings for a column, Phase 2 evaluates the 100 buffered values against `fallbackContext`:

```go
if !hasValidMatch {
    sampleVals := d.tableScanManager.UnrecognizedValues[table.TableName][columnName]
    if len(sampleVals) > 0 {
        fallbackDetector := NewRegexValueDetector()
        if err := fallbackDetector.Init(); err == nil {
            fallbackContext := ColumnContext{
                PIILabel_BankAccountNumber:     true,
                PIILabel_ChequeNumber:          true,
                PIILabel_CIFNumber:             true,
                PIILabel_LoanAccountNumber:     true,
                PIILabel_InsurancePolicyNumber: true,
                PIILabel_FASTagID:              true,
                PIILabel_CVV:                   true,
                PIILabel_Phone:                 true,
                PIILabel_MICRCode:              true,
                PIILabel_UAN:                   true,
                PIILabel_VoterID:               true,
                PIILabel_PassportNumber:        true,
                PIILabel_TAN:                   true,
                PIILabel_DrivingLicenceNumber:  true,
            }

            labelHits := make(map[PIILabel]int)
            labelWeights := make(map[PIILabel]float64)

            for _, val := range sampleVals {
                labels, _ := fallbackDetector.Detect(context.TODO(), val, fallbackContext)
                for _, lbl := range labels {
                    labelHits[lbl.PIILabel]++
                    labelWeights[lbl.PIILabel] += lbl.Weight
                }
            }
            // ...
        }
    }
}
```

---

### Benchmark Results on Obfuscated Schemas

Target Database: `obfuscated_pii_test` (Columns `col_01` to `col_07` with non-descriptive names)

| Column | Contents | Baseline (Before) | With Fallback Engine (After) |
|---|---|---|---|
| `col_01` | Bank Account Numbers | ❌ **MISSED (0%)** | ✅ **DETECTED** (`BankAccountNumber` Medium 🟡) |
| `col_02` | CVV Numbers | ❌ **MISSED (0%)** | ✅ **DETECTED** (`CVV` Medium 🟡) |
| `col_03` | Cheque Numbers | ❌ **MISSED (0%)** | ✅ **DETECTED** (`ChequeNumber` Low 🔵) |
| `col_04` | UAN Numbers | ❌ **MISSED (0%)** | ✅ **DETECTED** (`UAN` Medium 🟡) |
| `col_07` | MICR Codes | ❌ **MISSED (0%)** | ✅ **DETECTED** (`MICRCode` Medium 🟡) |

---

## 4. Fix 3: Phase 1 False-Positive Elimination & Phase 2 Architectural Confidence Cap

### Problem Statement & The "Enterprise Reference Code" Issue
In enterprise databases, columns such as `doctor_code`, `agent_code`, `driver_code`, `employee_code`, and `patient_code` store internal tracking identifiers (e.g. `DOC0000001`, `AGT1234567`, `EMP0000001`).

Because the format for `VoterID` is `[A-Z]{3}\d{7}` (3 letters + 7 digits), `doctor_code` matched VoterID regex perfectly. Because VoterID did **not** require column context, Phase 1 evaluated raw value weight (`0.80`).

**Resulting Bug:** 100% of internal reference code columns were misclassified as **VoterID at High Confidence 🔴**.

---

### Root Cause & Why Ambiguous Formats Collide
Formats that consist of generic letter/digit combinations (`3 letters + 7 digits`, `1 letter + 7 digits`, `4 letters + 5 digits + 1 letter`) are structurally ambiguous. They collide with internal company serial codes, SKU numbers, and employee IDs.

---

### Architectural Rules & Solutions

#### Rule 1: Context-Gating Ambiguous Formats (Phase 1 Protection)
`VoterID`, `PassportNumber`, `TAN`, and `DrivingLicence (Sarathi)` are added to `RequiresColumnContext: true`. 
- **Effect:** Phase 1 will **only** evaluate them if the column name explicitly suggests VoterID, Passport, TAN, or Driving Licence. Columns like `doctor_code` or `agent_code` are completely ignored in Phase 1.

#### Rule 2: Architectural Confidence Ceiling (Phase 2 Protection)
When a column name does not match any known PII keyword, Phase 2 guesses PII based purely on data values. 
- **Architectural Policy:** **An unconfirmed guess can NEVER be High Confidence 🔴.**
- **Implementation:** Phase 2 calculates average weight and enforces a hard cap at `0.69` (**Medium 🟡**).

$$\text{Phase 2 Weight} = \min\left(\frac{\sum \text{Weights}}{\text{TotalSamples}}, 0.69\right)$$

---

### Code Changes in `regex_detector.go` and `database_scanner.go`

#### Change 1: Add `RequiresColumnContext: true` in `piiscanner/regex_detector.go`

```go
// piiscanner/regex_detector.go

PIILabel_TAN: {
    {
        Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{4}[0-9]{5}[A-Z]\b`),
        Weight:                0.9,
        Region:                RegionIndia,
        RequiresColumnContext: true, // ✅ Added
    },
},
PIILabel_DrivingLicenceNumber: {
    {
        Regexp:                regexp.MustCompile(`(?i)\b((?:ap|ar|as...)[0-9]{2}[0-9]{11})\b`),
        Weight:                0.9,
        Region:                RegionIndia,
        RequiresColumnContext: true, // ✅ Added
    },
},
PIILabel_VoterID: {
    {
        Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{3}\d{7}\b`),
        Weight:                0.8,
        Region:                RegionIndia,
        RequiresColumnContext: true, // ✅ Added
    },
},
PIILabel_PassportNumber: {
    {
        Regexp:                regexp.MustCompile(`(?i)\b[A-Z][0-9]{7}\b`),
        Weight:                1.0,
        Region:                RegionIndia,
        RequiresColumnContext: true, // ✅ Added
    },
    {
        Regexp:                regexp.MustCompile(`(?i)\b[A-Z]{2}[0-9]{6}\b`),
        Weight:                1.0,
        Region:                RegionIndia,
        RequiresColumnContext: true, // ✅ Added
    },
},
```

#### Change 2: Phase 2 Hard Architectural Cap in `piiscanner/database_scanner.go`

```go
// piiscanner/database_scanner.go (Line 511)

totalSamples := len(sampleVals)
for lbl, hits := range labelHits {
    if hits > 0 {
        // Average weight over sampled values
        avgWeight := labelWeights[lbl] / float64(totalSamples)

        // ✅ HARD ARCHITECTURAL CAP: Phase 2 (unrecognized column name) capped at Medium (0.69)
        if avgWeight >= 0.70 {
            avgWeight = 0.69
        }

        piiDataWithWeight := NewPIIDataWithWeightString(lbl, avgWeight, DetectorType_ValueDetector, "regex")
        piiDataWithWeight.SetScanedValueAndMatchCount(hits, totalSamples)
        output.Data[table.TableName][columnName] = append(output.Data[table.TableName][columnName], *piiDataWithWeight)
    }
}
```

---

### Empirical Test Verification

#### Test Table: `code_identifier_regression_test`

| Column | Sample Value | Baseline Output | Fixed Output | Result Status |
|---|---|---|---|---|
| `doctor_code` | `DOC0000001` | 🔴 **High (VoterID)** | ❌ **No Finding** | ✅ **False Positive Eliminated** |
| `agent_code` | `AGT0000001` | 🔴 **High (VoterID)** | ❌ **No Finding** | ✅ **False Positive Eliminated** |
| `driver_code` | `DRV0000001` | 🔴 **High (VoterID)** | ❌ **No Finding** | ✅ **False Positive Eliminated** |
| `employee_code` | `EMP0000001` | 🔴 **High (VoterID)** | ❌ **No Finding** | ✅ **False Positive Eliminated** |
| `patient_code` | `PAT0000001` | 🔴 **High (VoterID)** | ❌ **No Finding** | ✅ **False Positive Eliminated** |

---

## 5. Complete Entity Classification Reference Table

| Entity Label | Phase 1 Global Scan? | Requires Column Context? | Phase 2 Fallback Scan? | Max Phase 2 Confidence |
|---|---|---|---|---|
| **Email** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **Aadhaar** | ✅ Yes (Verhoeff) | ❌ No | N/A | High 🔴 |
| **CreditCard** | ✅ Yes (Luhn) | ❌ No | N/A | High 🔴 |
| **GSTIN** | ✅ Yes (Mod-36) | ❌ No | N/A | High 🔴 |
| **PAN** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **IFSC** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **CIN** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **ABHA** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **DematAccount** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **VehicleNumber** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **OAuthToken** | ✅ Yes | ❌ No | N/A | High 🔴 |
| **VoterID** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **PassportNumber** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **TAN** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **DrivingLicence (Sarathi)** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **BankAccountNumber** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **CVV** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **ChequeNumber** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **UAN** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **MICRCode** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **CIFNumber** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
| **FASTagID** | ❌ Gated | ✅ **Yes** | ✅ **Yes** | **Medium 🟡 (0.69)** |
