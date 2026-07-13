# dpdpascanner — India DPDP Act PII Scanner

[![Go Build](https://github.com/klouddb/DPA_private/actions/workflows/release.yml/badge.svg)](https://github.com/klouddb/DPA_private/actions/workflows/release.yml) [![Go Lint](https://github.com/klouddb/DPA_private/actions/workflows/golangci.yml/badge.svg)](https://github.com/klouddb/DPA_private/actions/workflows/golangci.yml) [![Golang Vulnerability Check](https://github.com/klouddb/DPA_private/actions/workflows/govulncheck.yml/badge.svg)](https://github.com/klouddb/DPA_private/actions/workflows/govulncheck.yml)

A command-line PII (Personally Identifiable Information) scanner for PostgreSQL databases, built for compliance with India's **Digital Personal Data Protection (DPDP) Act 2023**.

Scan one or more PostgreSQL servers and databases for sensitive data — Aadhaar, PAN, GSTIN, bank accounts, credit cards, passports, UPI IDs, driving licences, and **40+ more entity types** — with results in the terminal, log files, and a self-contained HTML report.

---

## What You Get

- **Terminal output** — clean table showing only High confidence findings per database
- **HTML report** — `kshield_pii_report.html` — visual report with tabs for High and Low/Medium confidence findings, pagination, and color-coded labels
- **Log files** — `kshield_pii_highconfidence.log` and `kshield_pii_lowconfidence.log` — full detail for every confidence level
- **Data Scan** — finds PII in actual column values using random sampling (~10% of rows)
- **Meta Scan** — finds PII from column names alone, without reading any data
- **Deep Scan** — like Data Scan but reads all rows, no sampling limit
- **Multi-instance support** — scan multiple PostgreSQL servers and databases in one run

---

## Prerequisites

| Tool | Why | Version |
|------|-----|---------|
| Go | To build and run the scanner | 1.18 or newer |
| PostgreSQL | The database being scanned | Any modern version |
| Git | To clone this repo | Any |
| Python 3 *(optional)* | Only needed to seed test data | 3.8 or newer |

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/klouddb/DPA_private.git
cd DPA_private
```

---

## Step 2 — Create the Config File

Create a file named `config.toml` in the project root. This is where you tell the scanner which PostgreSQL servers and databases to scan.

**Basic example — one server, one database:**
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["my_database"]
```

**Advanced example — multiple servers and databases:**
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "password1"
databases = ["sales_db", "hr_db", "finance_db"]

[[instances]]
host      = "prod-server.example.com"
port      = 5432
user      = "readonly_user"
password  = "password2"
databases = ["production_db"]
```

> `config.toml` is listed in `.gitignore` and will **not** be accidentally committed to Git.

---

## Step 3 — Build the Binary

```bash
# On Linux / Mac
go build -o dpdpascanner ./cmd/

# On Windows
go build -o dpdpascanner.exe ./cmd/
```

This creates the `dpdpascanner` (or `dpdpascanner.exe`) binary in the project root.

---

## Step 4 — Run a Scan

**Scan everything in config.toml (simplest):**
```bash
# Linux / Mac
./dpdpascanner

# Windows
.\dpdpascanner.exe
```

NOTE: Dont forget to attach .exe after "dpdpascanner" in the commands if you are using Windows

**Scan a specific database:**
```bash
.\dpdpascanner --database sales_db
```

**Scan a specific server:**
```bash
.\dpdpascanner --target-host prod-server.example.com
```

**Scan a specific server and database together:**
```bash
.\dpdpascanner --target-host localhost --database hr_db
```

---

## All Available Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `.` (current folder) | Folder containing `config.toml`. Use this if your config file is in a different location. |
| `--piiscanner` | `datascan` | Scan type. Options: `datascan`, `metascan`, `deepscan`. See scan types below. |
| `--database` | *(all databases)* | Scan only this one database. Leave empty to scan all databases in the config. |
| `--schema` | `public` | PostgreSQL schema to scan. Most databases use `public`. |
| `--target-host` | *(all hosts)* | Scan only this one server. Leave empty to scan all servers in the config. |
| `--target-port` | *(all ports)* | Scan only instances on this port. Useful if you have multiple instances on different ports. |
| `--exclude-table` | *(none)* | Comma-separated list of tables to skip. Example: `--exclude-table audit_logs,temp_data` |
| `--include-table` | *(all tables)* | Comma-separated list of tables to scan. All others will be skipped. |
| `--print-all` | `false` | By default, terminal only shows High confidence. Add this flag to also show Medium and Low in the terminal. |
| `--print-summary` | `false` | Print a short summary only, without the full table breakdown. |

---

## Scan Types Explained

### `datascan` *(default)*
Reads actual data from your database columns using random sampling — approximately 10% of rows, up to 10,000 rows per table.

- **Best for:** Detecting PII hidden in columns with generic names (e.g. `field_01`, `ref_b`)
- **How it works:** Scans values and matches against 40+ regex patterns
- **Output:** Data Scan Report + Meta Scan Report

### `metascan`
Only looks at column names — does **not** read any actual data from the database.

- **Best for:** Quick scan, or environments where reading data is restricted
- **How it works:** Matches column names against known PII naming patterns
- **Output:** Meta Scan Report only

### `deepscan`
Same as `datascan` but reads **all rows** with no sampling limit.

- **Best for:** Thorough scan on smaller databases where you want complete coverage
- **Note:** Can be slow on large tables
- **Output:** Data Scan Report + Meta Scan Report

---

## Understanding the Output

### Terminal
Shows only **High confidence** findings after each database scan. Each database is shown in its own section:

```
=== Scanning localhost:5432 / sales_db ===

Data Scan Report
+----------------+----------+-------+------------+----------+---------+
| TABLE          | COLUMN   | LABEL | CONFIDENCE | DETECTOR | MATCHED |
+----------------+----------+-------+------------+----------+---------+
| public.users   | email    | Email | High 🔴    | regex    | 101/101 |
+----------------+----------+-------+------------+----------+---------+

Meta Scan Report
+----------------+----------+----------+------------+
| TABLE          | COLUMN   | LABEL    | CONFIDENCE |
+----------------+----------+----------+------------+
| public.users   | dob      | BirthDate| High 🔴    |
+----------------+----------+----------+------------+

> High confidence log file created at: [ /path/to/kshield_pii_highconfidence.log ]
> Low confidence log file created at:  [ /path/to/kshield_pii_lowconfidence.log ]
> HTML report created at:              [ /path/to/kshield_pii_report.html ]
```

### HTML Report (`kshield_pii_report.html`)
A self-contained HTML file created in the project folder after each scan. Open it in any browser — no internet required.

It contains:
- **Summary cards** — Tables scanned, Data Findings, Meta Findings, Low/Med Data count, Low/Med Meta count
- **High Confidence tab** — Data Scan and Meta Scan tables with pagination
- **Low / Medium Confidence tab** — All lower-confidence findings in the same table format
- **Color-coded labels** — Each PII type has a distinct color badge
- **Matched ratio bar** — Visual bar showing what percentage of rows matched

> **Note:** The HTML report is overwritten each time a scan runs. If you scan multiple databases, the file will contain results from the **last** database scanned. Run with `--database` to target a specific database and keep its report.

### Log Files
Two files are created (or overwritten) after each database scan:

| File | Contents |
|------|----------|
| `kshield_pii_highconfidence.log` | All High confidence findings with full detail |
| `kshield_pii_lowconfidence.log` | All Medium and Low confidence findings |

> Like the HTML report, log files are overwritten per database scan.

---

## PII Entities Detected (40 types)

| Category | Entities |
|----------|----------|
| Identity | Name, Gender, Nationality, Username |
| Contact | Email, Phone, Address, Location |
| Government ID | Aadhaar, PAN, Passport, Voter ID, Driving Licence, Ration Card |
| Financial | Credit Card, CVV, Bank Account, Demat Account, UPI ID, IFSC, MICR Code, Cheque Number, CIF Number |
| Tax & Corporate | GSTIN, TAN, CIN, SEBI Registration |
| Employment | UAN, EPF Member ID, ESIC |
| Healthcare | ABHA Number |
| Transport | Vehicle Number, FASTag ID |
| Loans & Insurance | Loan Account Number, Insurance Policy Number |
| Network | IP Address, MAC Address |
| Auth | Password, OAuth Token |
| Date | Birth Date |

---

## Example Usage Scenarios

**Scan everything, all servers and databases:**
```bash
.\dpdpascanner
```

**Scan only one database on one server:**
```bash
.\dpdpascanner --target-host localhost --database hr_db --piiscanner datascan
```

**Quick scan using column names only (no data read):**
```bash
.\dpdpascanner --piiscanner metascan --database sales_db
```

**Skip audit and temp tables:**
```bash
.\dpdpascanner --exclude-table audit_logs,temp_sessions,migrations
```

**Scan only specific tables:**
```bash
.\dpdpascanner --include-table users,customers,employees
```

**Config file is in a different folder:**
```bash
.\dpdpascanner --config C:\configs\prod --database sales_db
```

**See all confidence levels in terminal (not just High):**
```bash
.\dpdpascanner --print-all --database hr_db
```

**Non-default schema:**
```bash
.\dpdpascanner --schema hr --database company_db
```

---

## Project Structure

```
DPA_private/
├── cmd/
│   └── main.go                  ← CLI entry point, all flags defined here
├── piiscanner/
│   ├── detector.go              ← 40 PII label definitions
│   ├── constants.go             ← Scan type constants, ignore rules
│   ├── database_scanner.go      ← Core scan engine, NewConfig
│   ├── output_helper.go         ← Terminal and log file output
│   ├── html_report.go           ← HTML report generator
│   └── ...
├── benchmark/
│   └── seed_comprehensive.py    ← Seeds test database with 40 entity types
├── config.toml                  ← Your credentials (not in git)
└── go.mod
```

---

## Optional — Seed Test Data

If you want to test the scanner without setting up your own database, run the seed script. It creates a `pii_comprehensive` database with 13 tables, ~10,000 rows each, covering all 40 PII entity types.

```bash
pip install psycopg2-binary
python benchmark/seed_comprehensive.py
```

Then add it to your `config.toml`:
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password"
databases = ["pii_comprehensive"]
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `Failed to load config.toml` | Make sure `config.toml` exists in the folder you are running from, or use `--config` to point to its location |
| `Could not connect` | Check that PostgreSQL is running, and that the host, port, user, and password in `config.toml` are correct |
| `go: command not found` | Go is not installed or not on your system PATH — [install Go](https://go.dev/dl/) |
| Scan takes a long time | Use `--piiscanner metascan` for a faster scan, or `--include-table` to scan only specific tables |
| Terminal shows fewer results than log file | This is expected — terminal shows only the first High confidence entry per column. Full results are always in the log files and HTML report |
| HTML report only has last database | Run with `--database yourdb` to target one database and keep its report |
| `[SKIP] Could not connect` for one instance | Other instances still scan. Fix the credentials for the skipped instance in `config.toml` |
