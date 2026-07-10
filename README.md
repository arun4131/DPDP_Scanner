# DPA Private — India DPDP Act PII Scanner

A web-based PII (Personally Identifiable Information) scanner for PostgreSQL databases, built for compliance with India's **Digital Personal Data Protection (DPDP) Act 2023**.

Scan your databases for sensitive data — Aadhaar, PAN, GSTIN, bank accounts, credit cards, passports, and 30+ more entity types — through a clean browser UI with terminal output.

---

## What You Get

- **Browser UI** — pick a server and database, results load automatically
- **Data Scan** — finds PII in actual column values (high confidence)
- **Meta Scan** — finds PII from column names alone
- **Low Confidence** — flags tables with weak PII signals for manual review
- **Terminal output** — full results printed in the server window
- **Log files** — `kshield_pii_highconfidence.log` and `kshield_pii_lowconfidence.log`

---

## Prerequisites

Install these before you start. Each link goes to the official download page.

| Tool | Why | Version |
|------|-----|---------|
| [Go](https://go.dev/dl/) | Runs the backend server | 1.18 or newer |
| [PostgreSQL](https://www.postgresql.org/download/) | The database being scanned | Any modern version |
| [Git](https://git-scm.com/downloads) | To clone this repo | Any |
| [Python 3](https://www.python.org/downloads/) *(optional)* | Only needed to seed test data | 3.8 or newer |

> **Not sure if Go is installed?** Open a terminal and run `go version`. If you see a version number, you're good.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/klouddb/DPA_private.git
cd DPA_private
```

---

## Step 2 — Create the Config File

Create a file named **`config.toml`** in the root of the project (same folder as `go.mod`).

This file tells the scanner which PostgreSQL instances and databases to show in the UI. Your database passwords stay here — they are never sent to the browser.

```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["my_database", "another_database"]
```

**Multiple databases on the same server** — just list them all:
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "your_password_here"
databases = ["db1", "db2", "db3"]
```

**Multiple PostgreSQL servers** — add more `[[instances]]` blocks:
```toml
[[instances]]
host      = "localhost"
port      = 5432
user      = "postgres"
password  = "password1"
databases = ["production_db"]

[[instances]]
host      = "192.168.1.100"
port      = 5433
user      = "admin"
password  = "password2"
databases = ["analytics_db"]
```

> `config.toml` is in `.gitignore` — it will not be accidentally committed.

---

## Step 3 — Run the Server

```bash
go run ./cmd/server/
```

The first run downloads dependencies automatically (may take a minute). You should see:

```
Loaded 1 instance(s) from config.toml
Server running at http://localhost:8080
```

Open **http://localhost:8080** in your browser.

> To use a different port: `PORT=9000 go run ./cmd/server/`

---

## Step 4 — Run a Scan

1. **Select an instance** from the first dropdown (e.g. `localhost:5432`)
2. **Select a database** from the second dropdown

The scan starts automatically. Results appear in three sections:

- **Data Scan** — columns where actual values match PII patterns
- **Meta Scan** — columns whose names suggest PII
- **Low Confidence** — tables with weak signals, flagged for manual review

Full results are also printed in the terminal window where the server is running.

---

## Output Files

After each scan, two log files are written to the folder where you ran the server:

| File | Contents |
|------|----------|
| `kshield_pii_highconfidence.log` | High-confidence findings in table format |
| `kshield_pii_lowconfidence.log` | Medium/low-confidence findings |

---

## Optional — Seed Test Data

If you don't have a database to scan yet, you can create one with realistic fake PII data.

### Install psycopg2 (Python PostgreSQL driver)

```bash
pip install psycopg2-binary
```

### Edit the connection details

Open `benchmark/seed_comprehensive.py` and update the `DB` block near the top to match your PostgreSQL credentials:

```python
DB = {
    "host":     "localhost",
    "port":     5432,
    "user":     "postgres",
    "password": "your_password_here",
}
```

### Run the seed script

```bash
python benchmark/seed_comprehensive.py
```

This automatically creates a database called **`pii_comprehensive`** and populates 13 tables with 10,000 rows each, covering all 30+ India PII entity types (Aadhaar, PAN, GSTIN, credit cards, passports, driving licences, UPI IDs, and more).

Add `pii_comprehensive` to your `config.toml` databases list, then open the UI to scan it.

---

## Project Structure

```
DPA_private/
├── cmd/
│   └── server/
│       └── main.go          ← HTTP server + scan logic
├── piiscanner/              ← Core PII detection engine
├── front/
│   ├── index.html           ← Browser UI
│   ├── scripts/             ← Frontend JS
│   └── styles/              ← CSS
├── benchmark/               ← Scripts to generate test data
├── config.toml              ← Your local config (not in git)
└── go.mod
```

---

## Troubleshooting

**`Failed to load config.toml`**
→ Make sure `config.toml` exists in the project root (same folder as `go.mod`) and is valid TOML.

**`Could not connect to database`**
→ Check that PostgreSQL is running, the host/port/user/password in `config.toml` are correct, and the database name exists.

**Port 8080 already in use**
→ Either stop the other process or use a different port: `PORT=9090 go run ./cmd/server/`

**`go: command not found`**
→ Go is not installed or not on your PATH. Download it from https://go.dev/dl/ and restart your terminal after installing.

**Scan takes a long time**
→ The scanner samples ~10% of rows per table for performance. For very large tables this is expected.
