# Database reproduction: values chunked before detection

This fixture inserts one PostgreSQL row containing short controls and values
longer than 512 bytes in JSON, XML, query-string, Base64, and plain-text forms.
It exercises the real database adapter and scanner pipeline.

## 1. Create and seed a disposable database

Using a local PostgreSQL user with database-creation permission:

```bash
createdb dpdp_chunking_repro
psql -d dpdp_chunking_repro \
  -f benchmark/chunking_database_reproduction/setup.sql
```

If authentication or the port differs, provide them explicitly:

```bash
createdb -h localhost -p 5432 -U postgres dpdp_chunking_repro
psql -h localhost -p 5432 -U postgres -d dpdp_chunking_repro \
  -f benchmark/chunking_database_reproduction/setup.sql
```

The final SQL query prints every value's byte length. All `long_*` fixtures
should be greater than 512 bytes.

## 2. Run the real scanner

Replace the URI credentials when necessary:

```bash
GOCACHE=/tmp/dpdp-scanner-go-cache go run ./cmd \
  --piiscanner deepscan \
  --include-table chunking_document_reproduction \
  --print-all \
  'postgres://postgres:postgres@localhost:5432/dpdp_chunking_repro?sslmode=disable'
```

For a local PostgreSQL role that does not require a password:

```bash
GOCACHE=/tmp/dpdp-scanner-go-cache go run ./cmd \
  --piiscanner deepscan \
  --include-table chunking_document_reproduction \
  --print-all \
  'postgres://localhost:5432/dpdp_chunking_repro?sslmode=disable'
```

## Expected ground truth

| Column | Expected result |
|---|---|
| `short_json_control` | CVV found once with embedded-key context |
| `long_formatted_json` | CVV found once with embedded-key context |
| `short_xml_control` | CVV found once with embedded-key context |
| `long_formatted_xml` | CVV found once with embedded-key context |
| `short_query_control` | CVV found once with embedded-key context |
| `long_query_control` | CVV found once with embedded-key context |
| `short_base64_control` | CVV found once with embedded-key context |
| `long_base64_document` | CVV found once with embedded-key context |
| `long_text_duplicate` | Email matched once for one scanned cell |

## Current buggy behavior to inspect

The most important comparisons are:

1. Short JSON/XML/Base64 controls versus their long equivalents. A long
   structured value may lose its internal `cvv=312` extraction after being
   split into fragments.
2. `long_text_duplicate` contains one cell, but the same Email can be counted
   in multiple chunks. The report may show a match count or accumulated weight
   corresponding to more than one match for one scanned value.
3. `long_query_control` is deliberately longer than 512 bytes but contains no
   whitespace. The current `Chunks` helper generally leaves this value intact,
   proving that the trigger is whitespace-based chunking rather than length
   alone.

Scanner reports are written beneath:

```text
scan_results/dpdp_chunking_repro/
```

## Cleanup

```bash
dropdb dpdp_chunking_repro
```
