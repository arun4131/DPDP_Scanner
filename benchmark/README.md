# PII Scanner Benchmark

Reproducible benchmark suite for klouddbshield PII detection.
Tests India DPDP Act 2023 entities and US entities against mathematically valid synthetic data.

## Quick Start

### Run default benchmark (4,200 samples, India entities)
```bash
cd benchmark
go run benchmark_runner.go
```
Expected: ~99.31% accuracy

### Generate large datasets
```bash
python3 benchmark/gen_large_dataset.py
```
Generates:
- `india_large.csv` — 220,000 samples, 11 India entities (seed=2024)
- `us_large.csv` — 120,000 samples, 6 US entities (seed=2124)

### Run India large benchmark
Edit `benchmark_runner.go` line 14: change `benchmark.csv` to `india_large.csv`
```bash
go run benchmark_runner.go
```
Expected: ~99.03% accuracy

### Run US large benchmark
Edit `benchmark_runner.go`:
- Line 14: `benchmark.csv` → `us_large.csv`
- Line 23: `RegionIndia` → `RegionUS`
- Line 31: `RegionIndia` → `RegionUS`
```bash
go run benchmark_runner.go
```
Expected: ~99.67% accuracy

## Files

| File | Description |
|---|---|
| `benchmark.csv` | Reference dataset — 4,200 samples, 8 India entities, seed=42 |
| `benchmark_runner.go` | Go benchmark runner |
| `gen_large_dataset.py` | Generates large India + US datasets |
| `README.md` | This file |

Note: `india_large.csv` and `us_large.csv` are in `.gitignore` — generate them locally using `gen_large_dataset.py`.

## Benchmark Results

| Dataset | Samples | Entities | Accuracy | FP Rate |
|---|---|---|---|---|
| India original (seed=42) | 4,200 | 8 | 99.31% | 0.83% |
| India large (seed=2024) | 220,000 | 11 | 99.03% | 1.27% |
| US large (seed=2124) | 120,000 | 6 | 99.67% | 0.43% |
| **Total** | **344,200** | **17** | **99.22%** | |

## Competitor Comparison (US benchmark, 120,000 samples)

| Tool | Version | US Accuracy | False Positives | India Coverage |
|---|---|---|---|---|
| klouddbshield | current | 99.67% | 372 | 11/11 entities |
| scrubadub | 2.0.1 | 87.48% | 22 | 0/11 entities |
| pdscan | v0.1.9 | ~67% | 18,000+ | 0/11 entities |

## How Test Data is Generated

All samples are synthetically generated with fixed random seeds.

**Positive samples** — mathematically valid:
- Aadhaar: Verhoeff check digit computed
- Credit cards: Luhn check digit computed, real IIN prefixes (Visa/MC/Amex/RuPay)
- GSTIN: mod-36 check digit computed
- SSN: valid area ranges (001-665, 667-899) from SSA specification
- DL: real RTO state codes from MoRTH Transport Portal
- IFSC: real bank codes (SBIN, HDFC, ICIC etc.) + literal 0 at position 5

**Negative samples** — two types:
1. Corrupted look-alikes: valid shape but wrong check digit (Luhn-broken cards, Verhoeff-broken Aadhaar, ZZ state DL, I/O/Q/X passport series)
2. Generic noise: order IDs, dates, invoice codes, hex strings, version strings

## Running Competitor Comparison

```bash
# Install scrubadub
pip3 install scrubadub

# Download pdscan (Mac ARM)
curl -L https://github.com/ankane/pdscan/releases/download/v0.1.9/pdscan-0.1.9-arm64-darwin.zip -o /tmp/pdscan.zip
unzip /tmp/pdscan.zip -d /tmp/pdscan
chmod +x /tmp/pdscan/pdscan

# Run pdscan on US benchmark
/tmp/pdscan/pdscan --show-all file://$(pwd)/benchmark/us_large.csv
```
