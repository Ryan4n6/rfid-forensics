# rfid-forensics

Forensic analysis tool for HF contactless smart cards. Takes a Proxmark3 dump file and tells you what the data means: who made the lock system, what the card was used for, and when.

Built for law enforcement digital forensics. No existing tool does this.

## What it does

- **Vendor fingerprinting**: Matches key patterns against a database of known lock vendors, transit systems, and access control manufacturers
- **Audit log detection**: Finds timestamped event records (door opens, card programs, failures) with automatic checksum validation
- **Timestamp decoding**: Heuristic decode of counter fields as wall-clock times
- **Credential identification**: Identifies which sector holds the access authorization token
- **Chain of custody**: Full examiner metadata, SHA-256 file hashing, acquisition method documentation
- **Dump comparison**: Diff two cards from the same property to isolate per-card vs shared fields
- **Court-ready output**: Plain language report with raw hex evidence, or structured JSON for case management systems

## Install

```
pip install -e .
```

Requires Python 3.10+. No external dependencies for core functionality.

## Usage

### Full forensic analysis

```
rfid-forensics analyze dump.json
rfid-forensics analyze dump.bin --format json
rfid-forensics analyze dump.json -o report.txt
```

### With chain of custody

```
rfid-forensics analyze dump.json \
  --examiner "Det. J. Smith" \
  --badge "4521" \
  --agency "Orlando PD" \
  --case "2026-CR-4419" \
  --evidence "EV-007" \
  --acquired "2026-03-29 10:15 EST"
```

### Quick key check

```
rfid-forensics keys dump.json
```

### Audit log only

```
rfid-forensics audit dump.json
```

### Compare two cards

```
rfid-forensics diff card_a.json card_b.json
```

### Raw hex dump

```
rfid-forensics hexdump dump.json
```

## Supported formats

- Proxmark3 JSON dumps (`.json`, from `hf mf autopwn` or `hf mf dump`)
- Raw binary dumps (`.bin`, `.mfd`, `.dump`, 1024 or 4096 bytes)

## Vendor key database

The tool ships with known keys for:

- **Dormakaba/Saflok** (hotel locks)
- **NXP factory defaults** and MAD keys
- **HID iCLASS SE** (access control)
- **Transit systems** (various)
- **Vending/payment** systems

Add your own keys with `--vendor-keys file.txt` (format: `KEY_HEX:vendor:system` per line).

## How it works

A hotel key card recovered during a search warrant execution currently tells the investigator nothing without specialized knowledge. This tool bridges that gap:

1. **Triage**: Card recovered at scene. Examiner runs `rfid-forensics analyze dump.json`. Report says "Dormakaba/Saflok hotel lock, 6 door events between 15:33 and 16:18, lock ID 0xAE43."

2. **Corroboration**: Investigator subpoenas the hotel PMS and lock audit trail. Card's onboard audit log provides independent corroboration of server-side records.

3. **Lead generation**: Property master key identified. Additional cards from the same property can be read without running key recovery attacks.

## Limitations

- Timestamps are heuristic. "Seconds from midnight" is the most common hotel lock encoding, but the base date must be corroborated with external evidence.
- Vendor fingerprinting is based on known key patterns, not vendor confirmation. Keys can be reused across vendors.
- MIFARE Classic 1K/4K only. DESFire, MIFARE Plus, and NTAG support planned.
- Room numbers are not stored in plaintext on properly designed hotel cards. The tool identifies the credential token but cannot decode it without the lock's key table.

## For examiners

**Write blocking**: MIFARE Classic reads are non-destructive. The Proxmark3 in reader mode does not modify card data. However, the card's internal counter may increment on some implementations. Document this in your acquisition notes.

**Reproducibility**: The SHA-256 hash of the dump file is included in every report. Re-running the tool on the same dump file will produce identical analysis (timestamps in the report header will differ).

**Testimony**: The report's "Forensic Notes" section explains the basis for each conclusion. The "Investigative Leads" section suggests follow-up actions. Both are written for non-technical audiences.

## License

Apache 2.0
