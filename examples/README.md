# Example dumps

## synthetic-hotel-card.json

A fabricated MIFARE Classic 1K hotel key card. All keys, UIDs, timestamps, and
data are synthetic. No real property's security material is included.

Demonstrates:
- Credential sector identification (sector 1 with unique Key A)
- Card type indicator (0x52 = 'R' for room card)
- 6 audit log records with mod-256 checksums
- Timestamp decoding (seconds from midnight)
- Event type recognition (card programmed, door opened)
- Property master key vs room-specific key pattern
- Unattributed vendor: the synthetic keys are deliberately not in the vendor
  database, and the only match is the factory default Key B, so the report says
  "Unattributed" rather than guessing. Pass `--vendor-keys` with
  `A1B2C3D4E5F6:Example vendor:Hotel lock` to see an attributed report.

Run it:
```
rfid-forensics analyze examples/synthetic-hotel-card.json
rfid-forensics audit examples/synthetic-hotel-card.json
rfid-forensics keys examples/synthetic-hotel-card.json
```
