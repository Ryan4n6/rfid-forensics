# Vendor key contributions

Place additional vendor key files here. Each file is a plain text dictionary
with one entry per line:

```
KEY_HEX:vendor name:system description
```

Example:
```
A1B2C3D4E5F6:ACME Locks:Hotel lock (property master)
# Comments start with #
```

Load with:
```
rfid-forensics analyze dump.json --vendor-keys vendor_keys/my_keys.txt
```

## Rules for contributing keys

1. Keys must come from **authorized testing** of systems you own or have written
   permission to test. No keys obtained through unauthorized access.
2. Include the vendor name only if you can confirm it through direct observation
   (you know what lock system the card came from).
3. Mark confidence honestly. A key from one property is "possible." A key
   confirmed across multiple properties of the same vendor is "likely."
4. Do not submit keys that are under NDA, embargo, or responsible disclosure.
5. Sanitize: do not include property names, room numbers, or other PII in
   your submission.
