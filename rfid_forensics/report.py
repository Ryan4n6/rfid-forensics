"""Generate forensic reports from card analysis."""

import datetime
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .dump_loader import MfcCard
from .key_fingerprint import KeyAnalysis, UNATTRIBUTED_REASON
from .structure_detect import StructureAnalysis, atqa_value


@dataclass
class ChainOfCustody:
    """Chain of custody metadata."""

    examiner_name: str = ""
    examiner_badge: str = ""
    agency: str = ""
    case_number: str = ""
    evidence_number: str = ""
    date_acquired: str = ""
    acquisition_tool: str = "Proxmark3 (Iceman firmware)"
    acquisition_method: str = "Contactless RF read (ISO 14443-A)"
    write_blocked: bool = False
    notes: str = ""


def generate_report(
    card: MfcCard,
    key_analysis: KeyAnalysis,
    structure: StructureAnalysis,
    custody: Optional[ChainOfCustody] = None,
    output_format: str = "text",
) -> str:
    """Generate a forensic analysis report."""
    if output_format == "text":
        return _generate_text_report(card, key_analysis, structure, custody)
    elif output_format == "json":
        return _generate_json_report(card, key_analysis, structure, custody)
    else:
        raise ValueError(f"Unknown output format: {output_format}")


def _generate_text_report(
    card: MfcCard,
    key_analysis: KeyAnalysis,
    structure: StructureAnalysis,
    custody: Optional[ChainOfCustody],
) -> str:
    lines = []
    w = lines.append
    hr = lambda: w("=" * 72)

    hr()
    w("RFID FORENSICS: CONTACTLESS CARD ANALYSIS REPORT")
    hr()
    w(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z').strip()}")
    w(f"Tool version: rfid-forensics 0.1.0")
    w("")

    # Chain of custody
    if custody:
        w("CHAIN OF CUSTODY")
        w("-" * 40)
        if custody.examiner_name:
            w(f"  Examiner:         {custody.examiner_name}")
        if custody.examiner_badge:
            w(f"  Badge/ID:         {custody.examiner_badge}")
        if custody.agency:
            w(f"  Agency:           {custody.agency}")
        if custody.case_number:
            w(f"  Case Number:      {custody.case_number}")
        if custody.evidence_number:
            w(f"  Evidence Number:  {custody.evidence_number}")
        if custody.date_acquired:
            w(f"  Date Acquired:    {custody.date_acquired}")
        w(f"  Acquisition Tool: {custody.acquisition_tool}")
        w(f"  Method:           {custody.acquisition_method}")
        w(f"  Write Blocked:    {'Yes' if custody.write_blocked else 'No (see notes)'}")
        if custody.notes:
            w(f"  Notes:            {custody.notes}")
        w("")

    # Source file integrity
    w("SOURCE FILE")
    w("-" * 40)
    w(f"  File:    {card.source_file}")
    w(f"  SHA-256: {card.source_hash}")
    w("")

    # Card identification
    w("CARD IDENTIFICATION")
    w("-" * 40)
    w(f"  Type:  {card.card_type}")
    w(f"  UID:   {card.uid}")
    w(f"  ATQA:  {atqa_display(card)}")
    w(f"  SAK:   {card.sak}")
    w(f"  Sectors with data: {', '.join(str(s) for s in structure.data_sectors)}")
    w(f"  Empty sectors:     {len(structure.empty_sectors)} of {card.num_sectors}")
    if structure.card_type_byte:
        w(f"  Card type byte:    {structure.card_type_byte}")
    w("")

    # Vendor fingerprint
    w("VENDOR FINGERPRINT")
    w("-" * 40)
    if key_analysis.vendor_guess:
        w(f"  Probable vendor:  {key_analysis.vendor_guess}")
    else:
        w("  Probable vendor:  Unattributed")
    if key_analysis.system_guess:
        w(f"  Probable system:  {key_analysis.system_guess}")
    w(f"  Unique keys:      {len(key_analysis.unique_keys)}")
    w(f"  Key diversity:    {key_analysis.key_diversity_score:.2f} (0=uniform, 1=all unique)")
    w(f"  Default-key sectors: {key_analysis.default_key_sectors or 'None'}")
    w("")

    if key_analysis.matches:
        w("  Matched keys:")
        for m in key_analysis.matches:
            w(f"    {m.key_hex}: {m.vendor} / {m.system} [{m.confidence}]")
            if m.notes:
                w(f"      {m.notes}")
            sectors = key_analysis.unique_keys.get(m.key_hex, [])
            w(f"      Used in: {', '.join(sectors)}")
        w("")

    if key_analysis.unmatched:
        w("  Unmatched keys (not in vendor database):")
        for k in key_analysis.unmatched:
            sectors = key_analysis.unique_keys.get(k, [])
            w(f"    {k}: {', '.join(sectors)}")
        w("")

    # Data structure
    w("DATA STRUCTURE")
    w("-" * 40)

    if structure.credential_sector is not None:
        w(f"  Credential sector: {structure.credential_sector}")
        w("  (Sector with unique key, likely holds access authorization)")
        w("")

    if structure.data_fields:
        w("  Identified fields:")
        for f in structure.data_fields:
            w(f"    Sector {f.sector}, Block {f.block}, Offset {f.offset}: {f.label}")
            w(f"      Value: {f.value}")
            if f.interpretation:
                w(f"      Interpretation: {f.interpretation}")
        w("")

    # Raw data hex dump of non-empty sectors
    w("  Sector data (non-empty blocks):")
    for sector in structure.data_sectors:
        w(f"    Sector {sector}:")
        for blk in card.sector_data_blocks(sector):
            data = card.blocks.get(blk, b'\x00' * 16)
            if data != b'\x00' * 16:
                hex_str = " ".join(f"{b:02X}" for b in data)
                ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)
                w(f"      Block {blk:2d}: {hex_str}  |{ascii_str}|")
    w("")

    # Audit log
    if structure.has_audit_log:
        w("AUDIT LOG")
        w("-" * 40)
        dup_count = len(structure.audit_records) - structure.distinct_audit_count
        if dup_count:
            w(f"  Records found: {len(structure.audit_records)} "
              f"({structure.distinct_audit_count} distinct, {dup_count} exact duplicate"
              f"{'s' if dup_count > 1 else ''})")
        else:
            w(f"  Records found: {len(structure.audit_records)}")
        if structure.audit_sector is not None:
            w(f"  Primary sector: {structure.audit_sector}")

        lock_ids = set(r.lock_id for r in structure.audit_records)
        if lock_ids:
            w(f"  Lock IDs: {', '.join(f'0x{lid:04X}' for lid in sorted(lock_ids))}")
        w("")

        w("  Timeline:")
        w(f"  {'#':<4}{'Time':<14} {'Event':<6} {'Label':<44} {'Lock':<8}")
        w(f"  {'-'*3} {'-'*14} {'-'*6} {'-'*44} {'-'*8}")

        for i, r in enumerate(structure.audit_records):
            time_str = r.timestamp_guess or f"counter={r.counter}"
            label = r.event_label or f"Unknown (0x{r.event_type:02X})"
            chk = "OK" if r.checksum_valid else "BAD"
            dup = f"  DUP of [{r.duplicate_of}]" if r.duplicate_of is not None else ""
            w(f"  [{i}] {time_str:<14} 0x{r.event_type:02X}   {label:<44} 0x{r.lock_id:04X}  [{chk}]{dup}")

        w("")
        w("  NOTE: Timestamps are heuristic. 'Seconds from midnight' is the most")
        w("  common encoding for hotel locks, but the base date must be corroborated")
        w("  with external evidence (folio, PMS logs, or lock audit download).")
        w("")

        w("  Raw audit records:")
        for i, r in enumerate(structure.audit_records):
            hex_str = " ".join(f"{b:02X}" for b in r.raw)
            dup = f"  (duplicate of [{r.duplicate_of}])" if r.duplicate_of is not None else ""
            w(f"    [{i}] Block {r.block}+{r.offset}: {hex_str}  checksum={'valid' if r.checksum_valid else 'INVALID'}{dup}")
        w("")

    elif structure.audit_records:
        w("POSSIBLE AUDIT DATA")
        w("-" * 40)
        w(f"  {len(structure.audit_records)} record(s) with valid checksums found,")
        w("  but fewer than 2 records, so audit log status is uncertain.")
        w("")

    # Forensic notes
    w("FORENSIC NOTES")
    w("-" * 40)

    notes = _generate_forensic_notes(card, key_analysis, structure)
    for note in notes:
        w(f"  - {note}")
    w("")

    # Investigative leads
    w("INVESTIGATIVE LEADS")
    w("-" * 40)
    leads = _generate_leads(card, key_analysis, structure)
    for lead in leads:
        w(f"  - {lead}")
    w("")

    hr()
    w("END OF REPORT")
    hr()

    return "\n".join(lines)


def atqa_display(card: MfcCard) -> str:
    """Raw ATQA as stored plus its decoded value, so the byte order is never ambiguous."""
    val = atqa_value(card.atqa)
    return f"{card.atqa} (ATQA 0x{val:04X})" if val is not None else card.atqa


def _is_hotel(key_analysis: KeyAnalysis) -> bool:
    # "Property", "room" and "folio" language is only earned by a hotel attribution;
    # otherwise the report speaks about a generic site or system.
    return bool(key_analysis.vendor_guess) and "hotel" in (key_analysis.system_guess or "").lower()


def _generate_forensic_notes(card, key_analysis, structure):
    notes = []

    if key_analysis.vendor_guess:
        notes.append(
            f"Key pattern matches {key_analysis.vendor_guess}. This is a heuristic match "
            f"based on known key databases, not a vendor confirmation."
        )
    else:
        notes.append(UNATTRIBUTED_REASON)

    if key_analysis.default_key_sectors:
        notes.append(
            f"Sectors {key_analysis.default_key_sectors} use factory default keys (FFFFFFFFFFFF). "
            f"This may indicate unused sectors or a misconfigured system."
        )

    master_keys = [
        (k, locs) for k, locs in key_analysis.unique_keys.items()
        if len(locs) > card.num_sectors // 2 and k != "FFFFFFFFFFFF"
    ]
    if master_keys:
        for k, locs in master_keys:
            scope = (
                "This is likely a property-wide master key. Other cards from the same property "
                "will likely share it"
                if _is_hotel(key_analysis) else
                "This is likely a site-wide key. Other cards issued by the same system "
                "will likely share it"
            )
            notes.append(
                f"Key {k} appears in {len(locs)} of {card.num_sectors * 2} key slots. "
                f"{scope}, which allows reading them without key recovery."
            )

    if structure.audit_records:
        # Every listed record passes the checksum because passing it is how records are
        # found, so the note must not present that as an integrity result.
        rejected = structure.checksum_rejected
        notes.append(
            "Audit records were identified by a mod-256 checksum (sum of bytes 0 to 6 equals "
            "byte 7). Every listed record passes it by construction"
            + (f"; {rejected} other non-zero 8-byte chunk{'s' if rejected != 1 else ''} in the "
               f"data sectors did not and {'are' if rejected != 1 else 'is'} not treated as "
               f"audit data" if rejected else "")
            + ". A random 8-byte chunk passes by chance about 1 time in 256, so the checksum "
            "identifies the record format but is not proof that the data was unaltered. "
            "The SHA-256 above fixes the dump file's contents from the time of analysis; "
            "it does not attest to the card's state before acquisition."
        )

    for i, r in enumerate(structure.audit_records):
        if r.duplicate_of is not None:
            notes.append(
                f"Audit record [{i}] is a byte-for-byte duplicate of record [{r.duplicate_of}] "
                f"(same lock, counter, event, and parameter). This is consistent with the lock "
                f"writing the same entry twice, not with a second entry. Count it as one event "
                f"unless the lock's own audit download shows two."
            )

    cred_blk = card.blocks.get(1, b'\x00' * 16)
    if cred_blk != b'\x00' * 16:
        notes.append(
            "The authorization credential (sector 0, block 1) is opaque. The room number "
            "is NOT stored in plaintext on the card. The lock knows its own room assignment "
            "and validates the credential against its internal table. This is a security-positive "
            "design: editing the card data cannot redirect it to a different room."
        )

    notes.append(
        "MIFARE Classic 1K uses the Crypto-1 cipher, which is broken. Any card using "
        "this chip can be fully read and cloned with commodity hardware ($30 Proxmark3 Easy). "
        "The card's security depends entirely on the lock's online/offline validation model."
    )

    return notes


def _generate_leads(card, key_analysis, structure):
    leads = []

    if key_analysis.vendor_guess and "hotel" in (key_analysis.system_guess or "").lower():
        leads.append(
            "Hotel key card. The property's front desk system will have the guest folio "
            "(name, dates, room number, payment) tied to this card's UID or encoding session."
        )
        leads.append(
            "Subpoena the property management system (PMS) and lock audit trail. "
            "Common hotel lock platforms (Dormakaba System 6000, ASSA ABLOY Visionline, "
            "Onity HT) retain hundreds to thousands of events per lock."
        )

    if structure.has_audit_log:
        lock_ids = set(r.lock_id for r in structure.audit_records)
        for lid in lock_ids:
            leads.append(
                f"Lock ID 0x{lid:04X} can be cross-referenced with the property's lock "
                f"inventory to determine the physical room/door number."
                if _is_hotel(key_analysis) else
                f"Lock ID 0x{lid:04X} can be cross-referenced with the site's lock or reader "
                f"inventory to determine the physical door."
            )

        events = [r for r in structure.audit_records if r.timestamp_guess and r.duplicate_of is None]
        if events:
            leads.append(
                f"Card shows {len(events)} distinct timestamped events. Cross-reference with "
                f"surveillance footage, access logs, and guest folio to build a timeline."
            )

    master_keys = [
        k for k, locs in key_analysis.unique_keys.items()
        if len(locs) > card.num_sectors // 2 and k != "FFFFFFFFFFFF"
    ]
    if master_keys:
        if _is_hotel(key_analysis):
            leads.append(
                f"Property master key ({master_keys[0]}) is likely shared by every card "
                f"this property issues. Additional cards from this property can likely be "
                f"read with it without running key recovery attacks."
            )
        else:
            leads.append(
                f"Site-wide key ({master_keys[0]}) is likely shared by other cards from the "
                f"same system. Try it first on related cards before running key recovery attacks."
            )

    return leads


def _generate_json_report(card, key_analysis, structure, custody):
    import json

    atqa_int = atqa_value(card.atqa)
    report = {
        "tool": "rfid-forensics",
        "version": "0.1.0",
        "generated": datetime.datetime.now().isoformat(),
        "source": {
            "file": card.source_file,
            "sha256": card.source_hash,
        },
        "card": {
            "type": card.card_type,
            "uid": card.uid,
            "atqa": card.atqa,
            "atqa_value": f"0x{atqa_int:04X}" if atqa_int is not None else None,
            "sak": card.sak,
            "sectors_with_data": structure.data_sectors,
            "empty_sectors": len(structure.empty_sectors),
        },
        "vendor": {
            "guess": key_analysis.vendor_guess,
            "system": key_analysis.system_guess,
            # startswith("") matches everything, so a null guess must short-circuit.
            "confidence": next(
                (m.confidence for m in key_analysis.matches if m.vendor.startswith(key_analysis.vendor_guess)),
                None,
            ) if key_analysis.vendor_guess else None,
            "reason": None if key_analysis.vendor_guess else UNATTRIBUTED_REASON,
        },
        "keys": {
            "unique_count": len(key_analysis.unique_keys),
            "diversity": key_analysis.key_diversity_score,
            "matched": [
                {"key": m.key_hex, "vendor": m.vendor, "system": m.system, "confidence": m.confidence}
                for m in key_analysis.matches
            ],
            "unmatched": key_analysis.unmatched,
        },
        "audit_log": {
            "present": structure.has_audit_log,
            "record_count": len(structure.audit_records),
            "distinct_count": structure.distinct_audit_count,
            "records": [
                {
                    "index": i,
                    "lock_id": f"0x{r.lock_id:04X}",
                    "time": r.timestamp_guess,
                    "event_type": f"0x{r.event_type:02X}",
                    "event_label": r.event_label,
                    "checksum_valid": r.checksum_valid,
                    "raw_hex": r.raw.hex(),
                    "duplicate_of": r.duplicate_of,
                }
                for i, r in enumerate(structure.audit_records)
            ],
        },
    }

    if custody:
        report["chain_of_custody"] = {
            "examiner": custody.examiner_name,
            "badge": custody.examiner_badge,
            "agency": custody.agency,
            "case_number": custody.case_number,
            "evidence_number": custody.evidence_number,
            "date_acquired": custody.date_acquired,
            "tool": custody.acquisition_tool,
            "method": custody.acquisition_method,
            "write_blocked": custody.write_blocked,
        }

    return json.dumps(report, indent=2)
