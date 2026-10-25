"""Detect data structures, audit logs, and repeating records in card dumps."""

import logging
from dataclasses import dataclass, field
from typing import Optional

from .dump_loader import MfcCard

log = logging.getLogger(__name__)


@dataclass
class AuditRecord:
    """A single parsed audit log entry."""

    sector: int
    block: int
    offset: int
    raw: bytes
    lock_id: int
    counter: int
    event_type: int
    param: int
    checksum: int
    checksum_valid: bool
    timestamp_guess: Optional[str] = None
    event_label: Optional[str] = None
    # Index of the first byte-identical record; None if this record is unique.
    duplicate_of: Optional[int] = None


@dataclass
class DataField:
    """A detected data field in a block."""

    sector: int
    block: int
    offset: int
    length: int
    label: str
    raw: bytes
    value: str
    interpretation: str = ""


@dataclass
class StructureAnalysis:
    """Full structural analysis of card data."""

    data_sectors: list[int]
    empty_sectors: list[int]
    audit_records: list[AuditRecord]
    data_fields: list[DataField]
    card_type_byte: Optional[str] = None
    has_audit_log: bool = False
    audit_sector: Optional[int] = None
    credential_sector: Optional[int] = None
    distinct_audit_count: int = 0
    # Non-zero 8-byte chunks in data sectors that failed the checksum.
    checksum_rejected: int = 0


# Known hotel lock event types (from Caribe Royale decode and published research)
EVENT_TYPES = {
    0x24: "Door opened (guest entry)",
    0x26: "Card programmed (front desk encode)",
    0x64: "Programming confirmed (lock acknowledgment)",
    0x25: "Door opened (staff/master)",
    0x01: "Lock initialized",
    0x02: "Battery warning",
    0x03: "Deadbolt thrown",
    0x04: "Deadbolt retracted",
    0x10: "Failed entry attempt",
    0x11: "Card expired",
    0x12: "Card cancelled",
    0x20: "Emergency override",
}


def verify_checksum_mod256(record: bytes) -> bool:
    """Verify checksum as sum of bytes 0 to 6, mod 256."""
    if len(record) < 8:
        return False
    expected = sum(record[:7]) % 256
    return expected == record[7]


def detect_audit_records(card: MfcCard) -> list[AuditRecord]:
    """Detect 8-byte audit records with mod-256 checksums in data sectors."""
    return scan_audit_chunks(card)[0]


def scan_audit_chunks(card: MfcCard) -> tuple[list[AuditRecord], int]:
    """Return (audit records, count of non-zero chunks that failed the checksum)."""
    records = []
    rejected = 0

    for sector in card.data_sectors():
        for blk in card.sector_data_blocks(sector):
            data = card.blocks.get(blk, b'\x00' * 16)
            if data == b'\x00' * 16:
                continue

            for offset in range(0, len(data) - 7, 8):
                chunk = data[offset:offset + 8]
                if chunk == b'\x00' * 8:
                    continue

                if not verify_checksum_mod256(chunk):
                    rejected += 1
                    log.debug("block %d+%d %s failed mod-256 checksum, not an audit record",
                              blk, offset, chunk.hex())
                    continue

                lock_id = int.from_bytes(chunk[0:2], "big")
                counter = int.from_bytes(chunk[2:4], "big")
                event_type = chunk[4]
                param = int.from_bytes(chunk[5:7], "big")
                checksum = chunk[7]

                record = AuditRecord(
                    sector=sector,
                    block=blk,
                    offset=offset,
                    raw=chunk,
                    lock_id=lock_id,
                    counter=counter,
                    event_type=event_type,
                    param=param,
                    checksum=checksum,
                    checksum_valid=True,
                    event_label=EVENT_TYPES.get(event_type),
                )
                records.append(record)
                log.debug("audit record at block %d+%d: lock=0x%04X counter=%d event=0x%02X",
                          blk, offset, lock_id, counter, event_type)

    log.info("audit scan: %d record(s) accepted, %d non-zero chunk(s) failed checksum",
             len(records), rejected)
    return records, rejected


def flag_duplicate_records(records: list[AuditRecord]) -> list[AuditRecord]:
    """Mark records that are byte-identical to an earlier record."""
    # Same lock, same second, same event and param is far more consistent with
    # the lock re-writing a slot than with two entries, so the duplicate stays
    # visible but is not counted as a separate event.
    first_seen: dict[bytes, int] = {}
    for i, r in enumerate(records):
        if r.raw in first_seen:
            r.duplicate_of = first_seen[r.raw]
            log.info("record [%d] is a duplicate of [%d] (%s)", i, r.duplicate_of, r.raw.hex())
        else:
            first_seen[r.raw] = i
    return records


def try_timestamp_decode(records: list[AuditRecord]) -> list[AuditRecord]:
    """Attempt to decode counter values as timestamps.

    Heuristic: if counters are monotonically non-decreasing and fall
    within plausible ranges for seconds-from-midnight (0 to 86400),
    treat them as wall-clock times.
    """
    if not records:
        return records

    counters = [r.counter for r in records]

    if all(0 <= c <= 86400 for c in counters):
        is_monotonic = all(counters[i] <= counters[i + 1] for i in range(len(counters) - 1))
        if is_monotonic or len(records) == 1:
            log.info("timestamp heuristic: seconds from midnight (%d record(s), monotonic)", len(records))
            for r in records:
                hours = r.counter // 3600
                minutes = (r.counter % 3600) // 60
                seconds = r.counter % 60
                if hours < 24:
                    r.timestamp_guess = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    r.timestamp_guess = f"{r.counter}s from midnight (>{hours}h, unusual)"

        else:
            log.info("timestamp heuristic: none, counters in day range but not monotonic")

    elif all(0 <= c <= 86400 * 365 for c in counters):
        log.info("timestamp heuristic: seconds from epoch, base unknown (%d record(s))", len(records))
        for r in records:
            days = r.counter // 86400
            rem = r.counter % 86400
            hours = rem // 3600
            minutes = (rem % 3600) // 60
            r.timestamp_guess = f"Day {days}, {hours:02d}:{minutes:02d} (seconds from epoch?)"

    else:
        log.info("timestamp heuristic: none, counters exceed one year of seconds")

    return records


def detect_card_type_field(card: MfcCard) -> Optional[str]:
    """Check for card type indicator in sector 0, block 2."""
    blk2 = card.blocks.get(2, b'\x00' * 16)
    if blk2[0] != 0x00:
        char = chr(blk2[0]) if 0x20 <= blk2[0] <= 0x7E else None
        if char:
            return f"0x{blk2[0]:02X} (ASCII '{char}')"
        return f"0x{blk2[0]:02X}"
    return None


def detect_credential_sector(card: MfcCard) -> Optional[int]:
    """Identify which sector likely holds the room/access credential.

    Heuristic: the sector with a unique Key A (different from the
    property master key) on a data sector that contains non-zero data.
    """
    key_counts: dict[str, int] = {}
    for sector in range(card.num_sectors):
        ka = card.sector_keys.get(sector, {}).get("KeyA", "").upper()
        if ka and ka != "FFFFFFFFFFFF":
            key_counts[ka] = key_counts.get(ka, 0) + 1

    if not key_counts:
        log.info("credential sector: none, every Key A is default or missing")
        return None

    master_key = max(key_counts, key=key_counts.get)

    for sector in card.data_sectors():
        ka = card.sector_keys.get(sector, {}).get("KeyA", "").upper()
        if ka and ka != master_key and ka != "FFFFFFFFFFFF":
            log.info("credential sector: %d (Key A %s differs from master %s)", sector, ka, master_key)
            return sector

    log.info("credential sector: none, no data sector has a Key A other than master %s", master_key)
    return None


def analyze_data_fields(card: MfcCard) -> list[DataField]:
    """Extract and label known data fields."""
    fields = []

    blk0 = card.blocks.get(0, b'\x00' * 16)
    fields.append(DataField(
        sector=0, block=0, offset=0, length=4,
        label="UID", raw=blk0[:4],
        value=blk0[:4].hex().upper(),
        interpretation=f"Card UID: {blk0[:4].hex().upper()}",
    ))
    fields.append(DataField(
        sector=0, block=0, offset=4, length=1,
        label="BCC", raw=blk0[4:5],
        value=f"0x{blk0[4]:02X}",
        interpretation="Block Check Character (XOR of UID bytes)",
    ))
    fields.append(DataField(
        sector=0, block=0, offset=5, length=1,
        label="SAK", raw=blk0[5:6],
        value=f"0x{blk0[5]:02X}",
        interpretation=_interpret_sak(blk0[5]),
    ))
    fields.append(DataField(
        sector=0, block=0, offset=6, length=2,
        label="ATQA", raw=blk0[6:8],
        value=blk0[6:8].hex().upper(),
        interpretation=_interpret_atqa(blk0[6:8]),
    ))

    blk1 = card.blocks.get(1, b'\x00' * 16)
    if blk1 != b'\x00' * 16:
        fields.append(DataField(
            sector=0, block=1, offset=0, length=16,
            label="Authorization credential",
            raw=blk1,
            value=blk1.hex().upper(),
            interpretation="Opaque credential token (not a room number). Lock uses this to authorize entry.",
        ))

    card_type = detect_card_type_field(card)
    if card_type:
        blk2 = card.blocks.get(2, b'\x00' * 16)
        fields.append(DataField(
            sector=0, block=2, offset=0, length=1,
            label="Card type indicator",
            raw=blk2[:1],
            value=card_type,
            interpretation=f"Card type byte: {card_type}",
        ))

    return fields


def _interpret_sak(sak: int) -> str:
    sak_map = {
        0x08: "MIFARE Classic 1K",
        0x09: "MIFARE Mini",
        0x10: "MIFARE Plus 2K (SL2)",
        0x11: "MIFARE Plus 4K (SL2)",
        0x18: "MIFARE Classic 4K",
        0x19: "MIFARE Classic 2K (not officially supported)",
        0x20: "MIFARE Plus / DESFire / JCOP (ISO 14443-4 capable)",
        0x28: "JCOP / SmartMX",
        0x38: "MIFARE Classic 4K (emulated)",
        0x88: "MIFARE Classic 1K (Infineon clone)",
        0x98: "MIFARE Pro (NXP)",
    }
    return sak_map.get(sak, f"Unknown SAK 0x{sak:02X}")


def atqa_value(raw_hex: str) -> Optional[int]:
    """ATQA as an integer from its stored (LSB first) hex, or None if unparseable."""
    try:
        raw = bytes.fromhex(raw_hex)
    except ValueError:
        return None
    return int.from_bytes(raw, "little") if len(raw) == 2 else None


def _interpret_atqa(atqa: bytes) -> str:
    # ATQA goes over the air LSB first and block 0 stores it in that order,
    # so the bytes 04 00 are ATQA 0x0004.
    val = int.from_bytes(atqa, "little")
    # ATQA cannot tell NXP silicon from a clone, so labels name the card class only.
    atqa_map = {
        0x0004: "MIFARE Classic 1K",
        0x0002: "MIFARE Classic 4K",
        0x0044: "MIFARE Classic 1K, Ultralight, or NTAG",
        0x0042: "MIFARE Classic 4K",
        0x0344: "MIFARE DESFire",
    }
    # Bits 7 to 6 of the low byte encode UID size (ISO 14443-3).
    uid_size = {0: "4-byte UID", 1: "7-byte UID", 2: "10-byte UID"}.get(
        (val >> 6) & 0x3, "reserved UID size bits")
    label = atqa_map.get(val)
    if label:
        return f"ATQA 0x{val:04X}: consistent with {label}, {uid_size}"
    return f"ATQA 0x{val:04X}: unrecognized, {uid_size}"


def analyze_structure(card: MfcCard) -> StructureAnalysis:
    """Full structural analysis of a card dump."""
    data_secs = card.data_sectors()
    all_secs = list(range(card.num_sectors))
    empty_secs = [s for s in all_secs if s not in data_secs]

    audit_records, rejected = scan_audit_chunks(card)
    audit_records = try_timestamp_decode(audit_records)
    audit_records = flag_duplicate_records(audit_records)
    distinct = sum(1 for r in audit_records if r.duplicate_of is None)

    # Two copies of one record is not a log, so presence is judged on distinct records.
    has_audit = distinct >= 2
    log.info("audit log present=%s (%d record(s), %d distinct)", has_audit, len(audit_records), distinct)
    audit_sector = None
    if audit_records:
        sector_counts: dict[int, int] = {}
        for r in audit_records:
            sector_counts[r.sector] = sector_counts.get(r.sector, 0) + 1
        audit_sector = max(sector_counts, key=sector_counts.get)

    data_fields = analyze_data_fields(card)
    card_type = detect_card_type_field(card)
    cred_sector = detect_credential_sector(card)

    return StructureAnalysis(
        data_sectors=data_secs,
        empty_sectors=empty_secs,
        audit_records=audit_records,
        data_fields=data_fields,
        card_type_byte=card_type,
        has_audit_log=has_audit,
        audit_sector=audit_sector,
        credential_sector=cred_sector,
        distinct_audit_count=distinct,
        checksum_rejected=rejected,
    )
