"""Load MIFARE Classic dump files from various formats."""

import json
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class MfcCard:
    """Parsed MIFARE Classic card."""

    uid: str
    atqa: str
    sak: str
    blocks: dict[int, bytes]
    sector_keys: dict[int, dict] = field(default_factory=dict)
    source_file: str = ""
    source_hash: str = ""

    @property
    def card_type(self) -> str:
        if len(self.blocks) <= 64:
            return "MIFARE Classic 1K"
        return "MIFARE Classic 4K"

    @property
    def num_sectors(self) -> int:
        if len(self.blocks) <= 64:
            return 16
        return 40

    def sector_blocks(self, sector: int) -> list[int]:
        """Return block numbers for a sector."""
        if sector < 32:
            base = sector * 4
            return [base, base + 1, base + 2, base + 3]
        base = 128 + (sector - 32) * 16
        return list(range(base, base + 16))

    def sector_trailer(self, sector: int) -> int:
        """Return the trailer block number for a sector."""
        return self.sector_blocks(sector)[-1]

    def sector_data_blocks(self, sector: int) -> list[int]:
        """Return data block numbers (excluding trailer) for a sector."""
        blocks = self.sector_blocks(sector)
        if sector == 0:
            return blocks[1:-1]
        return blocks[:-1]

    def get_key_a(self, sector: int) -> Optional[bytes]:
        trailer = self.blocks.get(self.sector_trailer(sector))
        if trailer:
            return trailer[:6]
        return None

    def get_key_b(self, sector: int) -> Optional[bytes]:
        trailer = self.blocks.get(self.sector_trailer(sector))
        if trailer:
            return trailer[10:16]
        return None

    def get_access_bits(self, sector: int) -> Optional[bytes]:
        trailer = self.blocks.get(self.sector_trailer(sector))
        if trailer:
            return trailer[6:10]
        return None

    def data_sectors(self) -> list[int]:
        """Return sectors that contain non-zero, non-default data."""
        result = []
        for s in range(self.num_sectors):
            for blk in self.sector_data_blocks(s):
                data = self.blocks.get(blk, b'\x00' * 16)
                if data != b'\x00' * 16:
                    result.append(s)
                    break
        return result


def load_json(path: Path) -> MfcCard:
    """Load a proxmark3 JSON dump."""
    with open(path) as f:
        data = json.load(f)

    card_info = data.get("Card", {})
    uid = card_info.get("UID", "")
    atqa = card_info.get("ATQA", "")
    sak = card_info.get("SAK", "")

    blocks = {}
    for blk_str, hex_str in data.get("blocks", {}).items():
        blocks[int(blk_str)] = bytes.fromhex(hex_str)

    sector_keys = {}
    for sec_str, keys in data.get("SectorKeys", {}).items():
        sector_keys[int(sec_str)] = {
            "KeyA": keys.get("KeyA", ""),
            "KeyB": keys.get("KeyB", ""),
            "AccessConditions": keys.get("AccessConditions", ""),
        }

    return MfcCard(
        uid=uid,
        atqa=atqa,
        sak=sak,
        blocks=blocks,
        sector_keys=sector_keys,
        source_file=str(path),
    )


def load_bin(path: Path) -> MfcCard:
    """Load a raw binary MIFARE Classic dump (1024 or 4096 bytes)."""
    raw = path.read_bytes()
    if len(raw) not in (1024, 4096):
        log.error("invalid binary dump size %d bytes: %s", len(raw), path)
        raise ValueError(f"Invalid dump size: {len(raw)} bytes (expected 1024 or 4096)")

    blocks = {}
    for i in range(len(raw) // 16):
        blocks[i] = raw[i * 16 : (i + 1) * 16]

    uid_bytes = blocks[0][:4]
    uid = uid_bytes.hex().upper()
    atqa_bytes = blocks[0][6:8]
    atqa = atqa_bytes.hex().upper()
    sak = f"{blocks[0][5]:02X}"

    sector_keys = {}
    num_sectors = 16 if len(raw) == 1024 else 40
    for s in range(num_sectors):
        if s < 32:
            trailer_blk = s * 4 + 3
        else:
            trailer_blk = 128 + (s - 32) * 16 + 15
        trailer = blocks[trailer_blk]
        sector_keys[s] = {
            "KeyA": trailer[:6].hex().upper(),
            "KeyB": trailer[10:16].hex().upper(),
            "AccessConditions": trailer[6:10].hex().upper(),
        }

    return MfcCard(
        uid=uid,
        atqa=atqa,
        sak=sak,
        blocks=blocks,
        sector_keys=sector_keys,
        source_file=str(path),
    )


def load_dump(path: str | Path) -> MfcCard:
    """Auto-detect format and load a MIFARE Classic dump."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dump file not found: {path}")

    import hashlib
    file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    log.info("source %s sha256=%s", path.resolve(), file_hash)

    if path.suffix == ".json":
        fmt = "json (by extension)"
        card = load_json(path)
    elif path.suffix in (".bin", ".dump", ".mfd"):
        fmt = "binary (by extension)"
        card = load_bin(path)
    else:
        raw = path.read_bytes()
        if len(raw) in (1024, 4096):
            fmt = f"binary (by size, {len(raw)} bytes)"
            card = load_bin(path)
        else:
            try:
                fmt = "json (fallback parse)"
                card = load_json(path)
            except (json.JSONDecodeError, KeyError):
                log.error("cannot determine format of %s (%d bytes)", path, len(raw))
                raise ValueError(f"Cannot determine format of {path}")

    card.source_file = str(path.resolve())
    card.source_hash = file_hash
    log.info("loaded %s: uid=%s type=%s blocks=%d keyed_sectors=%d",
             fmt, card.uid, card.card_type, len(card.blocks), len(card.sector_keys))
    return card
