"""Load MIFARE Ultralight/Ultralight C dump files from Proxmark3 JSON format."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class UltralightCard:
    """Parsed MIFARE Ultralight or Ultralight C card."""

    uid: str
    version: str = ""
    signature: str = ""
    pages: dict[int, bytes] = field(default_factory=dict)
    counter0: int = 0
    counter1: int = 0
    counter2: int = 0
    tearing0: int = 0
    tearing1: int = 0
    tearing2: int = 0
    source_file: str = ""
    source_hash: str = ""

    @property
    def card_type(self) -> str:
        """Determine card type from version bytes or page count."""
        if self.version and self.version != "0000000000000000":
            v = bytes.fromhex(self.version)
            if len(v) >= 7:
                prod_type = v[2]
                prod_subtype = v[3]
                storage = v[6] if len(v) > 6 else 0
                if prod_type == 0x03:
                    if prod_subtype == 0x01:
                        if storage == 0x0B:
                            return "MIFARE Ultralight EV1 48b"
                        elif storage == 0x0E:
                            return "MIFARE Ultralight EV1 128b"
                        elif storage > 0:
                            return "MIFARE Ultralight EV1"
                        return "MIFARE Ultralight"
                    elif prod_subtype == 0x02:
                        return "MIFARE Ultralight C"
                elif prod_type == 0x04:
                    return "MIFARE Ultralight Nano"
        max_page = max(self.pages.keys()) if self.pages else 0
        if max_page >= 44:
            return "MIFARE Ultralight C (48 pages)"
        elif max_page >= 20:
            return "MIFARE Ultralight EV1 (by page count)"
        return "MIFARE Ultralight (by page count)"

    @property
    def is_ultralight_c(self) -> bool:
        return "Ultralight C" in self.card_type

    @property
    def manufacturer(self) -> str:
        if self.uid and self.uid[:2].upper() == "04":
            return "NXP Semiconductors"
        return "Unknown"

    @property
    def bcc0(self) -> Optional[int]:
        """BCC0 checksum (page 0, byte 3 or page 2 byte 0 depending on layout)."""
        if 2 in self.pages:
            return self.pages[2][0]
        return None

    @property
    def bcc1(self) -> Optional[int]:
        """BCC1 checksum (page 2, byte 0)."""
        if 2 in self.pages:
            return self.pages[2][0]
        return None

    @property
    def internal_byte(self) -> Optional[int]:
        """Internal byte (page 2, byte 1)."""
        if 2 in self.pages:
            return self.pages[2][1]
        return None

    @property
    def lock_bytes(self) -> Optional[bytes]:
        """Lock bytes (page 2, bytes 2-3)."""
        if 2 in self.pages:
            return self.pages[2][2:4]
        return None

    @property
    def lock_bits_set(self) -> list[str]:
        """Return list of locked pages/areas."""
        if not self.lock_bytes:
            return []
        lb = int.from_bytes(self.lock_bytes, "little")
        locked = []
        if lb & 0x0001:
            locked.append("Page 3 (OTP)")
        if lb & 0x0002:
            locked.append("Pages 4-9")
        if lb & 0x0004:
            locked.append("Pages 10-15")
        if lb & 0x0008:
            locked.append("Lock bits OTP")
        if lb & 0x0010:
            locked.append("Lock bits 4-9")
        if lb & 0x0020:
            locked.append("Lock bits 10-15")
        if lb & 0x0040:
            locked.append("Block Lock bit")
        if lb & 0x0080:
            locked.append("CC field")
        for i in range(8):
            if lb & (0x0100 << i):
                locked.append(f"Page {16 + i}")
        return locked

    @property
    def otp(self) -> Optional[bytes]:
        """One-Time Programmable bytes (page 3)."""
        return self.pages.get(3)

    @property
    def otp_is_programmed(self) -> bool:
        """Check if OTP has any bits set."""
        if self.otp:
            return any(b != 0 for b in self.otp)
        return False

    @property
    def user_data_pages(self) -> list[int]:
        """Return page numbers containing user data."""
        if self.is_ultralight_c:
            return [p for p in range(4, 40) if p in self.pages]
        return [p for p in range(4, 16) if p in self.pages]

    @property
    def readable_pages(self) -> int:
        return len(self.pages)

    @property
    def total_pages(self) -> int:
        if self.is_ultralight_c:
            return 48
        return 16

    @property
    def dump_complete(self) -> bool:
        return self.readable_pages >= self.total_pages

    def get_user_data(self) -> bytes:
        """Return concatenated user data from readable pages."""
        data = b""
        for p in sorted(self.user_data_pages):
            data += self.pages.get(p, b"\x00\x00\x00\x00")
        return data

    def page_hex(self, page: int) -> str:
        """Return hex string for a page."""
        if page in self.pages:
            return self.pages[page].hex().upper()
        return "--------"

    def page_ascii(self, page: int) -> str:
        """Return ASCII representation of a page."""
        if page not in self.pages:
            return "...."
        return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in self.pages[page])


def load_ultralight_json(path: Path) -> UltralightCard:
    """Load a Proxmark3 Ultralight JSON dump."""
    with open(path) as f:
        data = json.load(f)

    card_info = data.get("Card", {})

    card = UltralightCard(
        uid=card_info.get("UID", ""),
        version=card_info.get("Version", ""),
        signature=card_info.get("Signature", ""),
        counter0=int(card_info.get("Counter0", "000000"), 16),
        counter1=int(card_info.get("Counter1", "000000"), 16),
        counter2=int(card_info.get("Counter2", "000000"), 16),
        tearing0=int(card_info.get("Tearing0", "00"), 16),
        tearing1=int(card_info.get("Tearing1", "00"), 16),
        tearing2=int(card_info.get("Tearing2", "00"), 16),
    )

    for page_str, hex_str in data.get("blocks", {}).items():
        card.pages[int(page_str)] = bytes.fromhex(hex_str)

    return card


def load_ultralight_bin(path: Path) -> UltralightCard:
    """Load a raw binary Ultralight dump."""
    raw = path.read_bytes()

    if len(raw) % 4 != 0:
        raise ValueError(f"Invalid Ultralight dump size: {len(raw)} bytes (must be multiple of 4)")

    pages = {}
    for i in range(len(raw) // 4):
        pages[i] = raw[i * 4:(i + 1) * 4]

    uid_bytes = pages.get(0, b"\x00" * 4)[:3] + pages.get(1, b"\x00" * 4)
    uid = (uid_bytes[:3] + uid_bytes[4:]).hex().upper()

    return UltralightCard(uid=uid, pages=pages)


def load_ultralight(path: str | Path) -> UltralightCard:
    """Load an Ultralight dump file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dump file not found: {path}")

    import hashlib
    file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    log.info("source %s sha256=%s", path.resolve(), file_hash)

    if path.suffix == ".json":
        card = load_ultralight_json(path)
    elif path.suffix in (".bin", ".dump", ".mfd"):
        card = load_ultralight_bin(path)
    else:
        raw = path.read_bytes()
        if len(raw) % 4 == 0 and len(raw) <= 192:
            card = load_ultralight_bin(path)
        else:
            try:
                card = load_ultralight_json(path)
            except (json.JSONDecodeError, KeyError):
                raise ValueError(f"Cannot determine format of {path}")

    card.source_file = str(path.resolve())
    card.source_hash = file_hash

    log.info("loaded Ultralight: uid=%s type=%s pages=%d/%d",
             card.uid, card.card_type, card.readable_pages, card.total_pages)
    return card
