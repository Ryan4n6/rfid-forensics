"""Load DESFire dump files from Proxmark3 JSON format."""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class DesfireFile:
    """A file within a DESFire application."""

    file_id: str
    file_type: str
    type_raw: str
    comm_mode: str
    access_rights: str
    iso_file_id: Optional[str] = None
    file_size: Optional[int] = None
    data: Optional[bytes] = None
    read_success: bool = False

    @property
    def access_read(self) -> str:
        """Extract read access key from access rights (first nibble)."""
        if len(self.access_rights) >= 1:
            nibble = self.access_rights[0].upper()
            return "free" if nibble == "E" else f"key {int(nibble, 16)}"
        return "unknown"

    @property
    def access_write(self) -> str:
        """Extract write access key from access rights (second nibble)."""
        if len(self.access_rights) >= 2:
            nibble = self.access_rights[1].upper()
            return "free" if nibble == "E" else f"key {int(nibble, 16)}"
        return "unknown"

    @property
    def access_rw(self) -> str:
        """Extract read/write access key from access rights (third nibble)."""
        if len(self.access_rights) >= 3:
            nibble = self.access_rights[2].upper()
            return "free" if nibble == "E" else f"key {int(nibble, 16)}"
        return "unknown"

    @property
    def access_change(self) -> str:
        """Extract change access key from access rights (fourth nibble)."""
        if len(self.access_rights) >= 4:
            nibble = self.access_rights[3].upper()
            return "free" if nibble == "E" else f"key {int(nibble, 16)}"
        return "unknown"

    def data_ascii(self) -> str:
        """Return ASCII representation of data, replacing non-printable with dots."""
        if not self.data:
            return ""
        return "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in self.data)


@dataclass
class DesfireKey:
    """A key slot in a DESFire application."""

    key_num: int
    version: str
    key_value: Optional[str] = None

    @property
    def is_known(self) -> bool:
        return self.key_value is not None

    @property
    def is_default(self) -> bool:
        if not self.key_value:
            return False
        return all(c == "0" for c in self.key_value)


@dataclass
class DesfireApp:
    """A DESFire application."""

    aid: str
    iso_file_id: Optional[str] = None
    df_name: Optional[str] = None
    key_settings: str = ""
    num_keys: int = 0
    key_type: str = ""
    authenticated: bool = False
    keys: dict[int, DesfireKey] = field(default_factory=dict)
    files: dict[str, DesfireFile] = field(default_factory=dict)

    @property
    def is_picc_master(self) -> bool:
        return self.aid == "000000"

    @property
    def aid_function(self) -> str:
        """Decode well-known AID prefixes."""
        if self.aid == "000000":
            return "PICC Master Application"
        aid_int = int(self.aid, 16)
        prefix = (aid_int >> 16) & 0xFF
        known = {
            0xF5: "NDEF (NFC Forum)",
            0x47: "Gallagher Access Control",
            0x9B: "HID iCLASS SE",
        }
        return known.get(prefix, "Custom Application")

    def ks1_flags(self) -> dict[str, bool]:
        """Parse key settings byte 1."""
        if not self.key_settings:
            return {}
        ks = int(self.key_settings, 16)
        return {
            "config_changeable": bool(ks & 0x08),
            "free_create_delete": bool(ks & 0x04),
            "free_listing": bool(ks & 0x02),
            "master_changeable": bool(ks & 0x01),
        }


@dataclass
class DesfireCard:
    """Parsed DESFire card."""

    uid: str
    atqa: str
    sak: str
    version_hw: str = ""
    version_sw: str = ""
    production_date: str = ""
    signature: str = ""
    signature_valid: bool = False
    free_memory: int = 0
    applications: dict[str, DesfireApp] = field(default_factory=dict)
    source_file: str = ""
    source_hash: str = ""

    @property
    def card_type(self) -> str:
        """Determine DESFire variant from hardware version."""
        if not self.version_hw:
            return "DESFire (unknown version)"
        hw_bytes = bytes.fromhex(self.version_hw)
        if len(hw_bytes) >= 4:
            major = hw_bytes[3]
            if major == 0x00:
                return "DESFire EV0 (D40)"
            elif major == 0x01:
                return "DESFire EV1"
            elif major == 0x12:
                return "DESFire EV2"
            elif major == 0x33:
                return "DESFire EV3"
            elif major == 0x42:
                return "DESFire Light"
        return f"DESFire (hw version 0x{self.version_hw})"

    @property
    def storage_size(self) -> str:
        """Determine storage from hardware version byte 5."""
        if len(self.version_hw) < 12:
            return "unknown"
        size_byte = int(self.version_hw[10:12], 16)
        sizes = {
            0x16: "2KB",
            0x18: "4KB",
            0x1A: "8KB",
        }
        return sizes.get(size_byte, f"0x{size_byte:02X}")

    @property
    def manufacturer(self) -> str:
        """Determine manufacturer from UID prefix."""
        if self.uid and self.uid[:2].upper() == "04":
            return "NXP Semiconductors"
        return "Unknown"

    @property
    def num_apps(self) -> int:
        return len([a for a in self.applications.values() if not a.is_picc_master])

    @property
    def total_files(self) -> int:
        return sum(len(app.files) for app in self.applications.values())

    @property
    def total_data_bytes(self) -> int:
        total = 0
        for app in self.applications.values():
            for f in app.files.values():
                if f.data:
                    total += len(f.data)
        return total

    def known_keys(self) -> list[tuple[str, int, DesfireKey]]:
        """Return all keys where the value is known."""
        result = []
        for aid, app in self.applications.items():
            for key_num, key in app.keys.items():
                if key.is_known:
                    result.append((aid, key_num, key))
        return result

    def default_keys(self) -> list[tuple[str, int, DesfireKey]]:
        """Return all keys that are factory default (all zeros)."""
        return [(aid, num, key) for aid, num, key in self.known_keys() if key.is_default]


def load_desfire_json(path: Path) -> DesfireCard:
    """Load a Proxmark3 DESFire JSON dump."""
    with open(path) as f:
        data = json.load(f)

    card_info = data.get("Card", {})

    card = DesfireCard(
        uid=card_info.get("UID", ""),
        atqa=card_info.get("ATQA", ""),
        sak=card_info.get("SAK", ""),
        version_hw=card_info.get("VersionHW", ""),
        version_sw=card_info.get("VersionSW", ""),
        signature=card_info.get("Signature", ""),
        free_memory=card_info.get("FreeMem", 0),
    )

    for aid, app_data in data.get("Applications", {}).items():
        app = DesfireApp(
            aid=aid,
            iso_file_id=app_data.get("ISOFileID"),
            key_settings=app_data.get("KeySettings", ""),
            num_keys=app_data.get("NumKeys", 0),
            key_type=app_data.get("KeyType", ""),
            authenticated=app_data.get("Authenticated", False),
        )

        for key_str, key_data in app_data.get("Keys", {}).items():
            key = DesfireKey(
                key_num=int(key_str),
                version=key_data.get("Version", ""),
                key_value=key_data.get("Key"),
            )
            app.keys[key.key_num] = key

        for file_id, file_data in app_data.get("Files", {}).items():
            data_hex = file_data.get("Data", "")
            df = DesfireFile(
                file_id=file_id,
                file_type=file_data.get("Type", "unknown"),
                type_raw=file_data.get("TypeRaw", ""),
                comm_mode=file_data.get("CommMode", ""),
                access_rights=file_data.get("AccessRights", ""),
                iso_file_id=file_data.get("ISOFileID"),
                file_size=file_data.get("FileSize"),
                data=bytes.fromhex(data_hex) if data_hex else None,
                read_success=file_data.get("Read", False),
            )
            app.files[file_id] = df

        card.applications[aid] = app

    return card


def load_desfire(path: str | Path) -> DesfireCard:
    """Load a DESFire dump file."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Dump file not found: {path}")

    import hashlib
    file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    log.info("source %s sha256=%s", path.resolve(), file_hash)

    if path.suffix != ".json":
        raise ValueError(f"DESFire dumps must be JSON format, got: {path.suffix}")

    card = load_desfire_json(path)
    card.source_file = str(path.resolve())
    card.source_hash = file_hash

    log.info("loaded DESFire: uid=%s type=%s apps=%d files=%d",
             card.uid, card.card_type, card.num_apps, card.total_files)
    return card
