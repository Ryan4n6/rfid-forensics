"""Fingerprint MIFARE Classic keys against known vendor databases."""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .dump_loader import MfcCard


@dataclass
class KeyMatch:
    """A matched key with its vendor attribution."""

    key_hex: str
    vendor: str
    system: str
    confidence: str  # "confirmed", "likely", "possible"
    notes: str = ""


# Known vendor key patterns.
# Sources: public disclosures, published research, CTF write-ups, vendor documentation.
# Keys here are already public knowledge.
KNOWN_KEYS: dict[str, dict] = {
    # Hotel lock systems
    "6AF1A9F09615": {
        "vendor": "Dormakaba/Saflok",
        "system": "Hotel lock (property master key)",
        "confidence": "likely",
        "notes": "Common across Saflok-equipped properties. Shared on all sectors except room-specific data.",
    },
    "2A2C13CC242A": {
        "vendor": "Dormakaba/Saflok",
        "system": "Hotel lock (room data sector)",
        "confidence": "likely",
        "notes": "Per-property or per-lock-group key for guest credential sector.",
    },

    # NXP defaults
    "FFFFFFFFFFFF": {
        "vendor": "NXP (factory default)",
        "system": "Unkeyed / factory default",
        "confidence": "confirmed",
        "notes": "Factory-shipped default. If found as Key A on data sectors, the system may be misconfigured.",
    },
    "000000000000": {
        "vendor": "NXP (zeroed)",
        "system": "Zeroed key",
        "confidence": "confirmed",
        "notes": "Sometimes used as a null/disabled key slot.",
    },
    "A0A1A2A3A4A5": {
        "vendor": "NXP (MAD key)",
        "system": "MIFARE Application Directory",
        "confidence": "confirmed",
        "notes": "MAD sector key per NXP AN10787.",
    },
    "B0B1B2B3B4B5": {
        "vendor": "NXP (MAD key)",
        "system": "MIFARE Application Directory Key B",
        "confidence": "confirmed",
        "notes": "MAD sector Key B per NXP AN10787.",
    },
    "D3F7D3F7D3F7": {
        "vendor": "NXP (NFC Forum)",
        "system": "NDEF public key",
        "confidence": "confirmed",
        "notes": "NFC Forum NDEF application Key A.",
    },

    # Transit systems (public knowledge)
    "FC00018778F7": {
        "vendor": "Cubic (TransLink)",
        "system": "Transit fare card",
        "confidence": "likely",
    },
    "1FC235AC1309": {
        "vendor": "Various transit",
        "system": "Transit system",
        "confidence": "possible",
    },

    # Access control
    "484558414354": {
        "vendor": "HID (iCLASS SE)",
        "system": "Access control",
        "confidence": "confirmed",
        "notes": "ASCII 'HEXACT'. HID iCLASS SE processor key.",
    },

    # Vending / payment
    "434F4D4D4F41": {
        "vendor": "Commoa",
        "system": "Vending/laundry",
        "confidence": "likely",
        "notes": "ASCII 'COMMOA'. Cashless payment.",
    },

    # Parking
    "A22AE129C013": {
        "vendor": "SKIDATA",
        "system": "Parking garage",
        "confidence": "likely",
    },

    # Gym / leisure
    "49FAE4E3849F": {
        "vendor": "Various gym/leisure",
        "system": "Gym locker or membership",
        "confidence": "possible",
    },
}


@dataclass
class KeyAnalysis:
    """Full key analysis of a card."""

    unique_keys: dict[str, list[str]]  # key_hex -> list of "sector N Key A/B"
    matches: list[KeyMatch]
    unmatched: list[str]
    key_diversity_score: float  # 0.0 = all same, 1.0 = all different
    default_key_sectors: list[int]
    vendor_guess: Optional[str]
    system_guess: Optional[str]


def analyze_keys(card: MfcCard) -> KeyAnalysis:
    """Analyze all keys on a card and attempt vendor fingerprinting."""
    unique_keys: dict[str, list[str]] = {}

    for sector in range(card.num_sectors):
        key_a = card.sector_keys.get(sector, {}).get("KeyA", "")
        key_b = card.sector_keys.get(sector, {}).get("KeyB", "")

        if key_a:
            unique_keys.setdefault(key_a.upper(), []).append(f"Sector {sector} Key A")
        if key_b:
            unique_keys.setdefault(key_b.upper(), []).append(f"Sector {sector} Key B")

    matches = []
    unmatched = []
    vendor_counts: dict[str, int] = {}

    for key_hex in unique_keys:
        if key_hex in KNOWN_KEYS:
            info = KNOWN_KEYS[key_hex]
            match = KeyMatch(
                key_hex=key_hex,
                vendor=info["vendor"],
                system=info["system"],
                confidence=info["confidence"],
                notes=info.get("notes", ""),
            )
            matches.append(match)
            vendor = info["vendor"].split("(")[0].strip()
            sector_count = len(unique_keys[key_hex])
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + sector_count
        else:
            unmatched.append(key_hex)

    default_sectors = []
    for sector in range(card.num_sectors):
        key_a = card.sector_keys.get(sector, {}).get("KeyA", "").upper()
        key_b = card.sector_keys.get(sector, {}).get("KeyB", "").upper()
        if key_a == "FFFFFFFFFFFF" and key_b == "FFFFFFFFFFFF":
            default_sectors.append(sector)

    total_slots = card.num_sectors * 2
    num_unique = len(unique_keys)
    diversity = (num_unique - 1) / max(total_slots - 1, 1)

    vendor_guess = None
    system_guess = None
    non_default_vendors = {
        v: c for v, c in vendor_counts.items()
        if v not in ("NXP", "NXP (factory default)", "NXP (zeroed)")
    }
    pick_from = non_default_vendors or vendor_counts
    if pick_from:
        vendor_guess = max(pick_from, key=pick_from.get)
        for m in matches:
            if m.vendor.startswith(vendor_guess) and m.confidence in ("confirmed", "likely"):
                system_guess = m.system
                break

    return KeyAnalysis(
        unique_keys=unique_keys,
        matches=matches,
        unmatched=unmatched,
        key_diversity_score=diversity,
        default_key_sectors=default_sectors,
        vendor_guess=vendor_guess,
        system_guess=system_guess,
    )


def load_vendor_keys(path: Path) -> dict[str, dict]:
    """Load additional vendor keys from a text file (key_hex:vendor:system per line)."""
    extra = {}
    if not path.exists():
        return extra
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 3:
            key_hex = parts[0].strip().upper()
            extra[key_hex] = {
                "vendor": parts[1].strip(),
                "system": parts[2].strip(),
                "confidence": "possible",
            }
    return extra
