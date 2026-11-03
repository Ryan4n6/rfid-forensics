"""Generate forensic reports for Ultralight/Ultralight C cards."""

import json
import logging
from datetime import datetime

from .ultralight_loader import UltralightCard

log = logging.getLogger(__name__)


def generate_ultralight_report(card: UltralightCard, output_format: str = "text") -> str:
    """Generate a forensic report for an Ultralight card."""
    if output_format == "json":
        return _generate_json(card)
    return _generate_text(card)


def _generate_text(card: UltralightCard) -> str:
    """Generate a text report."""
    lines = []

    lines.append("=" * 72)
    lines.append("MIFARE Ultralight Forensic Analysis Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 72)
    lines.append("")

    lines.append("CARD IDENTIFICATION")
    lines.append("-" * 40)
    lines.append(f"  UID:          {card.uid}")
    lines.append(f"  Type:         {card.card_type}")
    lines.append(f"  Manufacturer: {card.manufacturer}")
    lines.append("")

    lines.append("DUMP STATUS")
    lines.append("-" * 40)
    lines.append(f"  Pages Read:   {card.readable_pages} of {card.total_pages}")
    lines.append(f"  Complete:     {'Yes' if card.dump_complete else 'No (auth-protected pages)'}")
    lines.append("")

    if card.version and card.version != "0000000000000000":
        lines.append("VERSION INFO")
        lines.append("-" * 40)
        lines.append(f"  Version:    {card.version}")
        lines.append("")

    if card.signature and card.signature != "0" * 64:
        lines.append("SIGNATURE")
        lines.append("-" * 40)
        lines.append(f"  {card.signature[:32]}")
        lines.append(f"  {card.signature[32:]}")
        lines.append("")

    lines.append("CONFIGURATION")
    lines.append("-" * 40)
    if card.lock_bytes:
        lb_hex = card.lock_bytes.hex().upper()
        lines.append(f"  Lock Bytes:   {lb_hex}")
        locked = card.lock_bits_set
        if locked:
            lines.append(f"  Locked:       {', '.join(locked)}")
        else:
            lines.append("  Locked:       (none)")

    if card.internal_byte is not None:
        lines.append(f"  Internal:     0x{card.internal_byte:02X}")

    if card.otp:
        otp_hex = card.otp.hex().upper()
        lines.append(f"  OTP:          {otp_hex} {'(programmed)' if card.otp_is_programmed else '(blank)'}")
    lines.append("")

    if any([card.counter0, card.counter1, card.counter2]):
        lines.append("COUNTERS")
        lines.append("-" * 40)
        lines.append(f"  Counter 0:    {card.counter0} (tearing: 0x{card.tearing0:02X})")
        lines.append(f"  Counter 1:    {card.counter1} (tearing: 0x{card.tearing1:02X})")
        lines.append(f"  Counter 2:    {card.counter2} (tearing: 0x{card.tearing2:02X})")
        lines.append("")

    if card.is_ultralight_c:
        lines.append("ULTRALIGHT C SECURITY")
        lines.append("-" * 40)
        if card.readable_pages < 48:
            lines.append("  3DES Auth:    Required (pages 10+ protected)")
            lines.append("  Key Pages:    40-43 (not readable)")
            lines.append("  Auth Config:  Pages 44-47 (not readable)")
        else:
            lines.append("  3DES Auth:    Disabled or key known")
        lines.append("")

    lines.append("PAGE DUMP")
    lines.append("-" * 40)
    lines.append(f"  {'Page':<6} {'Hex':<12} {'ASCII':<6} {'Description'}")
    lines.append(f"  {'-'*5} {'-'*11} {'-'*5} {'-'*30}")

    page_desc = {
        0: "UID bytes 0-2, BCC0",
        1: "UID bytes 3-6",
        2: "BCC1, Internal, Lock bytes",
        3: "OTP (One-Time Programmable)",
    }

    if card.is_ultralight_c:
        for i in range(4, 40):
            page_desc[i] = "User data"
        page_desc[40] = "3DES key byte 0-3"
        page_desc[41] = "3DES key byte 4-7"
        page_desc[42] = "3DES key byte 8-11"
        page_desc[43] = "3DES key byte 12-15"
        page_desc[44] = "Lock bytes 2"
        page_desc[45] = "Reserved"
        page_desc[46] = "Reserved"
        page_desc[47] = "Auth config"
    else:
        for i in range(4, 16):
            page_desc[i] = "User data"

    for page in range(card.total_pages):
        if page in card.pages:
            hex_str = card.page_hex(page)
            ascii_str = card.page_ascii(page)
            desc = page_desc.get(page, "")
            lines.append(f"  {page:<6} {hex_str:<12} {ascii_str:<6} {desc}")
        elif page < max(card.pages.keys()) + 5:
            lines.append(f"  {page:<6} {'--------':<12} {'....':<6} {page_desc.get(page, '')} (not read)")

    lines.append("")

    user_data = card.get_user_data()
    if user_data and any(b != 0 for b in user_data):
        lines.append("USER DATA (concatenated)")
        lines.append("-" * 40)
        for offset in range(0, len(user_data), 16):
            chunk = user_data[offset:offset + 16]
            hex_str = " ".join(f"{b:02X}" for b in chunk)
            ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
            lines.append(f"  {offset:04X}: {hex_str:<48} |{ascii_str}|")
        lines.append("")

    lines.append("=" * 72)
    lines.append("SOURCE FILE")
    lines.append("-" * 40)
    lines.append(f"  Path:   {card.source_file}")
    lines.append(f"  SHA256: {card.source_hash}")
    lines.append("=" * 72)

    return "\n".join(lines)


def _generate_json(card: UltralightCard) -> str:
    """Generate a JSON report."""
    report = {
        "report_type": "ultralight_forensic",
        "generated": datetime.now().isoformat(),
        "card": {
            "uid": card.uid,
            "type": card.card_type,
            "manufacturer": card.manufacturer,
            "is_ultralight_c": card.is_ultralight_c,
        },
        "dump_status": {
            "pages_read": card.readable_pages,
            "total_pages": card.total_pages,
            "complete": card.dump_complete,
        },
        "configuration": {
            "version": card.version if card.version != "0000000000000000" else None,
            "signature": card.signature if card.signature != "0" * 64 else None,
            "lock_bytes": card.lock_bytes.hex().upper() if card.lock_bytes else None,
            "locked_areas": card.lock_bits_set,
            "internal_byte": f"0x{card.internal_byte:02X}" if card.internal_byte is not None else None,
            "otp": card.otp.hex().upper() if card.otp else None,
            "otp_programmed": card.otp_is_programmed,
        },
        "counters": {
            "counter0": card.counter0,
            "counter1": card.counter1,
            "counter2": card.counter2,
            "tearing0": card.tearing0,
            "tearing1": card.tearing1,
            "tearing2": card.tearing2,
        },
        "pages": {str(p): card.pages[p].hex().upper() for p in sorted(card.pages.keys())},
        "user_data_hex": card.get_user_data().hex().upper(),
        "source": {
            "file": card.source_file,
            "sha256": card.source_hash,
        },
    }
    return json.dumps(report, indent=2)
