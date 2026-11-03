"""Generate forensic reports for DESFire cards."""

import json
import logging
from datetime import datetime
from typing import Optional

from .desfire_loader import DesfireCard

log = logging.getLogger(__name__)


def generate_desfire_report(
    card: DesfireCard,
    output_format: str = "text",
) -> str:
    """Generate a forensic report for a DESFire card."""
    if output_format == "json":
        return _generate_json(card)
    return _generate_text(card)


def _generate_text(card: DesfireCard) -> str:
    """Generate a text report."""
    lines = []

    lines.append("=" * 72)
    lines.append("DESFire Forensic Analysis Report")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 72)
    lines.append("")

    lines.append("CARD IDENTIFICATION")
    lines.append("-" * 40)
    lines.append(f"  UID:          {card.uid}")
    lines.append(f"  Type:         {card.card_type}")
    lines.append(f"  Storage:      {card.storage_size}")
    lines.append(f"  Manufacturer: {card.manufacturer}")
    lines.append(f"  Free Memory:  {card.free_memory} bytes")
    lines.append("")

    lines.append("HARDWARE/SOFTWARE VERSION")
    lines.append("-" * 40)
    lines.append(f"  HW Version: {card.version_hw}")
    lines.append(f"  SW Version: {card.version_sw}")
    if card.signature:
        lines.append(f"  Signature:  {card.signature[:32]}...")
        lines.append(f"              (verification: {'VALID' if card.signature_valid else 'NOT CHECKED'})")
    lines.append("")

    lines.append("APPLICATION SUMMARY")
    lines.append("-" * 40)
    lines.append(f"  Applications: {card.num_apps} (plus PICC master)")
    lines.append(f"  Total Files:  {card.total_files}")
    lines.append(f"  Data Read:    {card.total_data_bytes} bytes")
    lines.append("")

    default_keys = card.default_keys()
    if default_keys:
        lines.append("SECURITY FINDINGS")
        lines.append("-" * 40)
        lines.append(f"  [!] {len(default_keys)} key(s) still at factory default (all zeros):")
        for aid, key_num, key in default_keys:
            app_name = "PICC" if aid == "000000" else f"App {aid}"
            lines.append(f"      {app_name} key {key_num}: {key.key_value}")
        lines.append("")

    for aid, app in sorted(card.applications.items()):
        lines.append("=" * 72)
        if app.is_picc_master:
            lines.append("APPLICATION: PICC Master (000000)")
        else:
            lines.append(f"APPLICATION: {aid}")
            lines.append(f"  Function:    {app.aid_function}")

        if app.iso_file_id:
            lines.append(f"  ISO File ID: {app.iso_file_id}")

        lines.append(f"  Key Type:    {app.key_type.upper()}")
        lines.append(f"  Key Count:   {app.num_keys}")
        lines.append(f"  Auth Status: {'Authenticated' if app.authenticated else 'Not authenticated'}")

        ks = app.ks1_flags()
        if ks:
            lines.append(f"  Key Settings:")
            lines.append(f"    Config changeable:    {'Yes' if ks.get('config_changeable') else 'No'}")
            lines.append(f"    Free create/delete:   {'Yes' if ks.get('free_create_delete') else 'No'}")
            lines.append(f"    Free directory list:  {'Yes' if ks.get('free_listing') else 'No'}")
            lines.append(f"    Master key changeable: {'Yes' if ks.get('master_changeable') else 'No'}")
        lines.append("")

        if app.keys:
            lines.append("  KEYS:")
            for key_num in sorted(app.keys.keys()):
                key = app.keys[key_num]
                if key.is_known:
                    status = "DEFAULT" if key.is_default else "KNOWN"
                    lines.append(f"    Key {key_num}: {key.key_value} [{status}]")
                else:
                    lines.append(f"    Key {key_num}: (version {key.version}, value unknown)")
            lines.append("")

        if app.files:
            lines.append("  FILES:")
            for file_id in sorted(app.files.keys()):
                f = app.files[file_id]
                lines.append(f"    File {file_id}:")
                lines.append(f"      Type:     {f.file_type}")
                lines.append(f"      Comm:     {f.comm_mode}")
                lines.append(f"      Size:     {f.file_size} bytes")
                lines.append(f"      Access:   r={f.access_read} w={f.access_write} rw={f.access_rw} ch={f.access_change}")

                if f.data:
                    lines.append(f"      Data ({len(f.data)} bytes):")
                    for offset in range(0, len(f.data), 16):
                        chunk = f.data[offset:offset + 16]
                        hex_str = " ".join(f"{b:02X}" for b in chunk)
                        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
                        lines.append(f"        {offset:04X}: {hex_str:<48} |{ascii_str}|")
                else:
                    lines.append("      Data:     (not read)")
                lines.append("")
        lines.append("")

    lines.append("=" * 72)
    lines.append("SOURCE FILE")
    lines.append("-" * 40)
    lines.append(f"  Path:   {card.source_file}")
    lines.append(f"  SHA256: {card.source_hash}")
    lines.append("=" * 72)

    return "\n".join(lines)


def _generate_json(card: DesfireCard) -> str:
    """Generate a JSON report."""
    report = {
        "report_type": "desfire_forensic",
        "generated": datetime.now().isoformat(),
        "card": {
            "uid": card.uid,
            "type": card.card_type,
            "storage": card.storage_size,
            "manufacturer": card.manufacturer,
            "free_memory": card.free_memory,
            "version_hw": card.version_hw,
            "version_sw": card.version_sw,
            "signature": card.signature,
        },
        "summary": {
            "num_applications": card.num_apps,
            "total_files": card.total_files,
            "total_data_bytes": card.total_data_bytes,
            "default_keys": len(card.default_keys()),
        },
        "applications": {},
        "source": {
            "file": card.source_file,
            "sha256": card.source_hash,
        },
    }

    for aid, app in card.applications.items():
        app_data = {
            "function": app.aid_function,
            "iso_file_id": app.iso_file_id,
            "key_type": app.key_type,
            "num_keys": app.num_keys,
            "key_settings": app.ks1_flags(),
            "authenticated": app.authenticated,
            "keys": {},
            "files": {},
        }

        for key_num, key in app.keys.items():
            app_data["keys"][str(key_num)] = {
                "version": key.version,
                "value": key.key_value,
                "is_default": key.is_default,
            }

        for file_id, f in app.files.items():
            app_data["files"][file_id] = {
                "type": f.file_type,
                "comm_mode": f.comm_mode,
                "size": f.file_size,
                "access": {
                    "read": f.access_read,
                    "write": f.access_write,
                    "read_write": f.access_rw,
                    "change": f.access_change,
                },
                "data_hex": f.data.hex() if f.data else None,
                "data_ascii": f.data_ascii() if f.data else None,
            }

        report["applications"][aid] = app_data

    return json.dumps(report, indent=2)
