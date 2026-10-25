"""Command-line interface for rfid-forensics."""

import argparse
import logging
import sys
from pathlib import Path

from . import __version__
from .dump_loader import load_dump
from .key_fingerprint import analyze_keys, load_vendor_keys, KNOWN_KEYS
from .structure_detect import analyze_structure
from .report import generate_report, ChainOfCustody
from .diff import compare_dumps, format_comparison

log = logging.getLogger("rfid_forensics.cli")

LOG_FORMAT = "%(asctime)s [rfid-forensics] %(levelname)s %(name)s: %(message)s"


def _setup_logging(verbose: int, log_file: str | None) -> None:
    # Reports go to stdout, so logs always go to stderr or a file and never mix in.
    root = logging.getLogger("rfid_forensics")
    root.setLevel(logging.DEBUG)
    stderr = logging.StreamHandler(sys.stderr)
    stderr.setLevel({0: logging.WARNING, 1: logging.INFO}.get(verbose, logging.DEBUG))
    stderr.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(stderr)
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(LOG_FORMAT))
        root.addHandler(fh)


def main():
    parser = argparse.ArgumentParser(
        prog="rfid-forensics",
        description="HF contactless card forensic analysis tool",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0,
                        help="Log decisions to stderr (-v info, -vv debug)")
    common.add_argument("--log-file", help="Write a debug-level analysis log to this file")

    # analyze command
    p_analyze = subparsers.add_parser("analyze", parents=[common], help="Analyze a MIFARE Classic dump file")
    p_analyze.add_argument("dump", help="Path to dump file (.json, .bin, .mfd)")
    p_analyze.add_argument("-o", "--output", help="Write report to file instead of stdout")
    p_analyze.add_argument("--format", choices=["text", "json", "pdf"], default="text",
                           help="Output format (default: text)")
    p_analyze.add_argument("--vendor-keys", help="Additional vendor key file (key:vendor:system per line)")
    p_analyze.add_argument("--examiner", help="Examiner name for chain of custody")
    p_analyze.add_argument("--badge", help="Examiner badge/ID number")
    p_analyze.add_argument("--agency", help="Agency name")
    p_analyze.add_argument("--case", help="Case number")
    p_analyze.add_argument("--evidence", help="Evidence item number")
    p_analyze.add_argument("--acquired", help="Date/time card was acquired")

    # diff command
    p_diff = subparsers.add_parser("diff", parents=[common], help="Compare two dump files")
    p_diff.add_argument("dump_a", help="First dump file")
    p_diff.add_argument("dump_b", help="Second dump file")
    p_diff.add_argument("-o", "--output", help="Write report to file")

    # keys command
    p_keys = subparsers.add_parser("keys", parents=[common], help="Show key analysis only")
    p_keys.add_argument("dump", help="Path to dump file")
    p_keys.add_argument("--vendor-keys", help="Additional vendor key file")

    # audit command
    p_audit = subparsers.add_parser("audit", parents=[common], help="Show audit log only")
    p_audit.add_argument("dump", help="Path to dump file")

    # hexdump command
    p_hex = subparsers.add_parser("hexdump", parents=[common], help="Show raw hex of data sectors")
    p_hex.add_argument("dump", help="Path to dump file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    _setup_logging(args.verbose, args.log_file)
    log.info("rfid-forensics %s: %s", __version__, " ".join(sys.argv[1:]))

    try:
        if args.command == "analyze":
            _cmd_analyze(args)
        elif args.command == "diff":
            _cmd_diff(args)
        elif args.command == "keys":
            _cmd_keys(args)
        elif args.command == "audit":
            _cmd_audit(args)
        elif args.command == "hexdump":
            _cmd_hexdump(args)
    except Exception as e:
        log.debug("command %s failed", args.command, exc_info=True)
        # The handler already printed it to stderr at WARNING level; avoid printing twice.
        log.error("%s", e)
        sys.exit(1)
    log.info("command %s finished", args.command)


def _cmd_analyze(args):
    card = load_dump(args.dump)

    if args.vendor_keys:
        extra = load_vendor_keys(Path(args.vendor_keys))
        KNOWN_KEYS.update(extra)

    key_analysis = analyze_keys(card)
    structure = analyze_structure(card)

    custody = None
    if any([args.examiner, args.badge, args.agency, args.case, args.evidence, args.acquired]):
        custody = ChainOfCustody(
            examiner_name=args.examiner or "",
            examiner_badge=args.badge or "",
            agency=args.agency or "",
            case_number=args.case or "",
            evidence_number=args.evidence or "",
            date_acquired=args.acquired or "",
        )

    if args.format == "pdf":
        from .pdf_report import check_reportlab, generate_pdf

        if not check_reportlab():
            log.error("PDF output requires reportlab. Install with: pip install reportlab")
            sys.exit(1)

        output = args.output or f"rfid-report-{card.uid}.pdf"
        generate_pdf(card, key_analysis, structure, output, custody)
        log.info("PDF report written to %s", output)
        print(f"PDF report written to {output}")
    else:
        report = generate_report(card, key_analysis, structure, custody, args.format)

        if args.output:
            Path(args.output).write_text(report)
            log.info("%s report written to %s", args.format, args.output)
            print(f"Report written to {args.output}")
        else:
            log.info("%s report written to stdout", args.format)
            print(report)


def _cmd_diff(args):
    card_a = load_dump(args.dump_a)
    card_b = load_dump(args.dump_b)
    comparison = compare_dumps(card_a, card_b)
    text = format_comparison(comparison)

    if args.output:
        Path(args.output).write_text(text)
        print(f"Comparison written to {args.output}")
    else:
        print(text)


def _cmd_keys(args):
    card = load_dump(args.dump)

    if args.vendor_keys:
        extra = load_vendor_keys(Path(args.vendor_keys))
        KNOWN_KEYS.update(extra)

    analysis = analyze_keys(card)

    print(f"Card: {card.uid} ({card.card_type})")
    print(f"Unique keys: {len(analysis.unique_keys)}")
    print(f"Key diversity: {analysis.key_diversity_score:.2f}")
    print()

    if analysis.vendor_guess:
        print(f"Probable vendor: {analysis.vendor_guess}")
    else:
        print("Probable vendor: Unattributed")
    if analysis.system_guess:
        print(f"Probable system: {analysis.system_guess}")
    print()

    print("Key map:")
    for key_hex, locations in sorted(analysis.unique_keys.items()):
        match = next((m for m in analysis.matches if m.key_hex == key_hex), None)
        vendor_str = f" [{match.vendor}]" if match else ""
        print(f"  {key_hex}{vendor_str}")
        for loc in locations:
            print(f"    {loc}")
    print()


def _cmd_audit(args):
    card = load_dump(args.dump)
    structure = analyze_structure(card)

    if not structure.audit_records:
        print("No audit records found.")
        return

    total = len(structure.audit_records)
    dup_count = total - structure.distinct_audit_count
    if dup_count:
        print(f"Audit records: {total} ({structure.distinct_audit_count} distinct, "
              f"{dup_count} exact duplicate{'s' if dup_count > 1 else ''})")
    else:
        print(f"Audit records: {total}")
    lock_ids = set(r.lock_id for r in structure.audit_records)
    print(f"Lock IDs: {', '.join(f'0x{lid:04X}' for lid in sorted(lock_ids))}")
    print()

    print(f"{'#':<4}{'Time':<14} {'Event':<6} {'Label':<44} {'Lock':<7} {'Chk':<4}")
    print(f"{'-'*3} {'-'*14} {'-'*6} {'-'*44} {'-'*7} {'-'*4}")

    for i, r in enumerate(structure.audit_records):
        time_str = r.timestamp_guess or f"cnt={r.counter}"
        label = r.event_label or f"Unknown (0x{r.event_type:02X})"
        chk = "OK" if r.checksum_valid else "BAD"
        dup = f"  DUP of [{r.duplicate_of}]" if r.duplicate_of is not None else ""
        print(f"[{i}] {time_str:<14} 0x{r.event_type:02X}   {label:<44} 0x{r.lock_id:04X}  {chk}{dup}")


def _cmd_hexdump(args):
    card = load_dump(args.dump)

    for sector in card.data_sectors():
        print(f"Sector {sector}:")
        for blk in card.sector_data_blocks(sector):
            data = card.blocks.get(blk, b'\x00' * 16)
            if data != b'\x00' * 16:
                hex_str = " ".join(f"{b:02X}" for b in data)
                ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in data)
                print(f"  Block {blk:2d}: {hex_str}  |{ascii_str}|")
        print()


if __name__ == "__main__":
    main()
