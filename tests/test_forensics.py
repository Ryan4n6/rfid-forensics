"""Tests for rfid-forensics using the Caribe Royale hotel key dump as ground truth."""

import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from rfid_forensics.dump_loader import load_dump, load_json, load_bin
from rfid_forensics.key_fingerprint import analyze_keys, load_vendor_keys
from rfid_forensics.structure_detect import (
    _interpret_atqa,
    analyze_structure,
    detect_audit_records,
    verify_checksum_mod256,
    try_timestamp_decode,
)
from rfid_forensics.report import generate_report, ChainOfCustody
from rfid_forensics.diff import compare_dumps

DUMP_DIR = Path("/Users/admin/Projects/redteam/proxmark/dumps")
JSON_DUMP = DUMP_DIR / "hf-mf-21A420BD-dump.json"
BIN_DUMP = DUMP_DIR / "hf-mf-21A420BD-dump.bin"


@pytest.fixture
def card_json():
    return load_dump(JSON_DUMP)


@pytest.fixture
def card_bin():
    return load_dump(BIN_DUMP)


class TestDumpLoader:
    def test_load_json(self, card_json):
        assert card_json.uid == "21A420BD"
        assert card_json.sak == "08"
        assert card_json.card_type == "MIFARE Classic 1K"
        assert card_json.num_sectors == 16

    def test_load_bin(self, card_bin):
        assert card_bin.uid == "21A420BD"
        assert card_bin.card_type == "MIFARE Classic 1K"

    def test_json_and_bin_same_data(self, card_json, card_bin):
        """JSON and binary dumps of the same card must produce identical block data."""
        for blk in range(64):
            assert card_json.blocks[blk] == card_bin.blocks[blk], f"Block {blk} differs"

    def test_data_sectors(self, card_json):
        data = card_json.data_sectors()
        assert 0 in data
        assert 1 in data
        assert 4 in data

    def test_source_hash(self, card_json):
        assert len(card_json.source_hash) == 64

    def test_invalid_file(self):
        with pytest.raises(FileNotFoundError):
            load_dump("/nonexistent/file.json")


class TestKeyFingerprint:
    def test_vendor_detection(self, card_json):
        analysis = analyze_keys(card_json)
        assert analysis.vendor_guess == "Hotel lock system"

    def test_system_detection(self, card_json):
        analysis = analyze_keys(card_json)
        assert "Hotel" in analysis.system_guess or "hotel" in analysis.system_guess

    def test_unique_key_count(self, card_json):
        analysis = analyze_keys(card_json)
        assert len(analysis.unique_keys) == 3

    def test_property_master_key(self, card_json):
        analysis = analyze_keys(card_json)
        assert "6AF1A9F09615" in analysis.unique_keys
        locations = analysis.unique_keys["6AF1A9F09615"]
        assert len(locations) == 14

    def test_room_data_key(self, card_json):
        analysis = analyze_keys(card_json)
        assert "2A2C13CC242A" in analysis.unique_keys

    def test_default_key_sectors(self, card_json):
        analysis = analyze_keys(card_json)
        assert 2 in analysis.default_key_sectors

    def test_matched_keys(self, card_json):
        analysis = analyze_keys(card_json)
        matched_keys = [m.key_hex for m in analysis.matches]
        assert "6AF1A9F09615" in matched_keys
        assert "2A2C13CC242A" in matched_keys
        assert "FFFFFFFFFFFF" in matched_keys


class TestStructureDetect:
    def test_checksum_validation(self):
        """Verify mod-256 checksum on known good record from Caribe Royale."""
        record = bytes.fromhex("AE43DAD326920056")
        assert verify_checksum_mod256(record) is True

    def test_checksum_invalid(self):
        record = bytes.fromhex("AE43DAD326920057")
        assert verify_checksum_mod256(record) is False

    def test_audit_record_count(self, card_json):
        records = detect_audit_records(card_json)
        assert len(records) == 6

    def test_all_checksums_valid(self, card_json):
        records = detect_audit_records(card_json)
        for r in records:
            assert r.checksum_valid, f"Record at block {r.block}+{r.offset} has invalid checksum"

    def test_lock_id(self, card_json):
        records = detect_audit_records(card_json)
        lock_ids = set(r.lock_id for r in records)
        assert 0xAE43 in lock_ids

    def test_event_types(self, card_json):
        records = detect_audit_records(card_json)
        event_types = [r.event_type for r in records]
        assert 0x26 in event_types  # programmed
        assert 0x64 in event_types  # confirmed
        assert 0x24 in event_types  # door opened

    def test_timestamp_decode(self, card_json):
        records = detect_audit_records(card_json)
        records = try_timestamp_decode(records)
        assert records[0].timestamp_guess == "15:33:39"
        assert records[2].timestamp_guess == "15:38:24"

    def test_audit_sector(self, card_json):
        structure = analyze_structure(card_json)
        assert structure.has_audit_log is True
        assert structure.audit_sector == 4

    def test_credential_sector(self, card_json):
        structure = analyze_structure(card_json)
        assert structure.credential_sector == 1

    def test_card_type_byte(self, card_json):
        structure = analyze_structure(card_json)
        assert structure.card_type_byte is not None
        assert "R" in structure.card_type_byte


class TestReport:
    def test_text_report_contains_key_sections(self, card_json):
        ka = analyze_keys(card_json)
        sa = analyze_structure(card_json)
        report = generate_report(card_json, ka, sa)
        assert "RFID FORENSICS" in report
        assert "VENDOR FINGERPRINT" in report
        assert "AUDIT LOG" in report
        assert "FORENSIC NOTES" in report
        assert "INVESTIGATIVE LEADS" in report
        assert "Hotel lock system" in report

    def test_json_report_valid(self, card_json):
        ka = analyze_keys(card_json)
        sa = analyze_structure(card_json)
        report = generate_report(card_json, ka, sa, output_format="json")
        data = json.loads(report)
        assert data["card"]["uid"] == "21A420BD"
        assert data["vendor"]["guess"] == "Hotel lock system"
        assert data["audit_log"]["record_count"] == 6

    def test_chain_of_custody(self, card_json):
        ka = analyze_keys(card_json)
        sa = analyze_structure(card_json)
        custody = ChainOfCustody(
            examiner_name="Test Examiner",
            agency="Test PD",
            case_number="2026-TEST-001",
        )
        report = generate_report(card_json, ka, sa, custody)
        assert "Test Examiner" in report
        assert "Test PD" in report
        assert "2026-TEST-001" in report


    def test_pdf_report(self, card_json, tmp_path):
        ka = analyze_keys(card_json)
        sa = analyze_structure(card_json)
        from rfid_forensics.pdf_report import check_reportlab, generate_pdf

        if not check_reportlab():
            pytest.skip("reportlab not installed")

        pdf_path = str(tmp_path / "test-report.pdf")
        result = generate_pdf(card_json, ka, sa, pdf_path)
        assert Path(result).exists()
        assert Path(result).stat().st_size > 0
        with open(pdf_path, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"

    def test_pdf_with_custody(self, card_json, tmp_path):
        ka = analyze_keys(card_json)
        sa = analyze_structure(card_json)
        from rfid_forensics.pdf_report import check_reportlab, generate_pdf

        if not check_reportlab():
            pytest.skip("reportlab not installed")

        custody = ChainOfCustody(
            examiner_name="Test Examiner",
            agency="Test PD",
            case_number="2026-TEST-001",
        )
        pdf_path = str(tmp_path / "test-custody.pdf")
        result = generate_pdf(card_json, ka, sa, pdf_path, custody)
        assert Path(result).exists()
        assert Path(result).stat().st_size > 0


class TestDuplicateRecords:
    """Issue #1: byte-identical audit records must not count as separate events."""

    def test_duplicate_flagged(self, card_json):
        structure = analyze_structure(card_json)
        recs = structure.audit_records
        assert len(recs) == 6
        assert recs[4].raw == recs[3].raw
        assert recs[4].duplicate_of == 3
        assert all(r.duplicate_of is None for i, r in enumerate(recs) if i != 4)

    def test_distinct_count(self, card_json):
        structure = analyze_structure(card_json)
        assert structure.distinct_audit_count == 5

    def test_text_report_marks_duplicate(self, card_json):
        report = generate_report(card_json, analyze_keys(card_json), analyze_structure(card_json))
        assert "5 distinct, 1 exact duplicate" in report
        assert "DUP of [3]" in report
        assert "5 distinct timestamped events" in report
        assert "byte-for-byte duplicate of record [3]" in report

    def test_json_report_marks_duplicate(self, card_json):
        data = json.loads(generate_report(
            card_json, analyze_keys(card_json), analyze_structure(card_json), output_format="json"))
        assert data["audit_log"]["record_count"] == 6
        assert data["audit_log"]["distinct_count"] == 5
        assert data["audit_log"]["records"][4]["duplicate_of"] == 3
        assert data["audit_log"]["records"][3]["duplicate_of"] is None

    def test_no_duplicates_on_synthetic(self):
        structure = analyze_structure(load_dump(SYNTHETIC))
        assert structure.distinct_audit_count == len(structure.audit_records) == 6


SYNTHETIC = Path(__file__).parent.parent / "examples" / "synthetic-hotel-card.json"


class TestVendorAttribution:
    """Issue #2: chip-level keys (defaults, transport, clone backdoors) never attribute a vendor."""

    def test_default_key_only_is_unattributed(self):
        analysis = analyze_keys(load_dump(SYNTHETIC))
        assert analysis.vendor_guess is None
        assert analysis.system_guess is None
        assert "FFFFFFFFFFFF" in [m.key_hex for m in analysis.matches]

    def test_text_report_says_unattributed(self):
        card = load_dump(SYNTHETIC)
        report = generate_report(card, analyze_keys(card), analyze_structure(card))
        assert "Probable vendor:  Unattributed" in report
        assert "matches NXP" not in report
        assert "identify the chip, not the lock system" in report

    def test_json_null_vendor_and_confidence(self):
        card = load_dump(SYNTHETIC)
        data = json.loads(generate_report(
            card, analyze_keys(card), analyze_structure(card), output_format="json"))
        assert data["vendor"]["guess"] is None
        assert data["vendor"]["confidence"] is None
        assert data["vendor"]["reason"]

    def test_fudan_backdoor_key_does_not_attribute(self, card_json):
        card_json.sector_keys[1]["KeyA"] = "A396EFA4E24F"
        for s in range(card_json.num_sectors):
            if card_json.sector_keys[s].get("KeyA", "").upper() == "6AF1A9F09615":
                card_json.sector_keys[s]["KeyA"] = "FFFFFFFFFFFF"
        assert analyze_keys(card_json).vendor_guess is None

    def test_reference_card_still_attributed(self, card_json):
        assert analyze_keys(card_json).vendor_guess == "Hotel lock system"


class TestAtqa:
    """Issue #3: ATQA is stored LSB first in block 0."""

    def _atqa_field(self, card):
        return next(f for f in analyze_structure(card).data_fields if f.label == "ATQA")

    def test_reference_card_atqa(self, card_json):
        assert card_json.blocks[0][6:8] == bytes.fromhex("0400")
        interp = self._atqa_field(card_json).interpretation
        assert "0x0004" in interp
        assert "MIFARE Classic 1K" in interp
        assert "4-byte UID" in interp

    def test_synthetic_matches_proxmark_byte_order(self):
        card = load_dump(SYNTHETIC)
        assert card.blocks[0][6:8] == bytes.fromhex("0400")
        assert card.atqa == "0400"
        assert "MIFARE Classic 1K" in self._atqa_field(card).interpretation

    def test_decoder_values(self):
        assert "MIFARE Classic 4K" in _interpret_atqa(bytes.fromhex("0200"))
        assert "7-byte UID" in _interpret_atqa(bytes.fromhex("4400"))
        assert "unrecognized" in _interpret_atqa(bytes.fromhex("0400")[::-1])

    def test_no_manufacturer_claim(self, card_json):
        assert "NXP" not in self._atqa_field(card_json).interpretation


class TestLogging:
    """Issue #4: every analysis decision is logged under the rfid_forensics logger."""

    def _run(self, card, caplog):
        caplog.set_level(logging.DEBUG, logger="rfid_forensics")
        analyze_keys(card)
        analyze_structure(card)
        return "\n".join(r.getMessage() for r in caplog.records if r.name.startswith("rfid_forensics"))

    def test_load_logs_hash(self, caplog):
        caplog.set_level(logging.DEBUG, logger="rfid_forensics")
        card = load_dump(JSON_DUMP)
        assert card.source_hash in caplog.text

    def test_vendor_decision_logged(self, card_json, caplog):
        text = self._run(card_json, caplog)
        assert "vendor guess: Hotel lock system" in text

    def test_unattributed_logged(self, caplog):
        text = self._run(load_dump(SYNTHETIC), caplog)
        assert "vendor unattributed" in text

    def test_duplicate_logged(self, card_json, caplog):
        text = self._run(card_json, caplog)
        assert "record [4] is a duplicate of [3]" in text

    def test_timestamp_branch_logged(self, card_json, caplog):
        text = self._run(card_json, caplog)
        assert "timestamp heuristic: seconds from midnight" in text

    def test_missing_vendor_key_file_warns(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, logger="rfid_forensics")
        assert load_vendor_keys(tmp_path / "nope.txt") == {}
        assert "vendor key file not found" in caplog.text

    def test_malformed_vendor_key_line_warns(self, tmp_path, caplog):
        caplog.set_level(logging.WARNING, logger="rfid_forensics")
        f = tmp_path / "keys.txt"
        f.write_text("AABBCCDDEE01:Vendor:System\nnot-a-key-line\n")
        assert list(load_vendor_keys(f)) == ["AABBCCDDEE01"]
        assert "line 2" in caplog.text

    def test_cli_log_file(self, tmp_path):
        log_path = tmp_path / "analysis.log"
        out = subprocess.run(
            [sys.executable, "-m", "rfid_forensics", "analyze", str(JSON_DUMP),
             "--format", "json", "--log-file", str(log_path)],
            capture_output=True, text=True, check=True,
        )
        json.loads(out.stdout)
        log = log_path.read_text()
        assert "[rfid-forensics]" in log
        assert load_dump(JSON_DUMP).source_hash in log
        assert "vendor guess" in log

    def test_cli_quiet_by_default(self):
        out = subprocess.run(
            [sys.executable, "-m", "rfid_forensics", "audit", str(JSON_DUMP)],
            capture_output=True, text=True, check=True,
        )
        assert out.stderr == ""


def _report(card):
    return generate_report(card, analyze_keys(card), analyze_structure(card))


class TestReportWording:
    """Issue #5: forensic notes must not claim more than the analysis did."""

    def test_checksum_note_not_circular(self, card_json):
        report = _report(card_json)
        assert "indicating data integrity" not in report
        assert "identified by a mod-256 checksum" in report
        assert "9 other non-zero 8-byte chunks" in report
        assert "not proof that the data was unaltered" in report

    def test_rejected_count_on_structure(self, card_json):
        assert analyze_structure(card_json).checksum_rejected == 9

    def test_hotel_card_keeps_property_wording(self, card_json):
        report = _report(card_json)
        assert "property-wide master key" in report
        assert "shared across all locks" not in report

    def test_unattributed_card_uses_site_wording(self):
        report = _report(load_dump(SYNTHETIC))
        assert "property" not in report.lower()
        assert "site-wide key" in report

    def test_header_atqa_decoded(self, card_json):
        assert "ATQA:  0400 (ATQA 0x0004)" in _report(card_json)
        data = json.loads(generate_report(
            card_json, analyze_keys(card_json), analyze_structure(card_json), output_format="json"))
        assert data["card"]["atqa"] == "0400"
        assert data["card"]["atqa_value"] == "0x0004"


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext (poppler) not installed")
class TestPdfContent:
    """Issue #5: assert on rendered PDF text, not just that a file was written."""

    def _pdf_text(self, card, tmp_path, custody=None):
        from rfid_forensics.pdf_report import check_reportlab, generate_pdf
        if not check_reportlab():
            pytest.skip("reportlab not installed")
        pdf = tmp_path / "r.pdf"
        generate_pdf(card, analyze_keys(card), analyze_structure(card), str(pdf), custody)
        out = subprocess.run(["pdftotext", "-layout", str(pdf), "-"],
                             capture_output=True, text=True, check=True)
        return out.stdout

    def test_reference_card_pdf(self, card_json, tmp_path):
        text = self._pdf_text(card_json, tmp_path)
        assert "6 records (5 distinct, 1 exact duplicate)" in text
        assert "[DUP of #3]" in text
        assert "valid (dup #3)" in text
        assert "0400 (ATQA 0x0004)" in text
        assert "Hotel lock system" in text
        assert "identified by a mod-256 checksum" in text

    def test_synthetic_card_pdf(self, tmp_path):
        text = self._pdf_text(load_dump(SYNTHETIC), tmp_path)
        assert "Unattributed" in text
        assert "DUP" not in text
        assert "site-wide key" in text

    def test_custody_in_pdf(self, card_json, tmp_path):
        custody = ChainOfCustody(examiner_name="Det. Test", case_number="2026-CR-0001")
        text = self._pdf_text(card_json, tmp_path, custody)
        assert "Det. Test" in text
        assert "2026-CR-0001" in text


class TestDiff:
    def test_self_diff(self, card_json):
        """Comparing a card to itself should show no differences."""
        comp = compare_dumps(card_json, card_json)
        assert len(comp.different_blocks) == 0
        assert comp.same_property is True
