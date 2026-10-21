"""Tests for rfid-forensics using the Caribe Royale hotel key dump as ground truth."""

import json
from pathlib import Path

import pytest

from rfid_forensics.dump_loader import load_dump, load_json, load_bin
from rfid_forensics.key_fingerprint import analyze_keys
from rfid_forensics.structure_detect import (
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


class TestDiff:
    def test_self_diff(self, card_json):
        """Comparing a card to itself should show no differences."""
        comp = compare_dumps(card_json, card_json)
        assert len(comp.different_blocks) == 0
        assert comp.same_property is True
