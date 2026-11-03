"""Tests for Ultralight/Ultralight C loader and report generation."""

import json
import pytest
from pathlib import Path

from rfid_forensics.ultralight_loader import (
    UltralightCard, load_ultralight, load_ultralight_json,
)
from rfid_forensics.ultralight_report import generate_ultralight_report


@pytest.fixture
def sample_ultralight_json(tmp_path):
    """Create a sample Ultralight dump JSON for testing."""
    dump = {
        "Created": "proxmark3",
        "FileType": "mfu",
        "Card": {
            "UID": "041CBE92E77A80",
            "Version": "0000000000000000",
            "Signature": "0" * 64,
            "Counter0": "000000",
            "Tearing0": "00",
            "Counter1": "000000",
            "Tearing1": "00",
            "Counter2": "000000",
            "Tearing2": "00",
        },
        "blocks": {
            "0": "041CBE2E",
            "1": "92E77A80",
            "2": "8F480000",
            "3": "00000000",
            "4": "02D7C800",
            "5": "00000000",
            "6": "00000000",
            "7": "00000000",
            "8": "00000000",
            "9": "00000000",
        },
    }
    path = tmp_path / "test-ultralight.json"
    path.write_text(json.dumps(dump))
    return path


@pytest.fixture
def sample_ultralight_ev1_json(tmp_path):
    """Create a sample Ultralight EV1 dump with version info."""
    dump = {
        "Created": "proxmark3",
        "FileType": "mfu",
        "Card": {
            "UID": "0412345678ABCD",
            "Version": "0004030101000B03",
            "Signature": "AABBCCDD" * 8,
            "Counter0": "000005",
            "Tearing0": "BD",
            "Counter1": "000000",
            "Tearing1": "00",
            "Counter2": "000000",
            "Tearing2": "00",
        },
        "blocks": {str(i): "00000000" for i in range(20)},
    }
    dump["blocks"]["0"] = "041234AB"
    dump["blocks"]["1"] = "5678ABCD"
    dump["blocks"]["2"] = "EF480000"
    dump["blocks"]["4"] = "DEADBEEF"
    path = tmp_path / "test-ultralight-ev1.json"
    path.write_text(json.dumps(dump))
    return path


def test_load_ultralight_json(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert card.uid == "041CBE92E77A80"
    assert card.manufacturer == "NXP Semiconductors"
    assert card.readable_pages == 10


def test_ultralight_pages(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert 0 in card.pages
    assert 4 in card.pages
    assert card.pages[4] == bytes.fromhex("02D7C800")


def test_lock_bytes(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert card.lock_bytes == b"\x00\x00"
    assert card.lock_bits_set == []


def test_otp(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert card.otp == b"\x00\x00\x00\x00"
    assert not card.otp_is_programmed


def test_user_data(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    data = card.get_user_data()
    assert data.startswith(bytes.fromhex("02D7C800"))


def test_page_hex(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert card.page_hex(4) == "02D7C800"
    assert card.page_hex(99) == "--------"


def test_page_ascii(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert card.page_ascii(4) == "...."


def test_ev1_detection(sample_ultralight_ev1_json):
    card = load_ultralight(sample_ultralight_ev1_json)
    assert "EV1" in card.card_type
    assert "48b" in card.card_type


def test_counters(sample_ultralight_ev1_json):
    card = load_ultralight(sample_ultralight_ev1_json)
    assert card.counter0 == 5
    assert card.tearing0 == 0xBD


def test_generate_text_report(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    report = generate_ultralight_report(card, "text")
    assert "MIFARE Ultralight Forensic Analysis Report" in report
    assert "041CBE92E77A80" in report
    assert "02D7C800" in report


def test_generate_json_report(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    report = generate_ultralight_report(card, "json")
    data = json.loads(report)
    assert data["report_type"] == "ultralight_forensic"
    assert data["card"]["uid"] == "041CBE92E77A80"
    assert data["dump_status"]["pages_read"] == 10


def test_partial_dump_status(sample_ultralight_json):
    card = load_ultralight(sample_ultralight_json)
    assert not card.dump_complete


def test_load_binary_dump(tmp_path):
    raw = b"\x04\x12\x34\x56" + b"\x78\xAB\xCD\xEF" * 15
    path = tmp_path / "test.bin"
    path.write_bytes(raw)
    card = load_ultralight(path)
    assert len(card.pages) == 16


def test_load_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        load_ultralight("/nonexistent/path.json")


def test_lock_bits_parsing():
    card = UltralightCard(uid="04000000000000")
    card.pages[2] = bytes.fromhex("EF480300")
    locked = card.lock_bits_set
    assert "Page 3 (OTP)" in locked
    assert "Pages 4-9" in locked
