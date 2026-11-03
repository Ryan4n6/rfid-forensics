"""Tests for DESFire loader and report generation."""

import json
import pytest
from pathlib import Path

from rfid_forensics.desfire_loader import (
    DesfireCard, DesfireApp, DesfireFile, DesfireKey,
    load_desfire, load_desfire_json,
)
from rfid_forensics.desfire_report import generate_desfire_report


@pytest.fixture
def sample_desfire_json(tmp_path):
    """Create a sample DESFire dump JSON for testing."""
    dump = {
        "Created": "proxmark3",
        "FileType": "mfdes v1",
        "Version": 1,
        "Card": {
            "UID": "04671F02D21490",
            "ATQA": "4403",
            "SAK": "20",
            "VersionHW": "04010133001605",
            "VersionSW": "04010103001605",
            "Signature": "8345BD6E6A832E0F4B9CCEC3A4542F6B",
            "FreeMem": 2112,
        },
        "Applications": {
            "000000": {
                "KeySettings": "0F",
                "NumKeys": 1,
                "KeyType": "2tdea",
                "Authenticated": True,
                "Keys": {
                    "0": {"Version": "00", "Key": "00000000000000000000000000000000"}
                },
            },
            "000001": {
                "ISOFileID": "0001",
                "KeySettings": "0F",
                "NumKeys": 14,
                "KeyType": "2tdea",
                "Authenticated": True,
                "Keys": {
                    "0": {"Version": "00", "Key": "00000000000000000000000000000000"},
                    "1": {"Version": "00"},
                },
                "Files": {
                    "01": {
                        "Type": "standard",
                        "TypeRaw": "00",
                        "CommMode": "plain",
                        "AccessRights": "EEEE",
                        "ISOFileID": "0001",
                        "FileSize": 32,
                        "Read": True,
                        "Data": "48656C6C6F2044455346697265210000000000000000000000000000000000",
                    }
                },
            },
        },
    }
    path = tmp_path / "test-desfire.json"
    path.write_text(json.dumps(dump))
    return path


def test_load_desfire_json(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    assert card.uid == "04671F02D21490"
    assert card.card_type == "DESFire EV3"
    assert card.storage_size == "2KB"
    assert card.manufacturer == "NXP Semiconductors"
    assert card.free_memory == 2112


def test_desfire_applications(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    assert len(card.applications) == 2
    assert "000000" in card.applications
    assert "000001" in card.applications
    assert card.num_apps == 1


def test_picc_master_app(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    picc = card.applications["000000"]
    assert picc.is_picc_master
    assert picc.key_type == "2tdea"
    assert picc.num_keys == 1
    assert picc.authenticated


def test_custom_app(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    app = card.applications["000001"]
    assert not app.is_picc_master
    assert app.aid_function == "Custom Application"
    assert app.iso_file_id == "0001"
    assert app.num_keys == 14


def test_app_keys(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    app = card.applications["000001"]
    assert 0 in app.keys
    assert 1 in app.keys
    assert app.keys[0].is_known
    assert app.keys[0].is_default
    assert not app.keys[1].is_known


def test_default_keys(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    defaults = card.default_keys()
    assert len(defaults) == 2


def test_file_parsing(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    app = card.applications["000001"]
    assert "01" in app.files
    f = app.files["01"]
    assert f.file_type == "standard"
    assert f.comm_mode == "plain"
    assert f.file_size == 32
    assert f.access_rights == "EEEE"
    assert f.data is not None
    assert f.data.startswith(b"Hello DESFire!")


def test_file_access_rights(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    f = card.applications["000001"].files["01"]
    assert f.access_read == "free"
    assert f.access_write == "free"
    assert f.access_rw == "free"
    assert f.access_change == "free"


def test_file_data_ascii(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    f = card.applications["000001"].files["01"]
    ascii_str = f.data_ascii()
    assert ascii_str.startswith("Hello DESFire!")


def test_key_settings_flags(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    app = card.applications["000001"]
    flags = app.ks1_flags()
    assert flags["config_changeable"] is True
    assert flags["free_create_delete"] is True
    assert flags["free_listing"] is True
    assert flags["master_changeable"] is True


def test_generate_text_report(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    report = generate_desfire_report(card, "text")
    assert "DESFire Forensic Analysis Report" in report
    assert "04671F02D21490" in report
    assert "DESFire EV3" in report
    assert "Hello DESFire!" in report
    assert "SECURITY FINDINGS" in report
    assert "factory default" in report


def test_generate_json_report(sample_desfire_json):
    card = load_desfire(sample_desfire_json)
    report = generate_desfire_report(card, "json")
    data = json.loads(report)
    assert data["report_type"] == "desfire_forensic"
    assert data["card"]["uid"] == "04671F02D21490"
    assert data["summary"]["num_applications"] == 1
    assert data["summary"]["default_keys"] == 2


def test_known_aid_prefixes():
    app = DesfireApp(aid="F50001")
    assert app.aid_function == "NDEF (NFC Forum)"

    app = DesfireApp(aid="470001")
    assert app.aid_function == "Gallagher Access Control"


def test_card_type_detection():
    card = DesfireCard(uid="04000000000000", atqa="", sak="", version_hw="04010100001605")
    assert "EV0" in card.card_type or "D40" in card.card_type

    card = DesfireCard(uid="04000000000000", atqa="", sak="", version_hw="04010101001605")
    assert "EV1" in card.card_type

    card = DesfireCard(uid="04000000000000", atqa="", sak="", version_hw="04010112001605")
    assert "EV2" in card.card_type

    card = DesfireCard(uid="04000000000000", atqa="", sak="", version_hw="04010133001605")
    assert "EV3" in card.card_type


def test_load_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        load_desfire("/nonexistent/path.json")


def test_load_wrong_format(tmp_path):
    path = tmp_path / "test.bin"
    path.write_bytes(b"\x00" * 100)
    with pytest.raises(ValueError, match="JSON format"):
        load_desfire(path)
