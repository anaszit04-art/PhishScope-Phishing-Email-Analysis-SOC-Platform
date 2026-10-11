
import json
import pytest

from pathlib import Path
from src.evidence_importer import (
    import_email,
    validate_email,
    hash_file
)


def make_sample(tmp_path):
    sample = tmp_path / "sample.eml"
    sample.write_bytes(
        b"From: tester@example.invalid\n"
        b"To: analyst@example.invalid\n"
        b"Subject: Test\n"
        b"\n"
        b"Safe test message\n"
    )
    return sample


def test_valid_email(tmp_path):
    sample = make_sample(tmp_path)

    result = validate_email(sample)

    assert result["size_bytes"] > 0
    assert len(result["sha256"]) == 64


def test_evidence_copy_integrity(tmp_path):
    sample = make_sample(tmp_path)

    result = import_email(
        sample,
        "Pytest synthetic sample",
        evidence_root=tmp_path / "evidence"
    )

    assert (
        hash_file(sample)
        == hash_file(result["evidence_path"])
    )


def test_metadata_created(tmp_path):
    sample = make_sample(tmp_path)

    result = import_email(
        sample,
        "Testing acquisition",
        evidence_root=tmp_path / "evidence"
    )

    metadata = json.loads(
        Path(result["metadata_path"]).read_text()
    )

    assert metadata["case_id"] == result["case_id"]
    assert metadata["hash_algorithm"] == "SHA-256"


def test_invalid_extension(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("Invalid sample")

    with pytest.raises(ValueError):
        validate_email(sample)


def test_empty_email(tmp_path):
    sample = tmp_path / "empty.eml"
    sample.write_bytes(b"")

    with pytest.raises(ValueError):
        validate_email(sample)


def test_unique_evidence_cases(tmp_path):
    sample = make_sample(tmp_path)
    root = tmp_path / "evidence"

    first = import_email(sample, "Test", root)
    second = import_email(sample, "Test", root)

    assert first["case_id"] != second["case_id"]


def test_original_not_modified(tmp_path):
    sample = make_sample(tmp_path)
    original = sample.read_bytes()

    import_email(
        sample,
        "Integrity test",
        evidence_root=tmp_path / "evidence"
    )

    assert sample.read_bytes() == original
