
import json
import os

from src.report_generator import (
    generate_report,
    sha256_file
)


def test_sha256_file(tmp_path):
    sample = tmp_path / "evidence.txt"
    sample.write_bytes(b"test")

    expected = (
        "9f86d081884c7d659a2feaa0c55ad015"
        "a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )

    assert sha256_file(sample) == expected


def test_generate_report(tmp_path):
    evidence = tmp_path / "sample.eml"
    evidence.write_bytes(b"Sample email")

    report_dir = tmp_path / "reports"

    path = generate_report(
        email_result={"headers": {}},
        mitre_result={
            "technique_candidates": []
        },
        evidence_paths={
            "email": evidence
        },
        output_dir=report_dir
    )

    assert path.exists()

    report = json.loads(path.read_text())

    assert report["tool"] == "PhishScope"
    assert report["case_status"] == (
        "requires_analyst_review"
    )
    assert len(report["evidence"]) == 1
    assert report["evidence"][0]["sha256"] == (
        sha256_file(evidence)
    )


def test_unique_case_ids(tmp_path):
    first = generate_report(
        {},
        {},
        output_dir=tmp_path
    )

    second = generate_report(
        {},
        {},
        output_dir=tmp_path
    )

    assert first != second


def test_report_permissions(tmp_path):
    path = generate_report(
        {},
        {},
        output_dir=tmp_path
    )

    permissions = os.stat(path).st_mode & 0o777

    assert permissions == 0o600


def test_optional_evidence(tmp_path):
    path = generate_report(
        email_result={},
        mitre_result={},
        output_dir=tmp_path
    )

    report = json.loads(path.read_text())

    assert report["redirect_analysis"] is None
    assert report["feed_context"] is None
