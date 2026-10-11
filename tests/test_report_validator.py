
import json
import uuid

import pytest

from src.dashboard_data import (
    get_risk,
    load_report,
    load_reports
)

from src.report_validator import (
    MAX_URL_DETAILS,
    validate_report
)


def make_report(case_id=None):
    return {
        "tool": "PhishScope",
        "case_id": case_id or str(uuid.uuid4()),
        "generated_at": "2026-10-11T01:00:00+00:00",
        "email_analysis": {
            "headers": {
                "subject": "Synthetic test email"
            },
            "iocs": {
                "total_urls": 1,
                "url_details": [
                    {
                        "url": "https://example.invalid/",
                        "hostname": "example.invalid"
                    }
                ]
            },
            "attachments": []
        },
        "advanced_detection": {
            "findings": []
        },
        "risk_assessment": {
            "score": 55,
            "review_priority": "elevated",
            "contributions": []
        },
        "mitre_analysis": {
            "technique_candidates": []
        },
        "evidence": []
    }


def write_report(tmp_path, report):
    path = (
        tmp_path
        / f"case_{report['case_id']}.json"
    )

    path.write_text(
        json.dumps(report),
        encoding="utf-8"
    )

    return path


def test_valid_report():
    report = make_report()

    assert validate_report(report) is report


def test_valid_report_loads(tmp_path):
    report = make_report()
    path = write_report(tmp_path, report)

    loaded = load_report(path)

    assert loaded["case_id"] == report["case_id"]


def test_reject_invalid_ioc_structure():
    report = make_report()

    report["email_analysis"]["iocs"][
        "url_details"
    ] = "invalid"

    with pytest.raises(ValueError):
        validate_report(report)


def test_reject_non_numeric_score():
    report = make_report()

    report["risk_assessment"]["score"] = "high"

    with pytest.raises(ValueError):
        validate_report(report)


def test_reject_nan_score():
    report = make_report()

    report["risk_assessment"]["score"] = float("nan")

    with pytest.raises(ValueError):
        validate_report(report)


def test_reject_filename_case_mismatch(tmp_path):
    report = make_report()

    wrong_case_id = str(uuid.uuid4())

    path = tmp_path / f"case_{wrong_case_id}.json"

    path.write_text(
        json.dumps(report),
        encoding="utf-8"
    )

    with pytest.raises(ValueError):
        load_report(path)


def test_reject_oversized_ioc_list():
    report = make_report()

    report["email_analysis"]["iocs"][
        "url_details"
    ] = [{}] * (MAX_URL_DETAILS + 1)

    with pytest.raises(ValueError):
        validate_report(report)


def test_reject_symlink_report(tmp_path):
    report = make_report()
    original = write_report(tmp_path, report)

    link = tmp_path / "linked.json"
    link.symlink_to(original)

    with pytest.raises(ValueError):
        load_report(link)


def test_older_unscored_report_supported():
    report = make_report()

    report.pop("risk_assessment")

    assert validate_report(report) is report
    assert get_risk(report) is None


def test_bad_report_does_not_hide_good_case(tmp_path):
    valid = make_report()

    write_report(tmp_path, valid)

    bad = tmp_path / "case_corrupt.json"
    bad.write_text("{broken", encoding="utf-8")

    reports, errors = load_reports(tmp_path)

    assert len(reports) == 1
    assert len(errors) == 1
    assert reports[0]["case_id"] == valid["case_id"]


def test_reject_wrong_tool():
    report = make_report()

    report["tool"] = "Unknown"

    with pytest.raises(ValueError):
        validate_report(report)


def test_reject_boolean_score():
    report = make_report()

    report["risk_assessment"]["score"] = True

    with pytest.raises(ValueError):
        validate_report(report)
