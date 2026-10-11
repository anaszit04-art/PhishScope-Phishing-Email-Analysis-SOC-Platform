
import json

import pytest

from src.dashboard_data import (
    get_risk,
    load_report,
    load_reports,
    summarize_all,
    summarize_case
)


def make_report(case_id="test-case", score=55):
    return {
        "tool": "PhishScope",
        "case_id": case_id,
        "generated_at": "2026-10-11T00:00:00+00:00",
        "email_analysis": {
            "headers": {
                "subject": "Synthetic test"
            }
        },
        "advanced_detection": {
            "findings": [
                {"rule_id": "EMAIL-001"}
            ]
        },
        "risk_assessment": {
            "score": score,
            "review_priority": "elevated"
        },
        "mitre_analysis": {
            "technique_candidates": [
                {"technique_id": "T1566.002"}
            ]
        }
    }


def test_load_valid_report(tmp_path):
    path = tmp_path / "case_test.json"
    path.write_text(json.dumps(make_report()))

    report = load_report(path)

    assert report["case_id"] == "test-case"


def test_reject_foreign_report(tmp_path):
    path = tmp_path / "case_foreign.json"
    path.write_text(
        json.dumps({
            "tool": "Unknown",
            "case_id": "x"
        })
    )

    with pytest.raises(ValueError):
        load_report(path)


def test_load_reports(tmp_path):
    for name in ("one", "two"):
        path = tmp_path / f"case_{name}.json"
        path.write_text(
            json.dumps(make_report(name))
        )

    reports, errors = load_reports(tmp_path)

    assert len(reports) == 2
    assert errors == []


def test_invalid_report_is_skipped(tmp_path):
    path = tmp_path / "case_invalid.json"
    path.write_text("{not valid JSON")

    reports, errors = load_reports(tmp_path)

    assert reports == []
    assert len(errors) == 1


def test_case_summary():
    row = summarize_case(make_report())

    assert row["Score"] == 55
    assert row["Findings"] == 1
    assert row["ATT&CK candidates"] == 1


def test_dashboard_averages():
    reports = [
        make_report("one", 40),
        make_report("two", 60)
    ]

    summary = summarize_all(reports)

    assert summary["total_cases"] == 2
    assert summary["average_score"] == 50.0


def test_missing_risk_is_safe():
    report = make_report()
    report.pop("risk_assessment")

    assert get_risk(report) is None

    summary = summarize_case(report)

    assert summary["Score"] is None
    assert summary["Priority"] == "not_assessed"


def test_invalid_score_is_ignored():
    report = make_report(score=150)

    assert get_risk(report) is None
