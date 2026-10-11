
import json
import uuid

import pytest

from src.case_export import (
    build_analyst_export,
    build_timeline,
    export_json_bytes,
    export_text,
    parse_timestamp
)


def sample_data():
    case_id = str(uuid.uuid4())

    report = {
        "case_id": case_id,
        "generated_at": "2026-10-11T01:00:00+00:00",
        "email_analysis": {
            "headers": {
                "subject": "Synthetic test",
                "sender_address": "sender@example.invalid",
                "reply_to_address": "reply@example.invalid"
            },
            "iocs": {
                "total_urls": 1,
                "url_details": [
                    {
                        "url": "https://login.example.invalid/verify",
                        "hostname": "login.example.invalid"
                    }
                ]
            },
            "attachments": []
        },
        "advanced_detection": {
            "findings": [
                {
                    "rule_id": "EMAIL-002",
                    "severity": "medium",
                    "description": "Link mismatch"
                }
            ]
        },
        "risk_assessment": {
            "score": 20,
            "review_priority": "routine",
            "verdict": "not_determined",
            "contributions": []
        },
        "mitre_analysis": {
            "technique_candidates": [
                {
                    "technique_id": "T1566.002",
                    "technique_name": "Phishing: Spearphishing Link",
                    "status": "candidate"
                }
            ]
        },
        "evidence": [
            {
                "type": "email",
                "filename": "sample.eml",
                "sha256": "a" * 64,
                "size_bytes": 120
            }
        ]
    }

    note_id = str(uuid.uuid4())

    case_record = {
        "case_id": case_id,
        "status": "in_review",
        "updated_at": "2026-10-11T01:10:00+00:00",
        "notes": [
            {
                "note_id": note_id,
                "timestamp": "2026-10-11T01:10:00+00:00",
                "actor": "SOC Analyst",
                "text": "Test analyst note"
            }
        ],
        "history": [
            {
                "timestamp": "2026-10-11T01:05:00+00:00",
                "actor": "SOC Analyst",
                "action": "status_change",
                "previous": "open",
                "new": "in_review"
            },
            {
                "timestamp": "2026-10-11T01:10:00+00:00",
                "actor": "SOC Analyst",
                "action": "note_added",
                "note_id": note_id
            }
        ]
    }

    return report, case_record


def test_timeline_chronological():
    report, record = sample_data()

    timeline = build_timeline(report, record)

    assert len(timeline) == 3
    assert timeline[0]["type"] == "report_created"
    assert timeline[1]["type"] == "status_change"
    assert timeline[2]["type"] == "note_added"


def test_note_appears_in_timeline():
    report, record = sample_data()

    timeline = build_timeline(report, record)

    assert timeline[-1]["note"] == "Test analyst note"


def test_export_summary():
    report, record = sample_data()

    document = build_analyst_export(report, record)

    assert document["case_id"] == report["case_id"]
    assert document["case_status"] == "in_review"
    assert document["risk_assessment"]["score"] == 20
    assert len(document["advanced_findings"]) == 1


def test_export_contains_evidence_hash():
    report, record = sample_data()

    document = build_analyst_export(report, record)

    assert document["evidence"][0]["sha256"] == "a" * 64


def test_json_export_valid():
    report, record = sample_data()

    document = build_analyst_export(report, record)
    raw = export_json_bytes(document)

    recovered = json.loads(raw)

    assert recovered["case_id"] == report["case_id"]
    assert len(recovered["timeline"]) == 3


def test_plain_text_export():
    report, record = sample_data()

    document = build_analyst_export(report, record)
    text = export_text(document)

    assert "ANALYST INVESTIGATION REPORT" in text
    assert "Test analyst note" in text
    assert "T1566.002" in text


def test_case_id_mismatch_rejected():
    report, record = sample_data()
    record["case_id"] = str(uuid.uuid4())

    with pytest.raises(ValueError):
        build_analyst_export(report, record)


def test_timestamp_parsing():
    timestamp = parse_timestamp(
        "2026-10-11T01:00:00+00:00"
    )

    assert timestamp.year == 2026
    assert parse_timestamp("invalid").year == 1
