
"""
PhishScope — Case Timeline and Analyst Export

Combines a generated investigation report with separate
analyst case-management metadata.

Exports:
- Chronological investigation timeline
- Human-readable TXT report
- Structured JSON report

Never modifies the source evidence, original reports,
or case-management records.
"""

import json

from datetime import datetime, timezone


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp for timeline ordering."""
    if not isinstance(value, str) or not value:
        return datetime.min.replace(tzinfo=timezone.utc)

    try:
        result = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)

        return result.astimezone(timezone.utc)

    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def build_timeline(report, case_record):
    """
    Construct a chronological timeline.

    Uses recorded timestamps; it does not invent
    an email-delivery or compromise timestamp.
    """
    events = []

    generated = report.get("generated_at")

    if generated:
        events.append({
            "timestamp": generated,
            "type": "report_created",
            "actor": "PhishScope",
            "description": "Investigation report generated"
        })

    notes_by_id = {
        note.get("note_id"): note
        for note in case_record.get("notes", [])
        if isinstance(note, dict) and note.get("note_id")
    }

    referenced_notes = set()

    for action in case_record.get("history", []):
        if not isinstance(action, dict):
            continue

        kind = action.get("action", "unknown")
        timestamp = action.get("timestamp")
        actor = action.get("actor", "Unknown")

        if kind == "status_change":
            description = (
                f"Status changed from "
                f"{action.get('previous', '?')} "
                f"to {action.get('new', '?')}"
            )

        elif kind == "note_added":
            note_id = action.get("note_id")
            note = notes_by_id.get(note_id)

            if note is not None:
                referenced_notes.add(note_id)
                description = "Analyst note added"
            else:
                description = (
                    "Note addition recorded; note content unavailable"
                )

        else:
            description = f"Recorded action: {kind}"

        event = {
            "timestamp": timestamp,
            "type": kind,
            "actor": actor,
            "description": description
        }

        if kind == "note_added":
            note = notes_by_id.get(action.get("note_id"))
            if note is not None:
                event["note"] = str(note.get("text", ""))

        events.append(event)

    # Legacy records might contain notes without
    # corresponding history events.
    for note in case_record.get("notes", []):
        if not isinstance(note, dict):
            continue

        note_id = note.get("note_id")

        if note_id in referenced_notes:
            continue

        events.append({
            "timestamp": note.get("timestamp"),
            "type": "note_record",
            "actor": note.get("actor", "Unknown"),
            "description": "Analyst note recorded",
            "note": str(note.get("text", ""))
        })

    events.sort(
        key=lambda event: parse_timestamp(
            event.get("timestamp")
        )
    )

    return events


def build_analyst_export(report, case_record):
    """
    Combine the original investigation and analyst
    annotations into a new in-memory export document.
    """
    if not isinstance(report, dict):
        raise ValueError("Investigation report must be an object")

    if not isinstance(case_record, dict):
        raise ValueError("Case metadata must be an object")

    case_id = report.get("case_id")

    if (
        not isinstance(case_id, str)
        or case_record.get("case_id") != case_id
    ):
        raise ValueError("Case IDs do not match")

    email = report.get("email_analysis") or {}
    headers = email.get("headers") or {}
    iocs = email.get("iocs") or {}

    advanced = report.get("advanced_detection") or {}
    risk = report.get("risk_assessment") or {}
    mitre = report.get("mitre_analysis") or {}
    feed = report.get("feed_context") or {}

    evidence = report.get("evidence") or []

    indicators = []

    for item in iocs.get("url_details") or []:
        if not isinstance(item, dict):
            continue

        # Do not place full URLs with possible tokens
        # into the human-readable export.
        hostname = item.get("hostname")

        if isinstance(hostname, str) and hostname:
            indicators.append(hostname)

    techniques = []

    for item in mitre.get("technique_candidates") or []:
        if isinstance(item, dict):
            techniques.append({
                "id": item.get("technique_id"),
                "name": item.get("technique_name"),
                "status": item.get("status")
            })

    findings = []

    for item in advanced.get("findings") or []:
        if isinstance(item, dict):
            findings.append({
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "description": item.get("description")
            })

    attachments = email.get("attachments") or []

    return {
        "tool": "PhishScope",
        "export_schema_version": "1.0",
        "exported_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "case_id": case_id,
        "case_status": case_record.get("status", "open"),
        "report_created_at": report.get("generated_at"),
        "case_updated_at": case_record.get("updated_at"),
        "email": {
            "subject": headers.get("subject"),
            "sender": headers.get("sender_address"),
            "reply_to": headers.get("reply_to_address"),
            "url_count": iocs.get("total_urls", 0),
            "attachment_count": len(attachments),
            "unique_hostnames": sorted(set(indicators))
        },
        "risk_assessment": {
            "score": risk.get("score"),
            "review_priority": risk.get(
                "review_priority", "not_assessed"
            ),
            "verdict": risk.get(
                "verdict", "not_determined"
            ),
            "contributions": risk.get("contributions") or []
        },
        "advanced_findings": findings,
        "mitre_candidates": techniques,
        "feed_context": {
            "source": feed.get("source"),
            "download_time": feed.get("feed_download_time"),
            "match_counts": feed.get("match_counts") or {},
            "feed_integrity": feed.get("feed_integrity") or {}
        },
        "evidence": [
            {
                "type": item.get("type"),
                "filename": item.get("filename"),
                "sha256": item.get("sha256"),
                "size_bytes": item.get("size_bytes")
            }
            for item in evidence
            if isinstance(item, dict)
        ],
        "timeline": build_timeline(report, case_record),
        "analyst_notes": [
            {
                "timestamp": note.get("timestamp"),
                "actor": note.get("actor"),
                "text": note.get("text")
            }
            for note in case_record.get("notes", [])
            if isinstance(note, dict)
        ],
        "limitations": [
            "Exported findings require analyst interpretation.",
            "Risk scores are heuristic review priorities.",
            "Reported SPF, DKIM, and DMARC are not independently verified.",
            "ATT&CK techniques are candidates, not confirmed execution.",
            "Hostnames may be shared by unrelated services.",
            "Full URL indicators are intentionally omitted from this export.",
            "An analyst label is not an authenticated identity.",
            "The application-level history is not tamper-proof.",
            "The export does not independently rehash evidence files."
        ]
    }


def export_json_bytes(document):
    """Serialize a structured export for download."""
    return (
        json.dumps(
            document,
            indent=2,
            ensure_ascii=False
        ) + "\n"
    ).encode("utf-8")


def export_text(document):
    """
    Produce a readable plain-text investigation summary.

    Strings are quoted using JSON encoding to make
    line breaks and control characters visible.
    """

    def quoted(value):
        return json.dumps(
            value,
            ensure_ascii=True
        )

    lines = [
        "=" * 60,
        "PHISHSCOPE — ANALYST INVESTIGATION REPORT",
        "=" * 60,
        f"Case ID: {document['case_id']}",
        f"Exported: {document['exported_at']}",
        f"Case status: {document['case_status']}",
        "",
        "EMAIL SUMMARY",
        "-" * 60
    ]

    email = document["email"]

    for key in (
        "subject",
        "sender",
        "reply_to",
        "url_count",
        "attachment_count"
    ):
        lines.append(
            f"{key}: {quoted(email.get(key))}"
        )

    lines.append("")
    lines.append("HOSTNAME INDICATORS")
    lines.append("-" * 60)

    for hostname in email["unique_hostnames"]:
        lines.append(f"- {quoted(hostname)}")

    lines.extend([
        "",
        "RISK ASSESSMENT",
        "-" * 60
    ])

    risk = document["risk_assessment"]

    lines.append(f"Score: {risk.get('score')}")
    lines.append(
        f"Priority: {risk.get('review_priority')}"
    )
    lines.append(
        f"Verdict: {risk.get('verdict')}"
    )

    for contribution in risk["contributions"]:
        lines.append(
            f"+{contribution.get('points', 0)} "
            f"{contribution.get('identifier', '')}"
        )

    lines.extend([
        "",
        "ADVANCED DETECTIONS",
        "-" * 60
    ])

    for finding in document["advanced_findings"]:
        lines.append(
            f"{finding.get('rule_id')} "
            f"[{finding.get('severity')}] "
            f"{quoted(finding.get('description'))}"
        )

    lines.extend([
        "",
        "MITRE ATT&CK CANDIDATES",
        "-" * 60
    ])

    for technique in document["mitre_candidates"]:
        lines.append(
            f"{technique.get('id')} — "
            f"{quoted(technique.get('name'))} "
            f"({technique.get('status')})"
        )

    lines.extend([
        "",
        "EVIDENCE MANIFEST",
        "-" * 60
    ])

    for item in document["evidence"]:
        lines.append(
            f"Type: {quoted(item.get('type'))}"
        )
        lines.append(
            f"Filename: {quoted(item.get('filename'))}"
        )
        lines.append(
            f"SHA-256: {item.get('sha256')}"
        )
        lines.append("")

    lines.extend([
        "",
        "CHRONOLOGICAL CASE TIMELINE",
        "-" * 60
    ])

    for event in document["timeline"]:
        lines.append(
            f"{event.get('timestamp') or 'Unknown time'} "
            f"| {quoted(event.get('actor'))} "
            f"| {event.get('type')}"
        )
        lines.append(
            f"  {quoted(event.get('description'))}"
        )

        if "note" in event:
            lines.append(
                f"  Note: {quoted(event['note'])}"
            )

    lines.extend([
        "",
        "LIMITATIONS",
        "-" * 60
    ])

    for limitation in document["limitations"]:
        lines.append(f"- {limitation}")

    lines.extend([
        "",
        "END OF REPORT",
        ""
    ])

    return "\n".join(lines)
