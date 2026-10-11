
"""
PhishScope — Investigation Report Validator

Validates locally stored case report structures
before they are displayed in the SOC dashboard.

This module does not execute evidence, open URLs,
perform DNS lookups, or modify reports.

Compatibility:
- Supports older reports without risk assessment.
- Supports reports from Modules 3–13.
- Rejects malformed or inconsistent structures.
"""

import math
import uuid
from pathlib import Path


MAX_URL_DETAILS = 10000
MAX_FINDINGS = 2000
MAX_EVIDENCE_ITEMS = 1000
MAX_TECHNIQUES = 500
MAX_TIMELINE_ITEMS = 5000
MAX_FIELD_LENGTH = 100000


def require_object(value, name):
    """Require a JSON object."""
    if not isinstance(value, dict):
        raise ValueError(
            f"{name} must be a JSON object"
        )

    return value


def optional_object(parent, field):
    """Read an optional object field safely."""
    value = parent.get(field)

    if value is None:
        return {}

    return require_object(value, field)


def optional_list(parent, field, maximum):
    """Read an optional list with a size limit."""
    value = parent.get(field)

    if value is None:
        return []

    if not isinstance(value, list):
        raise ValueError(
            f"{field} must be a JSON array"
        )

    if len(value) > maximum:
        raise ValueError(
            f"{field} exceeds maximum length"
        )

    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(
                f"{field}[{index}] must be an object"
            )

    return value


def validate_string(value, field, required=False):
    """Validate a text field without interpreting it."""
    if value is None and not required:
        return

    if not isinstance(value, str):
        raise ValueError(
            f"{field} must be text"
        )

    if required and not value.strip():
        raise ValueError(
            f"{field} must not be empty"
        )

    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError(
            f"{field} is too long"
        )


def validate_score(risk):
    """Validate a heuristic score if present."""
    score = risk.get("score")

    if score is None:
        return

    if isinstance(score, bool):
        raise ValueError(
            "Risk score cannot be a boolean"
        )

    if not isinstance(score, (int, float)):
        raise ValueError(
            "Risk score must be numeric"
        )

    if not math.isfinite(score):
        raise ValueError(
            "Risk score must be finite"
        )

    if not 0 <= score <= 100:
        raise ValueError(
            "Risk score must be between 0 and 100"
        )


def validate_filename_case_id(report, filename):
    """
    Cross-check UUID-based PhishScope filenames.

    Older test fixtures and nonstandard report names
    remain supported.
    """
    if filename is None:
        return

    path = Path(filename)

    if not (
        path.name.startswith("case_")
        and path.suffix == ".json"
    ):
        return

    candidate = path.stem.removeprefix("case_")

    try:
        parsed = uuid.UUID(candidate)
    except (ValueError, AttributeError):
        return

    if str(parsed) != candidate:
        return

    if report["case_id"] != candidate:
        raise ValueError(
            "Report case ID does not match filename"
        )


def validate_report(report, filename=None):
    """
    Validate PhishScope report data.

    Returns the original object if valid.

    Does not modify the report.
    """

    require_object(report, "Report")

    if report.get("tool") != "PhishScope":
        raise ValueError(
            "Not a PhishScope investigation report"
        )

    validate_string(
        report.get("case_id"),
        "case_id",
        required=True
    )

    validate_filename_case_id(
        report,
        filename
    )

    for field in (
        "generated_at",
        "case_status",
        "schema_version"
    ):
        validate_string(
            report.get(field),
            field
        )

    # Email analysis
    email = optional_object(
        report,
        "email_analysis"
    )

    headers = optional_object(
        email,
        "headers"
    )

    for field in (
        "subject",
        "sender_address",
        "reply_to_address"
    ):
        validate_string(
            headers.get(field),
            f"headers.{field}"
        )

    iocs = optional_object(
        email,
        "iocs"
    )

    url_details = optional_list(
        iocs,
        "url_details",
        MAX_URL_DETAILS
    )

    for item in url_details:
        validate_string(
            item.get("url"),
            "url_details.url"
        )

        validate_string(
            item.get("hostname"),
            "url_details.hostname"
        )

    optional_list(
        email,
        "attachments",
        MAX_EVIDENCE_ITEMS
    )

    # Advanced detections
    advanced = optional_object(
        report,
        "advanced_detection"
    )

    optional_list(
        advanced,
        "findings",
        MAX_FINDINGS
    )

    # Risk assessment
    risk = optional_object(
        report,
        "risk_assessment"
    )

    validate_score(risk)

    validate_string(
        risk.get("review_priority"),
        "review_priority"
    )

    optional_list(
        risk,
        "contributions",
        MAX_FINDINGS
    )

    # Threat intelligence
    feed = optional_object(
        report,
        "feed_context"
    )

    optional_list(
        feed,
        "findings",
        MAX_URL_DETAILS
    )

    optional_object(
        feed,
        "match_counts"
    )

    optional_object(
        feed,
        "feed_integrity"
    )

    # MITRE ATT&CK
    mitre = optional_object(
        report,
        "mitre_analysis"
    )

    optional_list(
        mitre,
        "technique_candidates",
        MAX_TECHNIQUES
    )

    # Redirect analysis
    redirects = optional_object(
        report,
        "redirect_analysis"
    )

    for field in (
        "initial_url",
        "final_url"
    ):
        validate_string(
            redirects.get(field),
            f"redirect_analysis.{field}"
        )

    # Evidence manifest
    evidence = optional_list(
        report,
        "evidence",
        MAX_EVIDENCE_ITEMS
    )

    for item in evidence:
        for field in (
            "type",
            "filename",
            "sha256"
        ):
            validate_string(
                item.get(field),
                f"evidence.{field}"
            )

    return report
