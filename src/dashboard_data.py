
"""
PhishScope — Hardened Dashboard Data Layer

Loads and summarizes locally stored investigation
reports for the Streamlit SOC dashboard.

Protections:
- Regular-file checks
- Symbolic-link rejection
- File size limit
- JSON parsing errors handled
- Report structure validation
- UUID filename/case ID consistency
- Bounded number of loaded cases
- Safe handling of older unscored reports

The module never edits investigation reports.
"""

import json
import math

from pathlib import Path

from src.report_validator import validate_report


MAX_REPORT_BYTES = 5 * 1024 * 1024
MAX_CASES = 500


def load_report(path):
    """Read and validate one local case report."""
    path = Path(path)

    if path.is_symlink():
        raise ValueError(
            "Symbolic-link reports are not allowed"
        )

    if not path.is_file():
        raise ValueError(
            "Report must be a regular file"
        )

    size = path.stat().st_size

    if size == 0:
        raise ValueError(
            "Report file is empty"
        )

    if size > MAX_REPORT_BYTES:
        raise ValueError(
            "Report exceeds 5 MB"
        )

    # Read at most one byte past the size limit,
    # so even a growing file cannot be read
    # without bounds.
    with path.open("rb") as handle:
        raw = handle.read(
            MAX_REPORT_BYTES + 1
        )

    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError(
            "Report exceeds 5 MB"
        )

    report = json.loads(
        raw.decode("utf-8")
    )

    validate_report(
        report,
        filename=path.name
    )

    return report


def load_reports(directory="reports"):
    """
    Load case reports independently.

    A malformed report is skipped with a warning.
    Other valid reports remain available.

    Returns:
        (reports, errors)
    """

    directory = Path(directory)

    if directory.is_symlink():
        return [], [
            "Report directory cannot be a symlink"
        ]

    if not directory.is_dir():
        return [], []

    reports = []
    errors = []

    paths = sorted(
        directory.glob("case_*.json"),
        key=lambda item: item.name
    )

    if len(paths) > MAX_CASES:
        errors.append(
            f"Report limit reached: only "
            f"{MAX_CASES} files were considered"
        )

        paths = paths[:MAX_CASES]

    for path in paths:
        try:
            report = load_report(path)

            # Used only inside the dashboard.
            # This field is not written to disk.
            report["_dashboard_filename"] = (
                path.name
            )

            reports.append(report)

        except (
            OSError,
            ValueError,
            TypeError,
            UnicodeError,
            json.JSONDecodeError
        ) as exc:
            errors.append(
                f"{path.name}: {exc}"
            )

    reports.sort(
        key=lambda item: str(
            item.get("generated_at") or ""
        ),
        reverse=True
    )

    return reports, errors


def get_risk(report):
    """
    Return a valid heuristic score or None.

    A missing score is not interpreted as zero.
    """

    risk = report.get("risk_assessment") or {}

    if not isinstance(risk, dict):
        return None

    score = risk.get("score")

    if isinstance(score, bool):
        return None

    if not isinstance(score, (int, float)):
        return None

    if not math.isfinite(score):
        return None

    if not 0 <= score <= 100:
        return None

    return score


def summarize_case(report):
    """
    Create an overview row for the dashboard.
    """

    email = report.get("email_analysis") or {}
    headers = email.get("headers") or {}

    advanced = (
        report.get("advanced_detection") or {}
    )

    risk = (
        report.get("risk_assessment") or {}
    )

    mitre = (
        report.get("mitre_analysis") or {}
    )

    findings = (
        advanced.get("findings") or []
    )

    techniques = (
        mitre.get("technique_candidates") or []
    )

    return {
        "Case ID": report.get("case_id", ""),
        "Generated": report.get(
            "generated_at", ""
        ),
        "Subject": headers.get(
            "subject", ""
        ),
        "Score": get_risk(report),
        "Priority": risk.get(
            "review_priority",
            "not_assessed"
        ),
        "Findings": len(findings),
        "ATT&CK candidates": len(techniques)
    }


def summarize_all(reports):
    """
    Aggregate local dashboard statistics.
    """

    priorities = {}

    for report in reports:
        risk = (
            report.get("risk_assessment") or {}
        )

        priority = risk.get(
            "review_priority",
            "not_assessed"
        )

        priorities[priority] = (
            priorities.get(priority, 0) + 1
        )

    scores = []

    for report in reports:
        score = get_risk(report)

        if score is not None:
            scores.append(score)

    average = None

    if scores:
        average = round(
            sum(scores) / len(scores),
            1
        )

    return {
        "total_cases": len(reports),
        "scored_cases": len(scores),
        "average_score": average,
        "priorities": priorities
    }
