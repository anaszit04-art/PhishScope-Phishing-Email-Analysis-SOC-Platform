
"""
PhishScope — Unified Investigation Report Generator

Combines results from:
- Email analysis
- Advanced phishing detection
- Redirect-chain analysis
- IOC enrichment and threat intelligence
- MITRE ATT&CK mapping
- Explainable risk assessment

Creates a separate JSON report for each investigation.

Security features:
- SHA-256 evidence hashing
- Unique case identifiers
- UTC timestamps
- Private report permissions (0600 on POSIX)
- Exclusive file creation to avoid overwriting reports

The generated report contains investigative observations,
not a confirmed phishing verdict.
"""

import hashlib
import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path


SCHEMA_VERSION = "1.1"
TOOL_NAME = "PhishScope"


def sha256_file(path):
    """
    Calculate the SHA-256 hash of a local evidence file.

    Reads in chunks to avoid loading the entire file
    into memory.
    """

    digest = hashlib.sha256()

    with Path(path).open("rb") as file:
        for chunk in iter(
            lambda: file.read(65536),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def collect_evidence(evidence_paths):
    """
    Collect file metadata and SHA-256 hashes.

    evidence_paths example:
        {
            "email": "data/emails/sample.eml",
            "feed": "data/feeds/openphish.txt",
            "redirects": "data/redirects/sample.json"
        }
    """

    evidence = []

    for evidence_type, path in evidence_paths.items():
        evidence_path = Path(path)

        if not evidence_path.is_file():
            raise FileNotFoundError(
                f"Evidence file not found: {evidence_path}"
            )

        evidence.append({
            "type": evidence_type,
            "filename": evidence_path.name,
            "sha256": sha256_file(evidence_path),
            "size_bytes": evidence_path.stat().st_size
        })

    return evidence


def generate_report(
    email_result,
    mitre_result,
    redirect_result=None,
    feed_summary=None,
    evidence_paths=None,
    output_dir="reports",
    advanced_result=None,
    risk_result=None
):
    """
    Generate a unified JSON investigation report.

    Parameters:
        email_result:
            Parsed email headers, URLs, attachments, and IOCs.

        mitre_result:
            Candidate MITRE ATT&CK techniques.

        redirect_result:
            Optional analysis of recorded redirects.

        feed_summary:
            Optional offline IOC enrichment results.

        evidence_paths:
            Dictionary of local evidence files.

        output_dir:
            Destination directory for JSON reports.

        advanced_result:
            Optional advanced detection findings.

        risk_result:
            Optional explainable risk assessment.

    Returns:
        pathlib.Path pointing to the saved JSON report.
    """

    if evidence_paths is None:
        evidence_paths = {}

    # -----------------------------------------
    # Evidence integrity
    # -----------------------------------------

    evidence = collect_evidence(evidence_paths)

    # -----------------------------------------
    # Case identification
    # -----------------------------------------

    case_id = str(uuid.uuid4())

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    # -----------------------------------------
    # Unified investigation report
    # -----------------------------------------

    report = {
        "case_id": case_id,

        "tool": TOOL_NAME,

        "schema_version": SCHEMA_VERSION,

        "generated_at": generated_at,

        "case_status": "requires_analyst_review",

        "evidence": evidence,

        # Module 3 — Email analysis
        "email_analysis": email_result,

        # Module 7 — Advanced detection
        "advanced_detection": advanced_result,

        # Module 10 — Explainable risk assessment
        "risk_assessment": risk_result,

        # Module 4 — Recorded redirect analysis
        "redirect_analysis": redirect_result,

        # Module 9 — Offline IOC enrichment
        "feed_context": feed_summary,

        # Module 5 — MITRE ATT&CK mapping
        "mitre_analysis": mitre_result,

        # Forensic and analytical limitations
        "limitations": [
            (
                "Email authentication results were extracted "
                "from message headers and were not "
                "independently verified."
            ),
            (
                "Redirect analysis relies on supplied "
                "recorded HTTP evidence."
            ),
            (
                "MITRE ATT&CK mappings represent "
                "candidate techniques, not confirmed execution."
            ),
            (
                "Phishing intelligence matches are "
                "investigative leads, not independent "
                "proof of malicious behavior."
            ),
            (
                "Hostname-only matches may represent "
                "shared or compromised infrastructure."
            ),
            (
                "A missing intelligence match does not "
                "establish that an email or URL is safe."
            ),
            (
                "Risk scores are heuristic review priorities, "
                "not calibrated probabilities or "
                "confirmed phishing verdicts."
            ),
            (
                "No phishing destinations or email "
                "attachments were executed by this module."
            )
        ]
    }

    # -----------------------------------------
    # Create the output directory
    # -----------------------------------------

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------
    # Generate unique report filename
    # -----------------------------------------

    report_path = output_path / f"case_{case_id}.json"

    # -----------------------------------------
    # Create private report file
    # -----------------------------------------

    # os.O_EXCL prevents accidental overwriting.
    # Mode 0600 restricts access on POSIX systems.

    fd = os.open(
        report_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False
            )

            file.write("\n")

    except Exception:
        # Remove an incomplete report on failure.
        report_path.unlink(missing_ok=True)
        raise

    return report_path
