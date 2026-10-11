
"""
PhishScope v1.0 — Release Verification

Runs the automated test suite and a full offline
synthetic email investigation.

All temporary evidence and reports are written to
a temporary directory and removed afterward.

No phishing destinations or attachments are opened.
"""

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from src.evidence_importer import import_email
from src.report_validator import validate_report


ROOT = Path(__file__).resolve().parent


def file_hash(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def run_tests():
    print("\n[1/4] Running automated tests...", flush=True)

    subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        cwd=ROOT,
        check=True
    )


def verify_pipeline():
    print(
        "\n[2/4] Testing evidence import and integrity...",
        flush=True
    )

    source = ROOT / "data/emails/advanced_test.eml"
    feed = ROOT / "data/feeds/openphish.txt"

    if not source.is_file():
        raise FileNotFoundError(
            "Synthetic test email is missing"
        )

    if not feed.is_file():
        raise FileNotFoundError(
            "Local OpenPhish feed is missing"
        )

    original_hash = file_hash(source)

    with tempfile.TemporaryDirectory(
        prefix="phishscope_release_"
    ) as temporary:
        workdir = Path(temporary)

        imported = import_email(
            source,
            "PhishScope v1.0 synthetic release test",
            evidence_root=workdir / "evidence"
        )

        imported_path = Path(imported["evidence_path"])

        assert imported_path.is_file()
        assert file_hash(imported_path) == original_hash

        print("[PASS] Evidence SHA-256 matches")

        print(
            "\n[3/4] Running end-to-end investigation...",
            flush=True
        )

        reports_dir = workdir / "reports"

        result = subprocess.run(
            [
                sys.executable,
                "main.py",
                "--email",
                str(imported_path),
                "--feed",
                str(feed),
                "--output-dir",
                str(reports_dir)
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True
        )

        print(result.stdout)

        report_paths = list(
            reports_dir.glob("case_*.json")
        )

        assert len(report_paths) == 1, (
            "Exactly one report was expected"
        )

        report_path = report_paths[0]

        report = json.loads(
            report_path.read_text(encoding="utf-8")
        )

        validate_report(
            report,
            filename=report_path.name
        )

        risk = report.get("risk_assessment") or {}
        advanced = report.get("advanced_detection") or {}
        feed_context = report.get("feed_context") or {}

        assert risk.get("score") == 55
        assert risk.get("review_priority") == "elevated"
        assert risk.get("verdict") == "not_determined"

        assert advanced.get("total_findings") == 4

        assert (
            feed_context.get("feed_integrity") or {}
        ).get("verified") is True

        assert file_hash(source) == original_hash

        evidence_manifest = report.get("evidence") or []

        assert any(
            item.get("type") == "email"
            and item.get("sha256") == original_hash
            for item in evidence_manifest
        )

        print(
            "[PASS] Risk assessment, detections, "
            "feed integrity and evidence manifest"
        )


def verify_dashboard():
    print(
        "\n[4/4] Checking dashboard dependencies...",
        flush=True
    )

    import streamlit
    from src.dashboard_data import load_reports

    reports, errors = load_reports(
        ROOT / "reports"
    )

    if errors:
        for error in errors:
            print("[WARNING]", error)

    print("[PASS] Streamlit imported successfully")
    print(f"[INFO] Historical reports: {len(reports)}")
    print(f"[INFO] Rejected reports: {len(errors)}")

    if errors:
        raise RuntimeError(
            "Historical reports failed validation"
        )


def main():
    print("=" * 55)
    print("PHISHSCOPE v1.0 RELEASE VERIFICATION")
    print("=" * 55)

    run_tests()
    verify_pipeline()
    verify_dashboard()

    print()
    print("=" * 55)
    print("RELEASE VERIFICATION PASSED")
    print("=" * 55)

    print(
        "Note: This validates the synthetic laboratory "
        "workflow, not detection accuracy on real emails."
    )


if __name__ == "__main__":
    try:
        main()
    except (
        AssertionError,
        FileNotFoundError,
        RuntimeError,
        subprocess.CalledProcessError
    ) as error:
        print(f"\n[FAIL] {error}", file=sys.stderr)
        sys.exit(1)
