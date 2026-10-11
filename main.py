
import argparse
import json
from pathlib import Path

# Module 2 — IOC Extraction
# IOC extraction is used internally by the other modules.

# Module 3 — Email Analysis
from src.email_analyzer import analyze_email

# Module 4 — Redirect Chain Analysis
from src.redirect_analyzer import analyze_redirects

# Module 5 — MITRE ATT&CK Mapping
from src.mitre_mapper import map_techniques

# Module 6 — Unified Report Generator
from src.report_generator import generate_report

# Module 7 — Advanced Phishing Detection
from src.advanced_detector import analyze_advanced

# Module 9 — IOC Enrichment and Threat Intelligence
from src.ioc_enrichment import enrich_from_files

# Module 10 — Explainable Risk Assessment
from src.risk_assessor import assess_risk


def load_redirect_evidence(path):
    """
    Load recorded redirect-chain evidence from JSON.

    This function only reads local evidence.
    It does not contact any phishing website.
    """

    records = json.loads(
        Path(path).read_text(encoding="utf-8")
    )

    return analyze_redirects(records)


def load_feed_context(path, email_result):
    """
    Correlate email indicators with the local phishing feed.

    Supports:
        - Exact URL matches
        - Normalized URL matches
        - Hostname-only matches
        - Feed SHA-256 integrity comparison

    No live phishing URLs are visited.
    """

    return enrich_from_files(
        email_result,
        path
    )


def main():
    """
    Main entry point for the PhishScope investigation tool.
    """

    # ------------------------------------------
    # Command-line argument parser
    # ------------------------------------------

    parser = argparse.ArgumentParser(
        description=(
            "PhishScope Unified Phishing Investigator"
        )
    )

    parser.add_argument(
        "--email",
        required=True,
        help="Path to a local .eml email sample"
    )

    parser.add_argument(
        "--redirects",
        help="Optional locally recorded redirect-chain JSON"
    )

    parser.add_argument(
        "--feed",
        help="Optional local phishing URL intelligence feed"
    )

    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Directory for generated investigation reports"
    )

    args = parser.parse_args()

    print()
    print("=" * 50)
    print("         PHISHSCOPE INVESTIGATION")
    print("=" * 50)
    print("[*] Starting PhishScope investigation...")

    # ------------------------------------------
    # Evidence tracking
    # ------------------------------------------

    evidence_paths = {
        "email": args.email
    }

    # ------------------------------------------
    # Module 3 — Email Analysis
    # ------------------------------------------

    print("[*] Analyzing email...")

    email_result = analyze_email(
        args.email
    )

    print("[+] Email parsed successfully")

    # ------------------------------------------
    # Module 7 — Advanced Phishing Detection
    # ------------------------------------------

    print("[*] Running advanced detection rules...")

    advanced_result = analyze_advanced(
        args.email,
        email_result
    )

    print(
        "[+] Advanced detection completed:",
        advanced_result["total_findings"],
        "findings"
    )

    # ------------------------------------------
    # Module 4 — Redirect Chain Analysis
    # ------------------------------------------

    redirect_result = None

    if args.redirects:
        print("[*] Analyzing redirect evidence...")

        redirect_result = load_redirect_evidence(
            args.redirects
        )

        evidence_paths["redirects"] = args.redirects

        print("[+] Redirect evidence analyzed")

    # ------------------------------------------
    # Module 9 — IOC Enrichment
    # ------------------------------------------

    feed_summary = None

    if args.feed:
        print(
            "[*] Correlating IOCs with threat intelligence..."
        )

        feed_summary = load_feed_context(
            args.feed,
            email_result
        )

        evidence_paths["feed"] = args.feed

        print("[+] Feed correlation completed")

    # ------------------------------------------
    # Module 5 — MITRE ATT&CK Mapping
    # ------------------------------------------

    print("[*] Mapping evidence to MITRE ATT&CK...")

    mitre_result = map_techniques(
        email_result,
        redirect_result
    )

    print("[+] ATT&CK mapping completed")

    # ------------------------------------------
    # Module 10 — Explainable Risk Assessment
    # ------------------------------------------

    print("[*] Assessing investigation priority...")

    risk_result = assess_risk(
        advanced_result,
        feed_summary
    )

    print(
        "[+] Risk assessment completed:",
        risk_result["score"],
        "/ 100"
    )

    # ------------------------------------------
    # Module 6 — Unified Report Generation
    # ------------------------------------------

    print("[*] Generating investigation report...")

    report_path = generate_report(
        email_result=email_result,
        mitre_result=mitre_result,
        redirect_result=redirect_result,
        feed_summary=feed_summary,
        evidence_paths=evidence_paths,
        output_dir=args.output_dir,
        advanced_result=advanced_result,
        risk_result=risk_result
    )

    print("[+] Investigation report generated")

    # ------------------------------------------
    # Investigation Summary
    # ------------------------------------------

    print()
    print("=" * 50)
    print("       PHISHSCOPE INVESTIGATION SUMMARY")
    print("=" * 50)

    headers = email_result["headers"]
    iocs = email_result["iocs"]

    print(
        "Subject:",
        headers.get("subject", "")
    )

    print(
        "Sender:",
        headers.get("sender_address", "")
    )

    print(
        "Reply-To:",
        headers.get("reply_to_address", "")
    )

    print(
        "Email URLs:",
        iocs["total_urls"]
    )

    print(
        "Attachments:",
        len(email_result["attachments"])
    )

    print(
        "Advanced findings:",
        advanced_result["total_findings"]
    )

    print(
        "Risk score:",
        f"{risk_result['score']}/100"
    )

    print(
        "Review priority:",
        risk_result["review_priority"].upper()
    )

    print(
        "Risk verdict:",
        risk_result["verdict"]
    )

    print(
        "ATT&CK candidates:",
        len(mitre_result["technique_candidates"])
    )

    # ------------------------------------------
    # Advanced Detection Findings
    # ------------------------------------------

    if advanced_result["findings"]:
        print()
        print("--- Advanced Detection Findings ---")

        for finding in advanced_result["findings"]:
            print(
                f"[{finding['severity'].upper()}] "
                f"{finding['rule_id']}: "
                f"{finding['description']}"
            )

    # ------------------------------------------
    # Risk Assessment Breakdown
    # ------------------------------------------

    print()
    print("--- Risk Assessment Breakdown ---")

    if risk_result["contributions"]:
        for contribution in risk_result["contributions"]:
            print(
                f"[+{contribution['points']}] "
                f"{contribution['identifier']}: "
                f"{contribution['reason']}"
            )
    else:
        print("No weighted risk signals detected.")

    print()
    print(
        "Assessment type:",
        risk_result["assessment_type"]
    )

    print(
        "Verdict:",
        risk_result["verdict"]
    )

    # ------------------------------------------
    # Redirect Analysis
    # ------------------------------------------

    if redirect_result:
        print()
        print("--- Redirect Analysis ---")

        print(
            "Total hops:",
            redirect_result["total_hops"]
        )

        print(
            "Redirect count:",
            redirect_result["redirect_count"]
        )

        print(
            "Initial URL:",
            redirect_result["initial_url"]
        )

        print(
            "Final URL:",
            redirect_result["final_url"]
        )

    # ------------------------------------------
    # IOC Enrichment Results
    # ------------------------------------------

    if feed_summary:
        print()
        print("--- Threat Intelligence ---")

        match_counts = feed_summary["match_counts"]
        integrity = feed_summary["feed_integrity"]

        print(
            "Feed URLs:",
            feed_summary["feed_url_count"]
        )

        print(
            "Feed hostnames:",
            feed_summary["feed_hostname_count"]
        )

        print(
            "Exact URL matches:",
            match_counts["exact_url"]
        )

        print(
            "Normalized URL matches:",
            match_counts["normalized_url"]
        )

        print(
            "Hostname matches:",
            match_counts["hostname"]
        )

        print(
            "Unmatched URLs:",
            match_counts["none"]
        )

        print(
            "Invalid URLs:",
            match_counts["invalid_url"]
        )

        print(
            "Feed download time:",
            feed_summary.get("feed_download_time")
        )

        print(
            "Feed integrity verified:",
            integrity["verified"]
        )

    # ------------------------------------------
    # MITRE ATT&CK Candidates
    # ------------------------------------------

    if mitre_result["technique_candidates"]:
        print()
        print("--- MITRE ATT&CK Candidates ---")

        for technique in mitre_result[
            "technique_candidates"
        ]:
            print(
                f"{technique['technique_id']} - "
                f"{technique['technique_name']} "
                f"({technique['status']})"
            )

    # ------------------------------------------
    # Final Report Path
    # ------------------------------------------

    print()
    print("Report saved to:", report_path)
    print("=" * 50)
    print(
        "Note: Risk scores are heuristic review priorities, "
        "not probabilities or confirmed phishing verdicts."
    )


if __name__ == "__main__":
    main()
