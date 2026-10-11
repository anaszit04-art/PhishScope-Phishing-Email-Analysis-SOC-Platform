
import argparse
import json
from pathlib import Path
from datetime import datetime, timezone


TECHNIQUES = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access"
    },
    "T1566.001": {
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access"
    },
    "T1566.002": {
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access"
    }
}


def make_finding(technique_id, evidence, limitation):
    technique = TECHNIQUES[technique_id]

    return {
        "technique_id": technique_id,
        "technique_name": technique["name"],
        "tactic": technique["tactic"],
        "status": "candidate",
        "evidence": evidence,
        "limitation": limitation,
        "mitre_url": (
            "https://attack.mitre.org/techniques/"
            + technique_id.replace(".", "/")
            + "/"
        )
    }


def map_email(email_report):
    """Generate ATT&CK candidates from email evidence."""

    findings = []
    headers = email_report.get("headers", {})
    iocs = email_report.get("iocs", {})
    attachments = email_report.get("attachments", [])

    urls = iocs.get("url_details", [])

    if urls:
        findings.append(
            make_finding(
                "T1566.002",
                {
                    "source": "email_analysis",
                    "observation": (
                        "Email contains one or more HTTP links"
                    ),
                    "url_count": len(urls),
                    "url_hosts": sorted({
                        item["hostname"]
                        for item in urls
                    })
                },
                (
                    "A link alone does not prove malicious "
                    "intent, spearphishing targeting, or "
                    "user interaction."
                )
            )
        )

    if attachments:
        findings.append(
            make_finding(
                "T1566.001",
                {
                    "source": "email_analysis",
                    "observation": (
                        "Email contains file attachments"
                    ),
                    "attachment_count": len(attachments),
                    "attachment_hashes": [
                        item["sha256"]
                        for item in attachments
                    ]
                },
                (
                    "Attachments have not been proven "
                    "malicious or targeted."
                )
            )
        )

    auth = headers.get("authentication", [])

    reported_failures = []

    for entry in auth:
        for mechanism in ("spf", "dkim", "dmarc"):
            if "fail" in [
                str(v).lower()
                for v in entry.get(mechanism, [])
            ]:
                reported_failures.append(mechanism)

    if reported_failures:
        findings.append({
            "finding_type": "email_authentication",
            "status": "observation",
            "description": (
                "Email contains reported authentication "
                "failures."
            ),
            "mechanisms": sorted(
                set(reported_failures)
            ),
            "limitation": (
                "Authentication-Results values have not "
                "been independently verified. Header "
                "trust boundaries are not established."
            )
        })

    return findings


def map_redirects(redirect_report):
    """Record redirect behavior without inferring execution."""

    count = redirect_report.get("redirect_count", 0)

    if count <= 0:
        return []

    return [{
        "finding_type": "http_redirect_chain",
        "status": "observation",
        "description": (
            "Recorded HTTP evidence contains redirects."
        ),
        "redirect_count": count,
        "initial_url": redirect_report.get(
            "initial_url"
        ),
        "final_url": redirect_report.get(
            "final_url"
        ),
        "mitre_technique": None,
        "limitation": (
            "HTTP redirects alone do not demonstrate "
            "maliciousness or user execution."
        )
    }]


def map_techniques(email_report, redirect_report=None):
    """Combine findings from existing modules."""

    findings = map_email(email_report)

    if redirect_report is not None:
        findings.extend(
            map_redirects(redirect_report)
        )

    # Correlate by exact URL, not by assumptions.
    correlation = {
        "matched": False,
        "reason": "No matching redirect evidence"
    }

    if redirect_report:
        email_urls = {
            item["url"]
            for item in email_report.get(
                "iocs", {}
            ).get("url_details", [])
        }

        initial = redirect_report.get("initial_url")

        if initial in email_urls:
            correlation = {
                "matched": True,
                "reason": (
                    "Redirect initial URL matches "
                    "an extracted email URL"
                )
            }

    return {
        "project": "PhishScope",
        "module": "MITRE ATT&CK Mapper",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "technique_candidates": [
            item for item in findings
            if "technique_id" in item
        ],
        "additional_observations": [
            item for item in findings
            if "technique_id" not in item
        ],
        "redirect_correlation": correlation,
        "confirmed_execution": False
    }


def load_json(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8")
    )


def main():
    parser = argparse.ArgumentParser(
        description="PhishScope MITRE ATT&CK Mapper"
    )

    parser.add_argument(
        "--email",
        required=True,
        help="Email analysis JSON report"
    )

    parser.add_argument(
        "--redirects",
        help="Optional redirect analysis JSON report"
    )

    parser.add_argument(
        "--output",
        default="reports/mitre_analysis.json"
    )

    args = parser.parse_args()

    email_data = load_json(args.email)

    redirect_data = (
        load_json(args.redirects)
        if args.redirects
        else None
    )

    result = map_techniques(
        email_data,
        redirect_data
    )

    output = Path(args.output)
    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print("[+] MITRE mapping completed")
    print(
        "[+] Technique candidates:",
        len(result["technique_candidates"])
    )
    print(
        "[+] Additional observations:",
        len(result["additional_observations"])
    )
    print(
        "[+] Redirect correlation:",
        result["redirect_correlation"]["matched"]
    )
    print("[+] Report:", output)


if __name__ == "__main__":
    main()

