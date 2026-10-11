
import ipaddress
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlsplit

from bs4 import BeautifulSoup


def get_domain(address):
    """Extract the domain of an email address."""
    email_address = parseaddr(address or "")[1]

    if "@" not in email_address:
        return None

    return email_address.rsplit("@", 1)[1].lower()


def get_host(url):
    """Extract the hostname without visiting the URL."""
    try:
        parsed = urlsplit(url.strip())

        if parsed.scheme.lower() not in ("http", "https"):
            return None

        return parsed.hostname.lower() if parsed.hostname else None
    except (ValueError, AttributeError):
        return None


def make_finding(rule_id, severity, description, evidence):
    """Create a structured detection finding."""
    return {
        "rule_id": rule_id,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "status": "requires_review"
    }


def detect_sender_mismatch(headers):
    """Compare exact From and Reply-To domains."""
    findings = []

    from_domain = get_domain(headers.get("from", ""))
    reply_domain = get_domain(headers.get("reply_to", ""))

    if from_domain and reply_domain:
        if from_domain != reply_domain:
            findings.append(make_finding(
                "EMAIL-001",
                "low",
                "From and Reply-To domains differ",
                {
                    "from_domain": from_domain,
                    "reply_to_domain": reply_domain
                }
            ))

    return findings


def detect_html_link_mismatch(html):
    """Find links whose visible URL differs from href."""
    findings = []

    soup = BeautifulSoup(html, "html.parser")

    for link in soup.find_all("a", href=True):
        href = link.get("href")
        visible = link.get_text(" ", strip=True)

        if not isinstance(href, str):
            continue

        href_host = get_host(href)
        visible_host = get_host(visible)

        if href_host and visible_host:
            if href_host != visible_host:
                findings.append(make_finding(
                    "EMAIL-002",
                    "medium",
                    "Visible link hostname differs from destination",
                    {
                        "visible_text": visible,
                        "visible_hostname": visible_host,
                        "actual_url": href,
                        "actual_hostname": href_host
                    }
                ))

    return findings


def detect_ip_urls(iocs):
    """Find URLs that directly contain IP addresses."""
    findings = []

    for item in iocs.get("url_details", []):
        hostname = item.get("hostname")

        if not hostname:
            continue

        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            continue

        findings.append(make_finding(
            "EMAIL-003",
            "medium",
            "Email contains an IP-based URL",
            {
                "url": item.get("url"),
                "ip_address": str(ip)
            }
        ))

    return findings


def detect_authentication_failures(headers):
    """Inspect recorded authentication results."""
    findings = []

    for index, entry in enumerate(
        headers.get("authentication", [])
    ):
        failed = []

        for mechanism in ("spf", "dkim", "dmarc"):
            values = entry.get(mechanism, [])

            if any(
                str(value).lower() == "fail"
                for value in values
            ):
                failed.append(mechanism)

        if failed:
            findings.append(make_finding(
                "EMAIL-004",
                "medium",
                "Reported email authentication failure",
                {
                    "header_index": index,
                    "mechanisms": failed,
                    "verified": False
                }
            ))

    return findings


def read_html_parts(email_path):
    """Read HTML email parts without rendering them."""
    path = Path(email_path)

    # The main analyzer already uses a 10 MB file limit.
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("Email exceeds 10 MB limit")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(path.read_bytes())

    html_parts = []

    for part in message.walk():
        if part.is_multipart():
            continue

        if part.get_content_type() != "text/html":
            continue

        if part.get_content_disposition() == "attachment":
            continue

        if part.get_filename():
            continue

        payload = part.get_payload(decode=True)

        if payload is None:
            continue

        charset = part.get_content_charset() or "utf-8"

        try:
            html = payload.decode(
                charset, errors="replace"
            )
        except LookupError:
            html = payload.decode(
                "utf-8", errors="replace"
            )

        html_parts.append(html)

    return html_parts


def analyze_advanced(email_path, email_result):
    """Run all advanced detection rules."""
    findings = []
    headers = email_result.get("headers", {})
    iocs = email_result.get("iocs", {})

    findings.extend(
        detect_sender_mismatch(headers)
    )

    findings.extend(
        detect_ip_urls(iocs)
    )

    findings.extend(
        detect_authentication_failures(headers)
    )

    for html in read_html_parts(email_path):
        findings.extend(
            detect_html_link_mismatch(html)
        )

    return {
        "module": "Advanced Email Detection",
        "total_findings": len(findings),
        "findings": findings,
        "limitations": [
            "Rules produce leads, not phishing verdicts.",
            "Email authentication is not independently verified.",
            "Only explicit visible HTTP(S) links are compared.",
            "Different hostnames do not necessarily imply deception.",
            "HTML is parsed without browser rendering."
        ]
    }
