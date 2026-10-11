
import hashlib
import json
import re
from pathlib import Path
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from bs4 import BeautifulSoup

from src.ioc_extractor import extract_iocs


URL_PATTERN = re.compile(
    r'https?://[^\s<>"\']+',
    re.IGNORECASE
)


def sha256_bytes(data):
    """Calculate SHA-256 for raw data."""
    return hashlib.sha256(data).hexdigest()


def get_header(message, name):
    """Return a header as a string."""
    value = message.get(name)
    return str(value) if value is not None else ""


def get_authentication_results(message):
    """Extract reported SPF, DKIM and DMARC results."""

    raw_results = [
        str(value)
        for value in message.get_all(
            "Authentication-Results", []
        )
    ]

    findings = []

    for result in raw_results:
        findings.append({
            "raw": result,
            "spf": re.findall(
                r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b',
                result,
                re.IGNORECASE
            ),
            "dkim": re.findall(
                r'\bdkim=(pass|fail|none|temperror|permerror|policy)\b',
                result,
                re.IGNORECASE
            ),
            "dmarc": re.findall(
                r'\bdmarc=(pass|fail|none|temperror|permerror)\b',
                result,
                re.IGNORECASE
            )
        })

    return findings


def extract_email_urls(text_parts, html_parts):
    """Extract links without opening them."""

    urls = set()

    for text in text_parts:
        for url in URL_PATTERN.findall(text):
            urls.add(url.rstrip(".,;)>"))

    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")

        # Extract links stored in HTML attributes.
        for tag in soup.find_all(["a", "area"]):
            href = tag.get("href")

            if isinstance(href, str) and href.lower().startswith(
                ("http://", "https://")
            ):
                urls.add(href)

        # Also detect visible URLs in HTML text.
        for url in URL_PATTERN.findall(soup.get_text(" ")):
            urls.add(url.rstrip(".,;)>"))

    return sorted(urls)


def analyze_email(file_path):
    """Parse a raw email without executing its content."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(file_path)

    raw_email = path.read_bytes()

    # Set a basic file-size limit for safer analysis.
    if len(raw_email) > 10 * 1024 * 1024:
        raise ValueError("Email exceeds 10 MB limit")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    sender = get_header(message, "From")
    reply_to = get_header(message, "Reply-To")

    headers = {
        "from": sender,
        "sender_address": parseaddr(sender)[1],
        "reply_to": reply_to,
        "reply_to_address": parseaddr(reply_to)[1],
        "return_path": get_header(
            message, "Return-Path"
        ),
        "to": get_header(message, "To"),
        "subject": get_header(message, "Subject"),
        "date": get_header(message, "Date"),
        "message_id": get_header(
            message, "Message-ID"
        ),
        "received": [
            str(value)
            for value in message.get_all("Received", [])
        ],
        "authentication": get_authentication_results(
            message
        )
    }

    text_parts = []
    html_parts = []
    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        payload = part.get_payload(decode=True)

        if payload is None:
            continue

        # Do not execute, open, or extract attachments.
        if disposition == "attachment" or filename:
            attachments.append({
                "filename": filename,
                "content_type": content_type,
                "size_bytes": len(payload),
                "sha256": sha256_bytes(payload)
            })
            continue

        if content_type not in (
            "text/plain", "text/html"
        ):
            continue

        charset = part.get_content_charset() or "utf-8"

        try:
            decoded = payload.decode(
                charset,
                errors="replace"
            )
        except LookupError:
            decoded = payload.decode(
                "utf-8",
                errors="replace"
            )

        if content_type == "text/plain":
            text_parts.append(decoded)
        else:
            html_parts.append(decoded)

    urls = extract_email_urls(
        text_parts, html_parts
    )

    # Reuse our existing Module 2 IOC extractor.
    iocs = extract_iocs(urls)

    return {
        "source_file": str(path),
        "file_sha256": sha256_bytes(raw_email),
        "headers": headers,
        "body_preview": "\n".join(text_parts)[:1000],
        "iocs": iocs,
        "attachments": attachments,
        "notes": [
            "Authentication results are reported, not verified.",
            "Received headers may contain untrusted entries.",
            "No suspicious URLs or attachments were opened."
        ]
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="PhishScope Email Analyzer"
    )

    parser.add_argument(
        "email_file",
        help="Path to a local .eml file"
    )

    args = parser.parse_args()

    result = analyze_email(args.email_file)

    output_dir = Path("reports")
    output_dir.mkdir(exist_ok=True)

    output = output_dir / "email_analysis.json"

    output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print("[+] Email analyzed successfully")
    print("[+] Subject:", result["headers"]["subject"])
    print("[+] URLs:", result["iocs"]["total_urls"])
    print("[+] Attachments:", len(result["attachments"]))
    print("[+] Report:", output)
