
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def normalize_url(url):
    """
    Normalize URL scheme, hostname, default port,
    and empty path without opening the URL.

    Query strings and fragments are preserved.
    """
    if not isinstance(url, str):
        return None

    try:
        parts = urlsplit(url.strip())

        scheme = parts.scheme.lower()
        hostname = parts.hostname

        if scheme not in ("http", "https") or not hostname:
            return None

        # Reject embedded username/password.
        if parts.username is not None:
            return None

        port = parts.port

        if port == 0:
            return None

        # IPv6 must use brackets in the authority.
        host = hostname.lower()

        if ":" in host:
            host = f"[{host}]"

        default_port = (
            (scheme == "http" and port == 80)
            or (scheme == "https" and port == 443)
        )

        if port is not None and not default_port:
            host = f"{host}:{port}"

        return urlunsplit((
            scheme,
            host,
            parts.path or "/",
            parts.query,
            parts.fragment
        ))

    except ValueError:
        return None


def get_hostname(url):
    """Extract hostname from a valid normalized URL."""
    normalized = normalize_url(url)

    if normalized is None:
        return None

    return urlsplit(normalized).hostname


def sha256_file(path):
    """Hash a local file as evidence."""
    digest = hashlib.sha256()

    with Path(path).open("rb") as handle:
        for chunk in iter(
            lambda: handle.read(65536), b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


def enrich_iocs(
    email_urls,
    feed_urls,
    metadata=None
):
    """
    Compare extracted email URLs with an offline feed.

    Match priority:
    1. Exact URL
    2. Normalized URL
    3. Same hostname
    4. No match
    """

    metadata = metadata or {}

    feed_exact = set()
    feed_normalized = set()
    feed_hosts = set()

    for url in feed_urls:
        url = url.strip()
        normalized = normalize_url(url)

        if not normalized:
            continue

        feed_exact.add(url)
        feed_normalized.add(normalized)
        feed_hosts.add(get_hostname(url))

    findings = []

    for email_url in sorted(set(email_urls)):
        normalized = normalize_url(email_url)

        if normalized is None:
            findings.append({
                "url": email_url,
                "match_type": "invalid_url",
                "matched": False,
                "note": "URL could not be parsed"
            })
            continue

        hostname = get_hostname(email_url)

        if email_url in feed_exact:
            match_type = "exact_url"
        elif normalized in feed_normalized:
            match_type = "normalized_url"
        elif hostname in feed_hosts:
            match_type = "hostname"
        else:
            match_type = "none"

        findings.append({
            "url": email_url,
            "hostname": hostname,
            "match_type": match_type,
            "matched": match_type not in (
                "none", "invalid_url"
            )
        })

    counts = {
        "exact_url": 0,
        "normalized_url": 0,
        "hostname": 0,
        "none": 0,
        "invalid_url": 0
    }

    for finding in findings:
        counts[finding["match_type"]] += 1

    return {
        "source": metadata.get(
            "source", "Local phishing intelligence feed"
        ),
        "feed_download_time": metadata.get(
            "download_time"
        ),
        "feed_url_count": len(feed_exact),
        "feed_hostname_count": len(feed_hosts),
        "email_url_count": len(findings),
        "match_counts": counts,
        "findings": findings,
        "limitations": [
            "Feed membership is an intelligence lead.",
            "A hostname match does not prove URL maliciousness.",
            "A missing match does not establish that a URL is safe.",
            "URL normalization is intentionally conservative.",
            "No live URL verification was performed."
        ]
    }


def enrich_from_files(email_result, feed_path):
    """
    Correlate analyzed email URLs with a local feed
    and its optional acquisition metadata.
    """

    feed_path = Path(feed_path)

    feed_urls = feed_path.read_text(
        encoding="utf-8"
    ).splitlines()

    metadata_path = (
        feed_path.parent / "openphish_metadata.json"
        if feed_path.name == "openphish.txt"
        else feed_path.with_suffix(".json")
    )

    metadata = {}

    if metadata_path.is_file():
        metadata = json.loads(
            metadata_path.read_text(encoding="utf-8")
        )

    email_urls = [
        item["url"]
        for item in email_result.get(
            "iocs", {}
        ).get("url_details", [])
    ]

    result = enrich_iocs(
        email_urls,
        feed_urls,
        metadata
    )

    actual_hash = sha256_file(feed_path)

    expected_hash = metadata.get("sha256")

    result["feed_integrity"] = {
        "sha256": actual_hash,
        "expected_sha256": expected_hash,
        "verified": (
            actual_hash == expected_hash
            if expected_hash is not None
            else None
        )
    }

    result["feed_filename"] = feed_path.name

    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Offline IOC Enrichment"
    )

    parser.add_argument("--email-report", required=True)
    parser.add_argument("--feed", required=True)

    args = parser.parse_args()

    email_report = json.loads(
        Path(args.email_report).read_text(
            encoding="utf-8"
        )
    )

    result = enrich_from_files(
        email_report, args.feed
    )

    print(json.dumps(result, indent=2))
