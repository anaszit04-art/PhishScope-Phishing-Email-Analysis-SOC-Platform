
import json
import ipaddress
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl
from collections import Counter


def analyze_url(url):
    """Extract structured indicators from one URL."""

    url = url.strip()
    parsed = urlsplit(url)

    if parsed.scheme.lower() not in ("http", "https"):
        return None

    hostname = parsed.hostname

    if not hostname:
        return None

    try:
        port = parsed.port
    except ValueError:
        return None

    # Detect literal IP addresses in the URL hostname.
    ip_address = None

    try:
        ip_address = str(
            ipaddress.ip_address(hostname)
        )
    except ValueError:
        pass

    return {
        "url": url,
        "hostname": hostname.lower(),
        "ip_address": ip_address,
        "scheme": parsed.scheme.lower(),
        "port": port,
        "path": parsed.path or "/",
        "query_parameters": [
            {"name": key, "value": value}
            for key, value in parse_qsl(
                parsed.query,
                keep_blank_values=True
            )
        ]
    }


def extract_iocs(urls):
    """Analyze URLs and produce structured IOC data."""

    results = []
    seen_urls = set()

    for url in urls:
        url = url.strip()

        if not url or url in seen_urls:
            continue

        seen_urls.add(url)

        result = analyze_url(url)

        if result:
            results.append(result)

    domains = sorted({
        result["hostname"]
        for result in results
        if not result["ip_address"]
    })

    ip_addresses = sorted({
        result["ip_address"]
        for result in results
        if result["ip_address"]
    })

    protocols = dict(
        Counter(result["scheme"] for result in results)
    )

    return {
        "total_urls": len(results),
        "total_domains": len(domains),
        "total_ips": len(ip_addresses),
        "domains": domains,
        "ip_addresses": ip_addresses,
        "protocols": protocols,
        "url_details": results
    }


def analyze_feed(feed_path, output_path):
    """Read a local feed and save extracted IOCs."""

    feed = Path(feed_path)

    if not feed.is_file():
        raise FileNotFoundError(
            f"Feed not found: {feed}"
        )

    urls = feed.read_text(
        encoding="utf-8"
    ).splitlines()

    print(f"[*] Reading {len(urls)} feed entries...")

    results = extract_iocs(urls)

    output = Path(output_path)
    output.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    output.write_text(
        json.dumps(results, indent=2),
        encoding="utf-8"
    )

    print("[+] IOC extraction completed.")
    print(f"[+] URLs: {results['total_urls']}")
    print(f"[+] Domains: {results['total_domains']}")
    print(f"[+] Literal IPs: {results['total_ips']}")
    print(f"[+] Report: {output}")

    return results


if __name__ == "__main__":
    analyze_feed(
        "data/feeds/openphish.txt",
        "reports/extracted_iocs.json"
    )
