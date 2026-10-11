
import json
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from src.ioc_extractor import extract_iocs

REDIRECT_CODES = {301, 302, 303, 307, 308}
MAX_HOPS = 20


def validate_url(url):
    """Validate the structure of a recorded HTTP URL."""
    if not isinstance(url, str):
        return False

    try:
        parsed = urlsplit(url)

        return (
            parsed.scheme.lower() in ("http", "https")
            and bool(parsed.hostname)
            and parsed.port != 0
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def analyze_redirects(records):
    """Analyze recorded redirect evidence offline."""

    if not isinstance(records, list) or not records:
        raise ValueError("Expected a nonempty list")

    if len(records) > MAX_HOPS:
        raise ValueError("Maximum hop limit exceeded")

    chain = []
    visited = set()
    expected_url = None

    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("Invalid response record")

        url = record["url"]
        status = int(record["status"])
        location = record.get("location")

        if not validate_url(url):
            raise ValueError(f"Invalid URL: {url}")

        if expected_url is not None and url != expected_url:
            raise ValueError(
                f"Unexpected URL at hop {index + 1}"
            )

        if url in visited:
            raise ValueError("Redirect loop detected")

        visited.add(url)
        destination = None

        if status in REDIRECT_CODES:
            if not isinstance(location, str) or not location:
                raise ValueError(
                    "Redirect response missing Location"
                )

            destination = urljoin(url, location)

            if not validate_url(destination):
                raise ValueError(
                    "Invalid redirect destination"
                )

        chain.append({
            "hop": index + 1,
            "url": url,
            "status_code": status,
            "redirect_to": destination,
            "hostname": urlsplit(url).hostname
        })

        expected_url = destination

        if destination is None and index != len(records) - 1:
            raise ValueError(
                "Unexpected records after final response"
            )

    if expected_url is not None:
        raise ValueError("Incomplete redirect chain")

    iocs = extract_iocs(
        [hop["url"] for hop in chain]
    )

    return {
        "total_hops": len(chain),
        "redirect_count": sum(
            hop["redirect_to"] is not None
            for hop in chain
        ),
        "initial_url": chain[0]["url"],
        "final_url": chain[-1]["url"],
        "chain": chain,
        "iocs": iocs,
        "evidence_type": "recorded_http_responses",
        "verified_live": False
    }


def analyze_redirect_file(input_file, output_file):
    records = json.loads(
        Path(input_file).read_text(encoding="utf-8")
    )

    result = analyze_redirects(records)

    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)

    output.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    print("[+] Redirect analysis completed")
    print("[+] Total hops:", result["total_hops"])
    print("[+] Redirects:", result["redirect_count"])
    print("[+] Final URL:", result["final_url"])
    print("[+] Report:", output)

    return result


if __name__ == "__main__":
    analyze_redirect_file(
        "data/redirects/test_redirect.json",
        "reports/redirect_analysis.json"
    )
