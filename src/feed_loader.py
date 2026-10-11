
import requests
import hashlib
import json

from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit

FEED_URL = "https://openphish.com/feed.txt"

OUTPUT_DIR = Path("data/feeds")
OUTPUT_FILE = OUTPUT_DIR / "openphish.txt"


def download_feed():

    print("[*] Connecting to OpenPhish...")

    response = requests.get(
        FEED_URL,
        timeout=30
    )

    response.raise_for_status()

    print("[+] Feed downloaded successfully.")

    # Parse the feed as text, without visiting its URLs.
    urls = []

    for line in response.text.splitlines():
        url = line.strip()
        parts = urlsplit(url)

        if (
            parts.scheme in ("http", "https")
            and parts.hostname
        ):
            urls.append(url)

    # Remove duplicates.
    urls = sorted(set(urls))

    if not urls:
        raise ValueError(
            "The feed did not contain valid HTTP URLs."
        )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    OUTPUT_FILE.write_text(
        "\n".join(urls) + "\n",
        encoding="utf-8"
    )

    # Calculate SHA256 for evidence integrity.
    file_hash = hashlib.sha256(
        OUTPUT_FILE.read_bytes()
    ).hexdigest()

    metadata = {
        "source": "OpenPhish Community Feed",
        "download_time": datetime.now(
            timezone.utc
        ).isoformat(),
        "total_urls": len(urls),
        "sha256": file_hash
    }

    metadata_file = (
        OUTPUT_DIR / "openphish_metadata.json"
    )

    metadata_file.write_text(
        json.dumps(metadata, indent=4),
        encoding="utf-8"
    )

    print(f"[+] Total URLs: {len(urls)}")
    print(f"[+] SHA256: {file_hash}")
    print(f"[+] Saved to: {OUTPUT_FILE}")

    return metadata


if __name__ == "__main__":
    download_feed()
