
import hashlib
import json

from src.ioc_enrichment import (
    normalize_url,
    enrich_iocs,
    enrich_from_files
)


def test_normalization():
    assert normalize_url(
        "HTTPS://EXAMPLE.INVALID:443"
    ) == "https://example.invalid/"


def test_exact_url_match():
    url = "https://example.invalid/login"

    result = enrich_iocs([url], [url])

    assert result["match_counts"]["exact_url"] == 1


def test_normalized_url_match():
    email = "https://EXAMPLE.INVALID:443/login"
    feed = "https://example.invalid/login"

    result = enrich_iocs([email], [feed])

    assert result["match_counts"]["normalized_url"] == 1


def test_hostname_match():
    email = "https://example.invalid/help"
    feed = "https://example.invalid/login"

    result = enrich_iocs([email], [feed])

    assert result["match_counts"]["hostname"] == 1


def test_no_match():
    email = "https://unknown.example.invalid/"
    feed = "https://other.example.invalid/"

    result = enrich_iocs([email], [feed])

    assert result["match_counts"]["none"] == 1


def test_feed_metadata_integrity(tmp_path):
    feed = tmp_path / "openphish.txt"
    feed.write_text(
        "https://example.invalid/login\n",
        encoding="utf-8"
    )

    digest = hashlib.sha256(feed.read_bytes()).hexdigest()

    metadata = {
        "source": "Synthetic test feed",
        "download_time": "2026-10-11T00:00:00+00:00",
        "sha256": digest
    }

    (tmp_path / "openphish_metadata.json").write_text(
        json.dumps(metadata),
        encoding="utf-8"
    )

    email_result = {
        "iocs": {
            "url_details": [{
                "url": "https://example.invalid/login"
            }]
        }
    }

    result = enrich_from_files(email_result, feed)

    assert result["feed_integrity"]["verified"] is True
    assert result["match_counts"]["exact_url"] == 1
    assert result["feed_download_time"] == (
        "2026-10-11T00:00:00+00:00"
    )
