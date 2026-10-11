
from src.ioc_extractor import analyze_url, extract_iocs


def test_extract_hostname():
    result = analyze_url(
        "https://login.example.com/verify"
    )

    assert result["hostname"] == "login.example.com"
    assert result["path"] == "/verify"


def test_extract_ip():
    result = analyze_url(
        "http://203.0.113.45/login"
    )

    assert result["ip_address"] == "203.0.113.45"


def test_extract_port():
    result = analyze_url(
        "https://example.com:8443/login"
    )

    assert result["port"] == 8443


def test_remove_duplicates():
    urls = [
        "https://example.com/login",
        "https://example.com/login"
    ]

    result = extract_iocs(urls)

    assert result["total_urls"] == 1


def test_invalid_url():
    assert analyze_url("not-a-url") is None
