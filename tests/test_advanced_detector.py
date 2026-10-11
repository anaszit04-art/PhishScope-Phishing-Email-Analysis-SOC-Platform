
from src.email_analyzer import analyze_email

from src.advanced_detector import (
    analyze_advanced,
    detect_sender_mismatch,
    detect_html_link_mismatch,
    detect_ip_urls,
    detect_authentication_failures
)


def test_sender_domain_mismatch():
    headers = {
        "from": "security@bank.example",
        "reply_to": "help@other.example"
    }

    findings = detect_sender_mismatch(headers)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EMAIL-001"


def test_matching_sender_domains():
    headers = {
        "from": "security@bank.example",
        "reply_to": "help@bank.example"
    }

    findings = detect_sender_mismatch(headers)

    assert findings == []


def test_html_link_mismatch():
    html = """
    <a href="https://other.example/login">
        https://bank.example/login
    </a>
    """

    findings = detect_html_link_mismatch(html)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EMAIL-002"


def test_matching_html_link():
    html = """
    <a href="https://bank.example/login">
        https://bank.example/login
    </a>
    """

    findings = detect_html_link_mismatch(html)

    assert findings == []


def test_ip_based_url():
    iocs = {
        "url_details": [
            {
                "url": "http://203.0.113.45/login",
                "hostname": "203.0.113.45"
            }
        ]
    }

    findings = detect_ip_urls(iocs)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "EMAIL-003"


def test_authentication_failure():
    headers = {
        "authentication": [
            {
                "spf": ["fail"],
                "dkim": ["none"],
                "dmarc": ["fail"]
            }
        ]
    }

    findings = detect_authentication_failures(headers)

    assert len(findings) == 1

    mechanisms = findings[0]["evidence"]["mechanisms"]

    assert "spf" in mechanisms
    assert "dmarc" in mechanisms


def test_complete_advanced_analysis():
    path = "data/emails/advanced_test.eml"

    email = analyze_email(path)
    result = analyze_advanced(path, email)

    assert result["total_findings"] == 4

    rule_ids = {
        finding["rule_id"]
        for finding in result["findings"]
    }

    assert rule_ids == {
        "EMAIL-001",
        "EMAIL-002",
        "EMAIL-003",
        "EMAIL-004"
    }
