
from src.email_analyzer import analyze_email


def test_email_subject():
    result = analyze_email(
        "data/emails/test_phishing.eml"
    )

    assert result["headers"]["subject"] == (
        "URGENT: Verify Your Account"
    )


def test_sender_address():
    result = analyze_email(
        "data/emails/test_phishing.eml"
    )

    assert result["headers"]["sender_address"] == (
        "security@example.invalid"
    )


def test_phishing_url():
    result = analyze_email(
        "data/emails/test_phishing.eml"
    )

    assert result["iocs"]["total_urls"] == 1

    assert (
        "login.example.invalid"
        in result["iocs"]["domains"]
    )


def test_attachment_count():
    result = analyze_email(
        "data/emails/test_phishing.eml"
    )

    assert len(result["attachments"]) == 0


def test_reported_spf_failure():
    result = analyze_email(
        "data/emails/test_phishing.eml"
    )

    authentication = result["headers"]["authentication"]

    assert "fail" in authentication[0]["spf"]
