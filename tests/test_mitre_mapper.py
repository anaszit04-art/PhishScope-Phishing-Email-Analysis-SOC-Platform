
from src.mitre_mapper import map_techniques


def sample_email(urls=None, attachments=None):
    return {
        "headers": {
            "authentication": []
        },
        "iocs": {
            "url_details": urls or []
        },
        "attachments": attachments or []
    }


def test_spearphishing_link_candidate():
    email = sample_email(
        urls=[{
            "url": "https://example.invalid/login",
            "hostname": "example.invalid"
        }]
    )

    result = map_techniques(email)

    assert result["technique_candidates"][0][
        "technique_id"
    ] == "T1566.002"


def test_attachment_candidate():
    email = sample_email(
        attachments=[{
            "filename": "document.pdf",
            "sha256": "a" * 64
        }]
    )

    result = map_techniques(email)

    assert result["technique_candidates"][0][
        "technique_id"
    ] == "T1566.001"


def test_no_techniques_without_evidence():
    result = map_techniques(sample_email())

    assert result["technique_candidates"] == []


def test_redirects_do_not_prove_execution():
    email = sample_email()

    redirects = {
        "redirect_count": 2,
        "initial_url": "https://a.example.invalid/",
        "final_url": "https://b.example.invalid/"
    }

    result = map_techniques(email, redirects)

    assert result["confirmed_execution"] is False
    assert result["technique_candidates"] == []


def test_exact_url_correlation():
    url = "https://example.invalid/start"

    email = sample_email(
        urls=[{
            "url": url,
            "hostname": "example.invalid"
        }]
    )

    redirects = {
        "redirect_count": 1,
        "initial_url": url,
        "final_url": "https://example.invalid/end"
    }

    result = map_techniques(email, redirects)

    assert result["redirect_correlation"]["matched"]
