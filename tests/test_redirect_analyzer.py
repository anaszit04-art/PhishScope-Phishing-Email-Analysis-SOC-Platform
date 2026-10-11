
import pytest

from src.redirect_analyzer import analyze_redirects


def test_valid_chain():
    records = [
        {
            "url": "https://a.example.invalid/start",
            "status": 302,
            "location": "/final"
        },
        {
            "url": "https://a.example.invalid/final",
            "status": 200
        }
    ]

    result = analyze_redirects(records)

    assert result["total_hops"] == 2
    assert result["redirect_count"] == 1


def test_redirect_loop():
    records = [
        {
            "url": "https://a.example.invalid/one",
            "status": 302,
            "location": "/two"
        },
        {
            "url": "https://a.example.invalid/two",
            "status": 302,
            "location": "/one"
        },
        {
            "url": "https://a.example.invalid/one",
            "status": 200
        }
    ]

    with pytest.raises(ValueError):
        analyze_redirects(records)


def test_invalid_scheme():
    with pytest.raises(ValueError):
        analyze_redirects([
            {
                "url": "file:///etc/passwd",
                "status": 200
            }
        ])


def test_missing_location():
    with pytest.raises(ValueError):
        analyze_redirects([
            {
                "url": "https://a.example.invalid/",
                "status": 302
            }
        ])


def test_empty_records():
    with pytest.raises(ValueError):
        analyze_redirects([])
