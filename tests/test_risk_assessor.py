
from src.risk_assessor import assess_risk, get_priority


def findings(*rule_ids):
    return {
        "findings": [
            {
                "rule_id": rule_id,
                "description": f"Detected {rule_id}"
            }
            for rule_id in rule_ids
        ]
    }


def feed(match_type, verified=True):
    return {
        "feed_integrity": {
            "verified": verified
        },
        "match_counts": {
            "exact_url": int(match_type == "exact_url"),
            "normalized_url": int(
                match_type == "normalized_url"
            ),
            "hostname": int(match_type == "hostname")
        }
    }


def test_empty_assessment():
    result = assess_risk({"findings": []})

    assert result["score"] == 0
    assert result["review_priority"] == "low"
    assert result["verdict"] == "not_determined"


def test_four_advanced_findings():
    result = assess_risk(findings(
        "EMAIL-001",
        "EMAIL-002",
        "EMAIL-003",
        "EMAIL-004"
    ))

    assert result["score"] == 55
    assert result["review_priority"] == "elevated"


def test_duplicate_rule_not_double_counted():
    result = assess_risk(findings(
        "EMAIL-002",
        "EMAIL-002"
    ))

    assert result["score"] == 20
    assert result["signal_count"] == 1


def test_exact_feed_match():
    result = assess_risk(
        findings(),
        feed("exact_url")
    )

    assert result["score"] == 30


def test_unverified_feed_ignored():
    result = assess_risk(
        findings(),
        feed("exact_url", verified=False)
    )

    assert result["score"] == 0
    assert result["signal_count"] == 0


def test_strongest_feed_match_only():
    context = feed("exact_url")
    context["match_counts"]["hostname"] = 3

    result = assess_risk(findings(), context)

    assert result["score"] == 30


def test_score_capped_at_100():
    # Current rule categories plus strongest feed match
    # total 85 points. Confirm this model's result.
    result = assess_risk(
        findings(
            "EMAIL-001",
            "EMAIL-002",
            "EMAIL-003",
            "EMAIL-004"
        ),
        feed("exact_url")
    )

    assert result["score"] == 85
    assert result["score"] <= 100


def test_priority_thresholds():
    assert get_priority(0) == "low"
    assert get_priority(15) == "routine"
    assert get_priority(40) == "elevated"
    assert get_priority(70) == "high"
