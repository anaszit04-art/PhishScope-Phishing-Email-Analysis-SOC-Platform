
from datetime import datetime, timezone


RULE_WEIGHTS = {
    "EMAIL-001": 10,
    "EMAIL-002": 20,
    "EMAIL-003": 15,
    "EMAIL-004": 10
}

FEED_WEIGHTS = {
    "exact_url": 30,
    "normalized_url": 25,
    "hostname": 5
}


def get_priority(score):
    """Convert heuristic points into review priority."""
    if score >= 70:
        return "high"
    if score >= 40:
        return "elevated"
    if score >= 15:
        return "routine"
    return "low"


def make_contribution(source, identifier, points, reason):
    """Describe why points were added."""
    return {
        "source": source,
        "identifier": identifier,
        "points": points,
        "reason": reason
    }


def assess_risk(advanced_result, feed_context=None):
    """
    Calculate an explainable investigation-priority score.

    This is not a probability or a phishing verdict.
    """

    advanced_result = advanced_result or {}
    contributions = []
    limitations = []

    # Each advanced detection rule contributes once.
    seen_rules = set()

    for finding in advanced_result.get("findings", []):
        rule_id = finding.get("rule_id")

        if rule_id not in RULE_WEIGHTS:
            continue

        if rule_id in seen_rules:
            continue

        seen_rules.add(rule_id)

        points = RULE_WEIGHTS[rule_id]

        contributions.append(make_contribution(
            "advanced_detection",
            rule_id,
            points,
            finding.get(
                "description",
                "Advanced detection signal"
            )
        ))

    # Evaluate optional threat intelligence.
    feed_context = feed_context or {}

    feed_verified = feed_context.get(
        "feed_integrity", {}
    ).get("verified")

    match_counts = feed_context.get(
        "match_counts", {}
    )

    # Only credit intelligence when the local feed hash
    # matches its recorded acquisition metadata.
    if feed_verified is True:

        # Count the strongest matching category once.
        for match_type in (
            "exact_url",
            "normalized_url",
            "hostname"
        ):
            if match_counts.get(match_type, 0) > 0:

                contributions.append(make_contribution(
                    "threat_intelligence",
                    match_type,
                    FEED_WEIGHTS[match_type],
                    (
                        f"At least one {match_type} "
                        "match in the local feed snapshot"
                    )
                ))

                break

    elif feed_context:
        limitations.append(
            "Feed integrity was not verified; "
            "feed matches received zero points."
        )

    # Additional limitations.
    if "EMAIL-004" in seen_rules:
        limitations.append(
            "Email authentication results were read "
            "from headers, not independently verified."
        )

    limitations.extend([
        "Scores are heuristic and not calibrated probabilities.",
        "No finding alone establishes malicious intent.",
        "The result requires analyst review."
    ])

    raw_score = sum(
        item["points"]
        for item in contributions
    )

    score = min(100, raw_score)

    return {
        "module": "Explainable Risk Assessment",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "score": score,
        "maximum_score": 100,
        "review_priority": get_priority(score),
        "assessment_type": "heuristic_review_priority",
        "contributions": contributions,
        "signal_count": len(contributions),
        "limitations": limitations,
        "verdict": "not_determined"
    }
