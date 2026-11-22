from decimal import Decimal


def calculate_risk_score(
    score_contributions: list[Decimal],
) -> Decimal:
    total = sum(
        score_contributions,
        Decimal("0"),
    )

    return min(
        total,
        Decimal("100"),
    )


def determine_risk_level(
    risk_score: Decimal,
) -> str:
    if risk_score < 30:
        return "low"

    if risk_score < 60:
        return "medium"

    if risk_score < 80:
        return "high"

    return "critical"


def determine_verdict(
    risk_score: Decimal,
) -> str:
    if risk_score >= 60:
        return "suspicious"

    return "likely_safe"


def determine_category(
    categories: list[str],
) -> str:
    if not categories:
        return "unknown"

    counts: dict[str, int] = {}

    for category in categories:
        counts[category] = (
            counts.get(category, 0) + 1
        )

    return max(
        counts,
        key=counts.get,
    )