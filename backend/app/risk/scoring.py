from decimal import Decimal

from app.detectors.base import DetectionFinding


def calculate_rule_score(
    findings: list[DetectionFinding],
) -> Decimal:
    total_score = sum(
        (
            finding.score_contribution
            for finding in findings
        ),
        Decimal("0"),
    )

    return min(
        total_score.quantize(Decimal("0.01")),
        Decimal("100.00"),
    )


def get_risk_level(score: Decimal) -> str:
    if score >= Decimal("80.00"):
        return "critical"

    if score >= Decimal("60.00"):
        return "high"

    if score >= Decimal("30.00"):
        return "medium"

    return "low"