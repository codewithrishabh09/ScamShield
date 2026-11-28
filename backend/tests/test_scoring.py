from decimal import Decimal

from app.detectors.base import DetectionFinding
from app.risk.scoring import (
    calculate_rule_score,
    get_risk_level,
)


def create_finding(score: str) -> DetectionFinding:
    return DetectionFinding(
        pattern_name="test_pattern",
        finding_type="test_pattern",
        category="phishing",
        severity="medium",
        title="Test finding",
        description="Test description",
        evidence="test evidence",
        score_contribution=Decimal(score),
    )


def test_calculate_rule_score() -> None:
    findings = [
        create_finding("15.00"),
        create_finding("25.00"),
        create_finding("20.00"),
    ]

    score = calculate_rule_score(findings)

    assert score == Decimal("60.00")


def test_rule_score_is_capped_at_100() -> None:
    findings = [
        create_finding("50.00"),
        create_finding("40.00"),
        create_finding("30.00"),
    ]

    score = calculate_rule_score(findings)

    assert score == Decimal("100.00")


def test_risk_level_low() -> None:
    assert get_risk_level(Decimal("20.00")) == "low"


def test_risk_level_medium() -> None:
    assert get_risk_level(Decimal("30.00")) == "medium"


def test_risk_level_high() -> None:
    assert get_risk_level(Decimal("60.00")) == "high"


def test_risk_level_critical() -> None:
    assert get_risk_level(Decimal("80.00")) == "critical"