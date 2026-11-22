from decimal import Decimal

from app.risk.risk_engine import (
    calculate_risk_score,
    determine_category,
    determine_risk_level,
    determine_verdict,
)


def test_risk_score_is_capped_at_100() -> None:
    score = calculate_risk_score(
        [
            Decimal("60"),
            Decimal("50"),
        ]
    )

    assert score == Decimal("100")


def test_low_risk() -> None:
    assert (
        determine_risk_level(
            Decimal("20")
        )
        == "low"
    )


def test_medium_risk() -> None:
    assert (
        determine_risk_level(
            Decimal("45")
        )
        == "medium"
    )


def test_high_risk() -> None:
    assert (
        determine_risk_level(
            Decimal("70")
        )
        == "high"
    )


def test_critical_risk() -> None:
    assert (
        determine_risk_level(
            Decimal("90")
        )
        == "critical"
    )


def test_suspicious_verdict() -> None:
    assert (
        determine_verdict(
            Decimal("70")
        )
        == "suspicious"
    )


def test_safe_verdict() -> None:
    assert (
        determine_verdict(
            Decimal("20")
        )
        == "likely_safe"
    )


def test_category() -> None:
    category = determine_category(
        [
            "phishing",
            "phishing",
            "otp_scam",
        ]
    )

    assert category == "phishing"


def test_unknown_category() -> None:
    assert (
        determine_category([])
        == "unknown"
    )