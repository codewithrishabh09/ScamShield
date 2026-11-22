from decimal import Decimal

from app.services.recommendation import (
    build_recommendation,
)


def test_critical_otp_recommendation() -> None:
    result = build_recommendation(
        Decimal("90"),
        "otp_scam",
    )

    assert result.priority == "immediate"
    assert "OTP" in result.action


def test_investment_recommendation() -> None:
    result = build_recommendation(
        Decimal("90"),
        "investment_scam",
    )

    assert result.priority == "immediate"
    assert "invest" in result.action.lower()


def test_low_risk_recommendation() -> None:
    result = build_recommendation(
        Decimal("10"),
        "unknown",
    )

    assert result.priority == "low"