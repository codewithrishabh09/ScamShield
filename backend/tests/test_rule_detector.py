from decimal import Decimal

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.detectors.rule_detector import (
    _build_title,
    detect_rules,
)
from app.models.threat_pattern import ThreatPattern


@pytest.mark.parametrize(
    "pattern_name,expected_title",
    [
        (
            "urgent_language",
            "Urgent language detected",
        ),
        (
            "account_threat",
            "Account suspension threat detected",
        ),
        (
            "otp_request",
            "OTP or verification code reference detected",
        ),
        (
            "reward_bait",
            "Reward or prize bait detected",
        ),
    ],
)
def test_build_title(
    pattern_name: str,
    expected_title: str,
) -> None:
    assert _build_title(pattern_name) == expected_title


@pytest.mark.asyncio
async def test_detect_rules_from_database(
    db_session: AsyncSession,
) -> None:
    db_session.add(
        ThreatPattern(
            name="test_otp_pattern",
            category="otp_scam",
            pattern=r"\btestotp\b",
            severity="high",
            score_weight=Decimal("25.00"),
            description="Test OTP pattern.",
            is_active=True,
        )
    )

    await db_session.commit()

    findings = await detect_rules(
        db_session,
        "Please share your testotp with us.",
    )

    matching_findings = [
        finding
        for finding in findings
        if finding.pattern_name == "test_otp_pattern"
    ]

    assert len(matching_findings) == 1

    finding = matching_findings[0]

    assert finding.finding_type == "test_otp_pattern"
    assert finding.category == "otp_scam"
    assert finding.severity == "high"
    assert finding.evidence == "testotp"
    assert finding.score_contribution == Decimal("25.00")


@pytest.mark.asyncio
async def test_detect_rules_ignores_non_matching_pattern(
    db_session: AsyncSession,
) -> None:
    db_session.add(
        ThreatPattern(
            name="test_non_matching",
            category="phishing",
            pattern=r"\bdefinitelynotpresent\b",
            severity="medium",
            score_weight=Decimal("10.00"),
            description="Test pattern.",
            is_active=True,
        )
    )

    await db_session.commit()

    findings = await detect_rules(
        db_session,
        "This message contains nothing suspicious.",
    )

    matching_findings = [
        finding
        for finding in findings
        if finding.pattern_name == "test_non_matching"
    ]

    assert matching_findings == []


@pytest.mark.asyncio
async def test_detect_rules_ignores_invalid_regex(
    db_session: AsyncSession,
) -> None:
    db_session.add(
        ThreatPattern(
            name="test_invalid_regex",
            category="phishing",
            pattern="[invalid",
            severity="high",
            score_weight=Decimal("20.00"),
            description="Invalid regex test.",
            is_active=True,
        )
    )

    await db_session.commit()

    findings = await detect_rules(
        db_session,
        "This message contains suspicious content.",
    )

    matching_findings = [
        finding
        for finding in findings
        if finding.pattern_name == "test_invalid_regex"
    ]

    assert matching_findings == []