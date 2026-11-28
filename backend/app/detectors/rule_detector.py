import re
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.detectors.base import DetectionFinding
from app.models.threat_pattern import ThreatPattern


async def detect_rules(
    db: AsyncSession,
    content: str,
) -> list[DetectionFinding]:
    result = await db.execute(
        select(ThreatPattern).where(
            ThreatPattern.is_active.is_(True)
        )
    )

    patterns = result.scalars().all()

    findings: list[DetectionFinding] = []

    for pattern in patterns:
        try:
            match = re.search(
                pattern.pattern,
                content,
                flags=re.IGNORECASE,
            )
        except re.error:
            continue

        if not match:
            continue

        evidence = match.group(0).strip()

        findings.append(
            DetectionFinding(
                pattern_name=pattern.name,
                finding_type=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                title=_build_title(pattern.name),
                description=(
                    pattern.description
                    or "Suspicious pattern detected."
                ),
                evidence=evidence,
                score_contribution=Decimal(
                    str(pattern.score_weight)
                ),
            )
        )

    return findings


def _build_title(pattern_name: str) -> str:
    titles = {
        "urgent_language": "Urgent language detected",
        "account_threat": "Account suspension threat detected",
        "otp_request": "OTP or verification code reference detected",
        "password_request": "Sensitive credential reference detected",
        "financial_request": "Financial transaction request detected",
        "reward_bait": "Reward or prize bait detected",
        "kyc_request": "KYC verification request detected",
        "click_link_request": "Link-click request detected",
        "job_offer_bait": "Job offer language detected",
        "guaranteed_investment": "Guaranteed investment claim detected",
    }

    return titles.get(
        pattern_name,
        "Suspicious pattern detected",
    )