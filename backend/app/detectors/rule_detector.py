import re
from dataclasses import dataclass
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_pattern import ThreatPattern


@dataclass
class RuleMatch:
    pattern_name: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    score_contribution: Decimal


async def detect_rules(
    db: AsyncSession,
    content: str,
) -> list[RuleMatch]:
    result = await db.execute(
        select(ThreatPattern).where(
            ThreatPattern.is_active.is_(True)
        )
    )

    patterns = result.scalars().all()

    matches: list[RuleMatch] = []

    for pattern in patterns:
        match = re.search(
            pattern.pattern,
            content,
            flags=re.IGNORECASE,
        )

        if not match:
            continue

        evidence = match.group(0).strip()

        matches.append(
            RuleMatch(
                pattern_name=pattern.name,
                category=pattern.category,
                severity=pattern.severity,
                title=_build_title(pattern.name),
                description=pattern.description
                or "Suspicious pattern detected.",
                evidence=evidence,
                score_contribution=Decimal(
                    str(pattern.score_weight)
                ),
            )
        )

    return matches


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