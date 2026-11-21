from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat_pattern import ThreatPattern


INITIAL_PATTERNS = [
    {
        "name": "urgent_language",
        "category": "phishing",
        "pattern": (
            r"\b(urgent|immediately|act now|do not delay|"
            r"within\s+\d+\s*(minutes?|hours?)|right away)\b"
        ),
        "severity": "medium",
        "score_weight": 15,
        "description": (
            "Detects language designed to create urgency "
            "and pressure the recipient into acting quickly."
        ),
    },
    {
        "name": "account_threat",
        "category": "account_takeover",
        "pattern": (
            r"\b(account|card|wallet|bank)\b.{0,80}"
            r"\b(blocked|suspended|deactivated|closed|locked)\b"
        ),
        "severity": "high",
        "score_weight": 20,
        "description": (
            "Detects threats involving account suspension "
            "or loss of access."
        ),
    },
    {
        "name": "otp_request",
        "category": "otp_scam",
        "pattern": (
            r"\b(otp|one[- ]time password|verification code|"
            r"security code)\b"
        ),
        "severity": "critical",
        "score_weight": 25,
        "description": (
            "Detects references to OTPs or verification codes "
            "that may indicate credential theft attempts."
        ),
    },
    {
        "name": "password_request",
        "category": "account_takeover",
        "pattern": (
            r"\b(password|passcode|pin|mpin|login credentials)\b"
        ),
        "severity": "critical",
        "score_weight": 25,
        "description": (
            "Detects requests or references to sensitive "
            "authentication credentials."
        ),
    },
    {
        "name": "financial_request",
        "category": "financial_scam",
        "pattern": (
            r"\b(send|transfer|pay|deposit|invest|"
            r"payment|money|amount|upi)\b"
        ),
        "severity": "high",
        "score_weight": 15,
        "description": (
            "Detects language associated with financial "
            "transactions or money movement."
        ),
    },
    {
        "name": "reward_bait",
        "category": "lottery_prize",
        "pattern": (
            r"\b(congratulations|won|winner|reward|"
            r"cashback|prize|lottery|gift|bonus)\b"
        ),
        "severity": "high",
        "score_weight": 15,
        "description": (
            "Detects reward or prize language commonly "
            "used in fraudulent messages."
        ),
    },
    {
        "name": "kyc_request",
        "category": "phishing",
        "pattern": (
            r"\b(kyc|know your customer)\b.{0,80}"
            r"\b(update|verify|complete|submit)\b"
        ),
        "severity": "high",
        "score_weight": 20,
        "description": (
            "Detects suspicious KYC verification language."
        ),
    },
    {
        "name": "click_link_request",
        "category": "phishing",
        "pattern": (
            r"\b(click|tap|open|visit)\b.{0,50}"
            r"\b(link|url|website|button)\b"
        ),
        "severity": "medium",
        "score_weight": 10,
        "description": (
            "Detects attempts to persuade users to open "
            "a link or website."
        ),
    },
    {
        "name": "job_offer_bait",
        "category": "job_scam",
        "pattern": (
            r"\b(job|work from home|part[- ]time|"
            r"salary|hiring|vacancy|employment)\b"
        ),
        "severity": "medium",
        "score_weight": 15,
        "description": (
            "Detects job-related language that may be "
            "associated with fraudulent employment offers."
        ),
    },
    {
        "name": "guaranteed_investment",
        "category": "investment_scam",
        "pattern": (
            r"\b(guaranteed|sure profit|risk[- ]free|"
            r"fixed return|double your money)\b"
        ),
        "severity": "critical",
        "score_weight": 25,
        "description": (
            "Detects unrealistic or guaranteed investment "
            "return claims."
        ),
    },
]


async def seed_threat_patterns(
    db: AsyncSession,
) -> int:
    inserted = 0

    for pattern_data in INITIAL_PATTERNS:
        result = await db.execute(
            select(ThreatPattern).where(
                ThreatPattern.name == pattern_data["name"]
            )
        )

        existing = result.scalar_one_or_none()

        if existing:
            continue

        db.add(
            ThreatPattern(
                **pattern_data,
            )
        )

        inserted += 1

    await db.commit()

    return inserted