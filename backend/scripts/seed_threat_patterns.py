import asyncio
from decimal import Decimal

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.threat_pattern import ThreatPattern


THREAT_PATTERNS = [
    {
        "name": "urgent_language",
        "category": "phishing",
        "pattern": (
            r"\b(?:urgent|immediately|act now|verify now|"
            r"respond now|within 24 hours|today only|do it now)\b"
        ),
        "severity": "medium",
        "score_weight": Decimal("15.00"),
        "description": (
            "The message uses urgency or time pressure "
            "to push the recipient into immediate action."
        ),
    },
    {
        "name": "account_threat",
        "category": "phishing",
        "pattern": (
            r"\b(?:account will be blocked|account blocked|"
            r"account suspended|account will be suspended|"
            r"account deactivated|account will be deactivated|"
            r"access will be removed|kyc expired)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("20.00"),
        "description": (
            "The message threatens account suspension, "
            "deactivation, or loss of access."
        ),
    },
    {
        "name": "otp_request",
        "category": "otp_scam",
        "pattern": (
            r"\b(?:otp|one[\s-]?time password|verification code|"
            r"verify code|security code|authentication code)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("25.00"),
        "description": (
            "The message references an OTP or verification "
            "code that may be requested by a scammer."
        ),
    },
    {
        "name": "password_request",
        "category": "account_takeover",
        "pattern": (
            r"\b(?:password|atm pin|upi pin|login credentials|"
            r"internet banking password)\b"
        ),
        "severity": "critical",
        "score_weight": Decimal("25.00"),
        "description": (
            "The message references sensitive authentication "
            "credentials such as passwords or PINs."
        ),
    },
    {
        "name": "financial_request",
        "category": "financial_scam",
        "pattern": (
            r"\b(?:send money|transfer money|make a payment|"
            r"pay now|payment required|bank details|account number|"
            r"upi payment|upi id|transfer funds)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("25.00"),
        "description": (
            "The message contains a request or instruction "
            "related to sending money or financial details."
        ),
    },
    {
        "name": "reward_bait",
        "category": "lottery_prize_scam",
        "pattern": (
            r"\b(?:you won|you have won|claim your reward|"
            r"claim reward|cashback|cashback available|prize|"
            r"lottery winner|congratulations you won)\b"
        ),
        "severity": "medium",
        "score_weight": Decimal("15.00"),
        "description": (
            "The message uses rewards, prizes, cashback, "
            "or lottery claims to attract the recipient."
        ),
    },
    {
        "name": "kyc_request",
        "category": "phishing",
        "pattern": (
            r"\b(?:kyc|complete kyc|verify kyc|"
            r"kyc verification|kyc update)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("15.00"),
        "description": (
            "The message requests KYC verification or updates, "
            "which can be used in phishing attempts."
        ),
    },
    {
        "name": "click_link_request",
        "category": "phishing",
        "pattern": (
            r"\b(?:click this link|click the link|open this link|"
            r"tap this link|visit this link|click here to verify|"
            r"click here to claim)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("15.00"),
        "description": (
            "The message asks the recipient to open or click "
            "a link, which can lead to a phishing website."
        ),
    },
    {
        "name": "job_offer_bait",
        "category": "job_scam",
        "pattern": (
            r"\b(?:work from home|job offer|part[- ]time job|"
            r"easy income|guaranteed job)\b"
        ),
        "severity": "high",
        "score_weight": Decimal("20.00"),
        "description": (
            "The message contains suspicious job or easy-income "
            "language commonly used in job scams."
        ),
    },
    {
        "name": "guaranteed_investment",
        "category": "investment_scam",
        "pattern": (
            r"\b(?:guaranteed returns?|guaranteed profit|"
            r"double your money|risk[- ]free investment|"
            r"fixed returns?|100% profit)\b"
        ),
        "severity": "critical",
        "score_weight": Decimal("25.00"),
        "description": (
            "The message makes unrealistic or guaranteed "
            "investment or profit claims."
        ),
    },
]


async def seed_threat_patterns() -> None:
    async with AsyncSessionLocal() as db:
        inserted = 0
        updated = 0

        for pattern_data in THREAT_PATTERNS:
            result = await db.execute(
                select(ThreatPattern).where(
                    ThreatPattern.name == pattern_data["name"]
                )
            )

            existing = result.scalar_one_or_none()

            if existing:
                existing.category = pattern_data["category"]
                existing.pattern = pattern_data["pattern"]
                existing.severity = pattern_data["severity"]
                existing.score_weight = pattern_data["score_weight"]
                existing.description = pattern_data["description"]
                existing.is_active = True

                updated += 1
                continue

            db.add(
                ThreatPattern(
                    **pattern_data,
                )
            )

            inserted += 1

        await db.commit()

        print(
            f"Threat pattern seed completed. "
            f"Inserted: {inserted}, Updated: {updated}"
        )


if __name__ == "__main__":
    asyncio.run(seed_threat_patterns())