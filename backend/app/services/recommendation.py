from dataclasses import dataclass
from decimal import Decimal


@dataclass
class Recommendation:
    action: str
    priority: str


def build_recommendation(
    risk_score: Decimal,
    category: str,
) -> Recommendation:
    if risk_score >= 80:
        if category == "otp_scam":
            action = (
                "Do not share any OTP or verification code. "
                "Banks and legitimate services do not require "
                "you to disclose your OTP."
            )

        elif category == "investment_scam":
            action = (
                "Do not transfer or invest money based on this "
                "offer. Guaranteed or unusually high returns "
                "are strong scam indicators."
            )

        elif category == "job_scam":
            action = (
                "Do not pay registration, verification, "
                "training, or security fees for this job offer. "
                "Verify the employer independently."
            )

        elif category == "account_takeover":
            action = (
                "Do not share passwords, PINs, or verification "
                "codes. Access your account through the official "
                "app or website and secure it immediately."
            )

        elif category == "phishing":
            action = (
                "Do not click the suspicious link or enter "
                "personal information. Open the official "
                "website or app directly."
            )

        else:
            action = (
                "Do not click links, share sensitive information, "
                "or transfer money. Verify the request through "
                "an official channel."
            )

        return Recommendation(
            action=action,
            priority="immediate",
        )

    if risk_score >= 60:
        return Recommendation(
            action=(
                "Do not provide sensitive information or make "
                "payments until the sender and request have "
                "been independently verified."
            ),
            priority="high",
        )

    if risk_score >= 30:
        return Recommendation(
            action=(
                "Proceed carefully and verify the message "
                "before taking any action."
            ),
            priority="medium",
        )

    return Recommendation(
        action=(
            "No major scam indicators were detected. "
            "Continue using normal security precautions."
        ),
        priority="low",
    )