from dataclasses import dataclass


@dataclass(frozen=True)
class ScamRule:
    name: str
    finding_type: str
    severity: str
    title: str
    description: str
    keywords: tuple[str, ...]
    score_contribution: float


SCAM_RULES: tuple[ScamRule, ...] = (
    ScamRule(
        name="urgent_action",
        finding_type="urgency",
        severity="high",
        title="Urgent action language detected",
        description=(
            "The message pressures the recipient to act immediately "
            "or within a very short period."
        ),
        keywords=(
            "urgent",
            "immediately",
            "act now",
            "verify now",
            "respond now",
            "within 24 hours",
            "today only",
            "do it now",
        ),
        score_contribution=15,
    ),
    ScamRule(
        name="account_threat",
        finding_type="account_threat",
        severity="high",
        title="Account threat detected",
        description=(
            "The message threatens account suspension, blocking, "
            "deactivation, or loss of access."
        ),
        keywords=(
            "account will be blocked",
            "account blocked",
            "account suspended",
            "account will be suspended",
            "account deactivated",
            "account will be deactivated",
            "access will be removed",
            "kyc expired",
        ),
        score_contribution=20,
    ),
    ScamRule(
        name="otp_request",
        finding_type="otp_request",
        severity="critical",
        title="OTP or verification code request detected",
        description=(
            "The message appears to request an OTP, verification code, "
            "or similar authentication credential."
        ),
        keywords=(
            "otp",
            "one time password",
            "one-time password",
            "verification code",
            "verify code",
            "security code",
            "authentication code",
        ),
        score_contribution=25,
    ),
    ScamRule(
        name="financial_request",
        finding_type="financial_request",
        severity="critical",
        title="Financial action request detected",
        description=(
            "The message asks the recipient to send money, make a payment, "
            "transfer funds, or provide banking information."
        ),
        keywords=(
            "send money",
            "transfer money",
            "make a payment",
            "pay now",
            "payment required",
            "bank details",
            "account number",
            "upi payment",
            "upi id",
            "transfer funds",
        ),
        score_contribution=25,
    ),
    ScamRule(
        name="reward_bait",
        finding_type="reward_bait",
        severity="high",
        title="Reward or prize bait detected",
        description=(
            "The message uses a prize, reward, cashback, or winning claim "
            "to encourage the recipient to take action."
        ),
        keywords=(
            "you won",
            "you have won",
            "claim your reward",
            "claim reward",
            "cashback",
            "cashback available",
            "prize",
            "lottery winner",
            "congratulations you won",
        ),
        score_contribution=15,
    ),
    ScamRule(
        name="credential_request",
        finding_type="credential_request",
        severity="critical",
        title="Sensitive credential request detected",
        description=(
            "The message appears to request sensitive credentials such as "
            "a password, PIN, or banking secret."
        ),
        keywords=(
            "password",
            "pin",
            "atm pin",
            "upi pin",
            "login credentials",
            "internet banking password",
        ),
        score_contribution=25,
    ),
    ScamRule(
        name="suspicious_link_action",
        finding_type="suspicious_link_action",
        severity="high",
        title="Suspicious link action language detected",
        description=(
            "The message encourages the recipient to click or open a link "
            "to complete a sensitive action."
        ),
        keywords=(
            "click this link",
            "click the link",
            "open this link",
            "tap this link",
            "visit this link",
            "click here to verify",
            "click here to claim",
        ),
        score_contribution=15,
    ),
)