from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class URLSignal:
    signal_type: str
    title: str
    description: str
    severity: str
    score_contribution: int


SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "buzz",
    "club",
    "work",
    "loan",
    "zip",
    "mov",
}


SUSPICIOUS_PATH_TERMS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "payment",
    "pay",
    "wallet",
    "kyc",
    "otp",
    "confirm",
}


def detect_url_signals(
    parsed_url,
) -> list[URLSignal]:
    signals: list[URLSignal] = []

    hostname = parsed_url.hostname or ""
    path = parsed_url.path.lower()

    # HTTP instead of HTTPS
    if parsed_url.scheme.lower() == "http":
        signals.append(
            URLSignal(
                signal_type="http_connection",
                title="Unencrypted HTTP URL detected",
                description=(
                    "The URL uses HTTP instead of HTTPS. "
                    "Sensitive information should not be "
                    "submitted through an unencrypted connection."
                ),
                severity="medium",
                score_contribution=15,
            )
        )

    # Suspicious TLD
    tld = _extract_tld(hostname)

    if tld in SUSPICIOUS_TLDS:
        signals.append(
            URLSignal(
                signal_type="suspicious_tld",
                title="Suspicious domain extension detected",
                description=(
                    f"The domain uses the .{tld} extension, "
                    "which can be abused in fraudulent links."
                ),
                severity="medium",
                score_contribution=15,
            )
        )

    # IP address instead of domain
    if _is_ip_address(hostname):
        signals.append(
            URLSignal(
                signal_type="ip_hostname",
                title="IP address used as hostname",
                description=(
                    "The URL points directly to an IP address "
                    "instead of using a normal domain name."
                ),
                severity="high",
                score_contribution=25,
            )
        )

    # Punycode
    if "xn--" in hostname.lower():
        signals.append(
            URLSignal(
                signal_type="punycode_domain",
                title="Punycode domain detected",
                description=(
                    "The domain contains punycode, which can "
                    "sometimes be used for look-alike domains."
                ),
                severity="high",
                score_contribution=20,
            )
        )

    # Excessive subdomains
    subdomain_count = max(
        hostname.count(".") - 1,
        0,
    )

    if subdomain_count >= 3:
        signals.append(
            URLSignal(
                signal_type="excessive_subdomains",
                title="Excessive subdomains detected",
                description=(
                    "The URL contains an unusually large number "
                    "of subdomains."
                ),
                severity="medium",
                score_contribution=10,
            )
        )

    # Very long URL
    if len(parsed_url.geturl()) > 150:
        signals.append(
            URLSignal(
                signal_type="long_url",
                title="Unusually long URL detected",
                description=(
                    "The URL is unusually long and may contain "
                    "tracking or obfuscation parameters."
                ),
                severity="medium",
                score_contribution=10,
            )
        )

    # Suspicious path terms
    matched_terms = [
        term
        for term in SUSPICIOUS_PATH_TERMS
        if term in path
    ]

    if matched_terms:
        signals.append(
            URLSignal(
                signal_type="sensitive_path",
                title="Sensitive action path detected",
                description=(
                    "The URL contains terms commonly associated "
                    "with login, verification, payment, or account "
                    "actions."
                ),
                severity="medium",
                score_contribution=15,
            )
        )

    # Suspicious characters
    if "@" in parsed_url.geturl():
        signals.append(
            URLSignal(
                signal_type="at_symbol",
                title="Suspicious @ symbol detected",
                description=(
                    "The URL contains an @ symbol, which can be "
                    "used to obscure the actual destination."
                ),
                severity="high",
                score_contribution=20,
            )
        )

    # Encoded characters
    encoded_count = parsed_url.geturl().count("%")

    if encoded_count >= 5:
        signals.append(
            URLSignal(
                signal_type="encoded_url",
                title="Heavy URL encoding detected",
                description=(
                    "The URL contains a large number of encoded "
                    "characters that may indicate obfuscation."
                ),
                severity="medium",
                score_contribution=10,
            )
        )

    return signals


def _extract_tld(hostname: str) -> str:
    parts = hostname.lower().split(".")

    if len(parts) < 2:
        return ""

    return parts[-1]


def _is_ip_address(hostname: str) -> bool:
    parts = hostname.split(".")

    if len(parts) != 4:
        return False

    try:
        return all(
            0 <= int(part) <= 255
            for part in parts
        )
    except ValueError:
        return False