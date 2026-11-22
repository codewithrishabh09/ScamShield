import re
from dataclasses import dataclass
from decimal import Decimal
from urllib.parse import urlparse

from app.detectors.url_detector import (
    URLSignal,
    detect_url_signals,
)


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


@dataclass
class URLAnalysisResult:
    url: str
    domain: str
    is_https: bool
    is_suspicious: bool
    risk_score: Decimal
    signals: list[URLSignal]


def extract_urls(content: str) -> list[str]:
    matches = URL_PATTERN.findall(content)

    cleaned_urls = []

    for url in matches:
        cleaned = url.rstrip(
            ".,!?;:)]}>"
        )

        if cleaned:
            cleaned_urls.append(cleaned)

    return cleaned_urls


def analyze_url(
    url: str,
) -> URLAnalysisResult:
    parsed_url = urlparse(url)

    signals = detect_url_signals(
        parsed_url
    )

    total_score = sum(
        signal.score_contribution
        for signal in signals
    )

    risk_score = Decimal(
        str(min(total_score, 100))
    )

    return URLAnalysisResult(
        url=url,
        domain=parsed_url.hostname or "",
        is_https=(
            parsed_url.scheme.lower() == "https"
        ),
        is_suspicious=risk_score >= 30,
        risk_score=risk_score,
        signals=signals,
    )


def analyze_content_urls(
    content: str,
) -> list[URLAnalysisResult]:
    urls = extract_urls(content)

    return [
        analyze_url(url)
        for url in urls
    ]