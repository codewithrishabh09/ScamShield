from decimal import Decimal

from app.services.url_analyzer import (
    analyze_url,
    extract_urls,
)


def test_extract_urls() -> None:
    content = (
        "Please visit https://example.com/login "
        "and confirm your account."
    )

    urls = extract_urls(content)

    assert urls == [
        "https://example.com/login"
    ]


def test_extract_multiple_urls() -> None:
    content = (
        "Visit https://example.com and "
        "https://example.org/verify."
    )

    urls = extract_urls(content)

    assert len(urls) == 2
    assert "https://example.com" in urls
    assert "https://example.org/verify" in urls


def test_https_url() -> None:
    result = analyze_url(
        "https://example.com"
    )

    assert result.is_https is True
    assert result.domain == "example.com"
    assert result.risk_score == Decimal("0")
    assert result.is_suspicious is False


def test_http_url_is_suspicious() -> None:
    result = analyze_url(
        "http://example.com/login"
    )

    assert result.is_https is False
    assert result.risk_score >= Decimal("30")
    assert result.is_suspicious is True


def test_ip_address_detection() -> None:
    result = analyze_url(
        "http://192.168.1.100/login"
    )

    signal_types = {
        signal.signal_type
        for signal in result.signals
    }

    assert "ip_hostname" in signal_types


def test_suspicious_tld_detection() -> None:
    result = analyze_url(
        "https://secure-login.xyz/verify"
    )

    signal_types = {
        signal.signal_type
        for signal in result.signals
    }

    assert "suspicious_tld" in signal_types
    assert "sensitive_path" in signal_types
    assert result.is_suspicious is True


def test_punycode_detection() -> None:
    result = analyze_url(
        "https://xn--pple-43d.example/login"
    )

    signal_types = {
        signal.signal_type
        for signal in result.signals
    }

    assert "punycode_domain" in signal_types


def test_at_symbol_detection() -> None:
    result = analyze_url(
        "https://google.com@example.com/login"
    )

    signal_types = {
        signal.signal_type
        for signal in result.signals
    }

    assert "at_symbol" in signal_types