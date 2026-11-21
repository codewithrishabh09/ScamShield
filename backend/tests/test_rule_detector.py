import pytest

from app.detectors.rule_detector import _build_title


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