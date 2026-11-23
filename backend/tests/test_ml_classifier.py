import pytest

from app.services.ml_classifier import (
    MODEL_PATH,
    classify_text,
)


@pytest.mark.skipif(
    not MODEL_PATH.exists(),
    reason="ML model has not been trained yet.",
)
def test_classify_text() -> None:
    result = classify_text(
        "URGENT! Verify your account immediately"
    )

    assert result.category
    assert 0.0 <= result.confidence <= 1.0