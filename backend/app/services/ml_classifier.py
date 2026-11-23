from dataclasses import dataclass
from pathlib import Path

import joblib


ROOT_DIR = Path(__file__).resolve().parents[3]

MODEL_PATH = (
    ROOT_DIR
    / "ml"
    / "models"
    / "scam_classifier.joblib"
)


@dataclass
class MLClassification:
    category: str
    confidence: float


_model = None


def get_model():
    global _model

    if _model is None:
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"ML model not found: {MODEL_PATH}"
            )

        _model = joblib.load(
            MODEL_PATH
        )

    return _model


def classify_text(
    text: str,
) -> MLClassification:
    model = get_model()

    probabilities = model.predict_proba(
        [text]
    )[0]

    classes = model.classes_

    best_index = probabilities.argmax()

    category = str(
        classes[best_index]
    )

    confidence = float(
        probabilities[best_index]
    )

    return MLClassification(
        category=category,
        confidence=confidence,
    )