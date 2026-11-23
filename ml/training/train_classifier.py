from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


ROOT_DIR = Path(__file__).resolve().parents[2]

DATASET_PATH = (
    ROOT_DIR
    / "ml"
    / "datasets"
    / "scam_messages.csv"
)

MODEL_PATH = (
    ROOT_DIR
    / "ml"
    / "models"
    / "scam_classifier.joblib"
)


def main() -> None:
    dataframe = pd.read_csv(
        DATASET_PATH
    )

    if dataframe.empty:
        raise ValueError(
            "Training dataset is empty."
        )

    required_columns = {
        "text",
        "category",
    }

    missing_columns = (
        required_columns
        - set(dataframe.columns)
    )

    if missing_columns:
        raise ValueError(
            f"Missing columns: {missing_columns}"
        )

    X = dataframe["text"].astype(str)
    y = dataframe["category"].astype(str)

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y,
        )
    )

    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    ngram_range=(1, 2),
                    max_features=5000,
                    sublinear_tf=True,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=2000,
                ),
            ),
        ]
    )

    pipeline.fit(
        X_train,
        y_train,
    )

    predictions = pipeline.predict(
        X_test
    )

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        pipeline,
        MODEL_PATH,
    )

    print(
        f"Model saved to: {MODEL_PATH}"
    )


if __name__ == "__main__":
    main()