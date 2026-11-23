import logging
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.detectors.rule_detector import detect_rules
from app.models.analysis_result import AnalysisResult
from app.models.risk_finding import RiskFinding
from app.models.scan import Scan
from app.models.url_analysis import URLAnalysis
from app.risk.risk_engine import (
    calculate_risk_score,
    determine_category,
    determine_risk_level,
    determine_verdict,
)
from app.services.explanation import (
    Explanation,
    build_explanations,
    build_risk_summary,
)
from app.services.ml_classifier import (
    MLClassification,
    classify_text,
)
from app.services.recommendation import build_recommendation
from app.services.url_analyzer import analyze_content_urls


logger = logging.getLogger(__name__)

# Minimum confidence required before the ML result is used
ML_CONFIDENCE_THRESHOLD = 0.70

# Maximum number of points the ML classifier can add to the risk score
ML_MAX_SCORE = Decimal("20")

# Identifies the model in the stored finding metadata
ML_MODEL_NAME = "tfidf-logistic-regression-v1"

# Maximum evidence length stored for the ML finding
ML_EVIDENCE_MAX_CHARS = 500


@dataclass
class ScanAnalysisOutput:
    analysis_result: AnalysisResult
    risk_summary: str
    recommendation: Any
    explanations: list[Explanation]


def serialize_signals(signals) -> list[dict]:
    """Convert signal objects into JSON-serializable dicts for the JSONB column."""
    serialized = []

    for signal in signals:
        if is_dataclass(signal):
            data = asdict(signal)
        elif hasattr(signal, "model_dump"):
            data = signal.model_dump()
        else:
            data = dict(vars(signal))

        # Decimal is not JSON serializable, so convert it to float
        for key, value in data.items():
            if isinstance(value, Decimal):
                data[key] = float(value)

        serialized.append(data)

    return serialized


def safe_classify(text: str) -> MLClassification | None:
    """Run the ML classifier as an optional signal.

    Returns None if the model file is missing or classification fails,
    so rule-based and URL analysis keep working.
    """
    try:
        return classify_text(text)
    except FileNotFoundError:
        logger.warning("ML model not found, skipping ML signal.")
    except Exception:
        logger.exception("ML classification failed, skipping ML signal.")

    return None


def is_ml_signal_strong(ml_result: MLClassification | None) -> bool:
    """Return True when the ML result is present and confident enough."""
    return (
        ml_result is not None
        and ml_result.confidence >= ML_CONFIDENCE_THRESHOLD
    )


def calculate_ml_score(ml_result: MLClassification | None) -> Decimal:
    """Convert ML confidence into risk points, capped at ML_MAX_SCORE."""
    if not is_ml_signal_strong(ml_result):
        return Decimal("0")

    score = min(
        Decimal(str(ml_result.confidence)) * ML_MAX_SCORE,
        ML_MAX_SCORE,
    )

    # Match the Numeric(5, 2) column precision
    return score.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


async def analyze_scan(
    db: AsyncSession,
    scan: Scan,
) -> ScanAnalysisOutput:
    # Read the values up front: after a commit the ORM object is expired,
    # and accessing its attributes in async code raises MissingGreenlet.
    scan_id = scan.id
    scan_content = scan.content

    rule_matches = await detect_rules(db, scan_content)

    url_results = analyze_content_urls(scan_content)

    ml_result = safe_classify(scan_content)
    ml_strong = is_ml_signal_strong(ml_result)

    rule_score = calculate_risk_score(
        [match.score_contribution for match in rule_matches]
    )

    url_score = calculate_risk_score(
        [result.risk_score for result in url_results]
    )

    # The ML score must be calculated BEFORE the combined score,
    # otherwise it would not be included in the final risk.
    ml_score = calculate_ml_score(ml_result)

    combined_score = min(
        rule_score + url_score + ml_score,
        Decimal("100"),
    )

    risk_level = determine_risk_level(combined_score)

    categories = [match.category for match in rule_matches]

    if any(result.is_suspicious for result in url_results):
        categories.append("phishing")

    if ml_strong:
        categories.append(ml_result.category)

    category = determine_category(categories)

    verdict = determine_verdict(combined_score)

    recommendation = build_recommendation(
        combined_score,
        category,
    )

    # Rule matches and URL signals are explained together
    all_findings = list(rule_matches)

    for result in url_results:
        all_findings.extend(result.signals)

    explanations = build_explanations(all_findings)

    # Add the ML finding to the explanations so it shows up in "why"
    if ml_strong:
        explanations.append(
            Explanation(
                finding_type="ml_classification",
                title=f"ML model detected {ml_result.category}",
                description=(
                    "The NLP classifier identified language "
                    "patterns associated with this scam category."
                ),
                evidence=None,
                severity="medium",
                score_contribution=ml_score,
            )
        )

    risk_summary = build_risk_summary(
        combined_score,
        risk_level,
        category,
        explanations,
    )

    analysis_result = AnalysisResult(
        scan_id=scan_id,
        risk_score=combined_score,
        risk_level=risk_level,
        category=category,
        verdict=verdict,
        # Store only the action string; the column is VARCHAR
        recommendation=recommendation.action,
        # Record every component that contributed, for traceability
        model_version=(
            "rules-v1+url-v1+ml-tfidf-lr-v1"
            if ml_strong
            else "rules-v1+url-v1"
        ),
    )

    db.add(analysis_result)
    # Flush so analysis_result.id is generated before creating findings
    await db.flush()

    for match in rule_matches:
        db.add(
            RiskFinding(
                analysis_id=analysis_result.id,
                finding_type=match.pattern_name,
                severity=match.severity,
                title=match.title,
                description=match.description,
                evidence=match.evidence,
                score_contribution=match.score_contribution,
            )
        )

    if ml_strong:
        db.add(
            RiskFinding(
                analysis_id=analysis_result.id,
                finding_type="ml_classification",
                severity="medium",
                title=f"ML model detected {ml_result.category}",
                description=(
                    "The NLP classifier identified language "
                    "patterns associated with this scam category."
                ),
                evidence=scan_content[:ML_EVIDENCE_MAX_CHARS],
                score_contribution=ml_score,
                extra_metadata={
                    "model": ML_MODEL_NAME,
                    "confidence": ml_result.confidence,
                    "category": ml_result.category,
                },
            )
        )

    for result in url_results:
        db.add(
            URLAnalysis(
                scan_id=scan_id,
                url=result.url,
                domain=result.domain,
                is_https=result.is_https,
                is_suspicious=result.is_suspicious,
                risk_score=result.risk_score,
                signals=serialize_signals(result.signals),
            )
        )

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(analysis_result)

    return ScanAnalysisOutput(
        analysis_result=analysis_result,
        risk_summary=risk_summary,
        recommendation=recommendation,
        explanations=explanations,
    )