import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy.ext.asyncio import AsyncSession

from app.detectors.rule_detector import detect_rules
from app.models.analysis_result import AnalysisResult
from app.models.risk_finding import RiskFinding
from app.models.scan import Scan


def calculate_risk_score(
    score_contributions: list[Decimal],
) -> Decimal:
    total = sum(
        score_contributions,
        Decimal("0"),
    )

    return min(
        total,
        Decimal("100"),
    )


def determine_risk_level(
    risk_score: Decimal,
) -> str:
    if risk_score < 30:
        return "low"

    if risk_score < 60:
        return "medium"

    if risk_score < 80:
        return "high"

    return "critical"


def determine_category(
    categories: list[str],
) -> str:
    if not categories:
        return "unknown"

    counts: dict[str, int] = {}

    for category in categories:
        counts[category] = counts.get(category, 0) + 1

    return max(
        counts,
        key=counts.get,
    )


def determine_verdict(
    risk_score: Decimal,
) -> str:
    if risk_score >= 60:
        return "suspicious"

    return "likely_safe"


def build_recommendation(
    risk_score: Decimal,
) -> str:
    if risk_score >= 80:
        return (
            "Do not click links, share OTPs or passwords, "
            "or transfer money. Verify the request through "
            "an official channel."
        )

    if risk_score >= 60:
        return (
            "Proceed with caution. Do not share sensitive "
            "information or make payments until the sender "
            "has been independently verified."
        )

    if risk_score >= 30:
        return (
            "Be cautious and verify the message before "
            "taking any action."
        )

    return (
        "No major scam indicators were detected. "
        "Continue to use normal security precautions."
    )


async def analyze_scan(
    db: AsyncSession,
    scan: Scan,
) -> AnalysisResult:
    matches = await detect_rules(
        db,
        scan.content,
    )

    score_contributions = [
        match.score_contribution
        for match in matches
    ]

    risk_score = calculate_risk_score(
        score_contributions
    )

    risk_level = determine_risk_level(
        risk_score
    )

    category = determine_category(
        [match.category for match in matches]
    )

    verdict = determine_verdict(
        risk_score
    )

    recommendation = build_recommendation(
        risk_score
    )

    analysis_result = AnalysisResult(
        scan_id=scan.id,
        risk_score=risk_score,
        risk_level=risk_level,
        category=category,
        verdict=verdict,
        recommendation=recommendation,
        model_version="rules-v1",
    )

    db.add(analysis_result)

    for match in matches:
        finding = RiskFinding(
            analysis_result=analysis_result,
            finding_type=match.pattern_name,
            severity=match.severity,
            title=match.title,
            description=match.description,
            evidence=match.evidence,
            score_contribution=match.score_contribution,
        )

        db.add(finding)

    scan.status = "completed"
    scan.completed_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(analysis_result)

    return analysis_result