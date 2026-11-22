from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timezone
from decimal import Decimal
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
from app.services.recommendation import build_recommendation
from app.services.url_analyzer import analyze_content_urls


@dataclass
class ScanAnalysisOutput:
    analysis_result: AnalysisResult
    risk_summary: str
    recommendation: Any
    explanations: list[Explanation]


def serialize_signals(signals) -> list[dict]:
    serialized = []

    for signal in signals:
        if is_dataclass(signal):
            data = asdict(signal)
        elif hasattr(signal, "model_dump"):
            data = signal.model_dump()
        else:
            data = dict(vars(signal))

        for key, value in data.items():
            if isinstance(value, Decimal):
                data[key] = float(value)

        serialized.append(data)

    return serialized


async def analyze_scan(
    db: AsyncSession,
    scan: Scan,
) -> ScanAnalysisOutput:
    scan_id = scan.id
    scan_content = scan.content

    rule_matches = await detect_rules(db, scan_content)

    url_results = analyze_content_urls(scan_content)

    rule_score = calculate_risk_score(
        [match.score_contribution for match in rule_matches]
    )

    url_score = calculate_risk_score(
        [result.risk_score for result in url_results]
    )

    combined_score = min(
        rule_score + url_score,
        Decimal("100"),
    )

    risk_level = determine_risk_level(combined_score)

    categories = [match.category for match in rule_matches]

    if any(result.is_suspicious for result in url_results):
        categories.append("phishing")

    category = determine_category(categories)

    verdict = determine_verdict(combined_score)

    recommendation = build_recommendation(
        combined_score,
        category,
    )

    all_findings = list(rule_matches)

    for result in url_results:
        all_findings.extend(result.signals)

    explanations = build_explanations(all_findings)

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
        recommendation=recommendation.action,  
        model_version="rules-url-v1",
    )

    db.add(analysis_result)
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