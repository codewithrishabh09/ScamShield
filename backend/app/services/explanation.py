from dataclasses import dataclass
from decimal import Decimal


@dataclass
class Explanation:
    finding_type: str
    title: str
    description: str
    evidence: str | None
    severity: str
    score_contribution: Decimal


def build_explanations(
    findings,
) -> list[Explanation]:
    explanations: list[Explanation] = []

    for finding in findings:
        explanations.append(
            Explanation(
                finding_type=finding.finding_type,
                title=finding.title,
                description=finding.description,
                evidence=finding.evidence,
                severity=finding.severity,
                score_contribution=(
                    finding.score_contribution
                ),
            )
        )

    return explanations


def build_risk_summary(
    risk_score: Decimal,
    risk_level: str,
    category: str,
    explanations: list[Explanation],
) -> str:
    if not explanations:
        return (
            f"The message appears low risk with a "
            f"score of {risk_score}/100. No major "
            f"scam indicators were detected."
        )

    top_findings = explanations[:3]

    reasons = ", ".join(
        explanation.title.lower()
        for explanation in top_findings
    )

    return (
        f"This scan was classified as {risk_level} risk "
        f"with a score of {risk_score}/100. "
        f"The main indicators detected were: {reasons}."
    )