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


def _first_attr(obj, names: list[str], default=None):
    for name in names:
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


def build_explanations(
    findings,
) -> list[Explanation]:
    explanations: list[Explanation] = []

    for finding in findings:
        finding_type = _first_attr(
            finding,
            ["finding_type", "pattern_name", "signal_type"],
            default="unknown",
        )

        score = _first_attr(
            finding,
            ["score_contribution", "risk_score", "score", "weight"],
            default=Decimal("0"),
        )

        explanations.append(
            Explanation(
                finding_type=finding_type,
                title=_first_attr(
                    finding,
                    ["title"],
                    default=finding_type.replace("_", " ").title(),
                ),
                description=_first_attr(
                    finding,
                    ["description"],
                    default="",
                ),
                evidence=_first_attr(
                    finding,
                    ["evidence"],
                    default=None,
                ),
                severity=_first_attr(
                    finding,
                    ["severity"],
                    default="medium",
                ),
                score_contribution=Decimal(str(score)),
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