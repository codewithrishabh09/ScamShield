from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionFinding:
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: str
    score_contribution: float