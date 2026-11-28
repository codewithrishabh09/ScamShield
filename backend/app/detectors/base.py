from dataclasses import dataclass
from decimal import Decimal


@dataclass(frozen=True)
class DetectionFinding:
    pattern_name: str
    finding_type: str
    category: str
    severity: str
    title: str
    description: str
    evidence: str
    score_contribution: Decimal