import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

ALLOWED_INPUT_TYPES = {"message", "url"}


class ScanCreate(BaseModel):
    input_type: str
    content: str = Field(min_length=1, max_length=10000)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    input_type: str
    content: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None


class ExplanationItem(BaseModel):
    finding_type: str
    title: str
    description: str
    evidence: str | None = None
    severity: str
    score_contribution: float


class AnalysisDetail(BaseModel):
    risk_score: float
    risk_level: str
    category: str
    verdict: str
    recommendation: str | None = None
    priority: str | None = None
    summary: str | None = None
    why: list[ExplanationItem] = []


class ScanDetailResponse(BaseModel):
    id: uuid.UUID
    input_type: str
    content: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    analysis: AnalysisDetail | None = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    page: int
    page_size: int
    total: int