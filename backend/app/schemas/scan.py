import uuid
from datetime import datetime
from decimal import Decimal

from pydantic import BaseModel, ConfigDict, Field


ALLOWED_INPUT_TYPES = {
    "message",
    "url",
}


class ScanCreate(BaseModel):
    input_type: str = Field(
        min_length=1,
        max_length=30,
    )

    content: str = Field(
        min_length=1,
        max_length=10000,
    )


class ScanResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
    )

    id: uuid.UUID
    input_type: str
    content: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None


class ScanListResponse(BaseModel):
    items: list[ScanResponse]
    page: int
    page_size: int
    total: int


class ScanAnalysisSummary(BaseModel):
    risk_score: Decimal
    risk_level: str
    category: str
    verdict: str
    recommendation: str
    summary: str


class ScanDetailResponse(BaseModel):
    id: uuid.UUID
    input_type: str
    content: str
    status: str
    created_at: datetime
    completed_at: datetime | None = None
    analysis: ScanAnalysisSummary | None = None