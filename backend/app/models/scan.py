import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String, Text, func, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    input_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    content: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        index=True,
    )

    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    user = relationship(
        "User",
        back_populates="scans",
    )

    analysis_result = relationship(
        "AnalysisResult",
        back_populates="scan",
        uselist=False,
        cascade="all, delete-orphan",
    )

    url_analysis = relationship(
        "URLAnalysis",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    feedback = relationship(
        "UserFeedback",
        back_populates="scan",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index(
            "ix_scans_user_created_at",
            "user_id",
            "created_at",
        ),
    )