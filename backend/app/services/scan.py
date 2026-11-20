import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis_result import AnalysisResult
from app.models.scan import Scan


async def create_scan(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    input_type: str,
    content: str,
) -> Scan:
    scan = Scan(
        user_id=user_id,
        input_type=input_type,
        content=content.strip(),
        status="pending",
    )

    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    return scan


async def get_user_scan(
    db: AsyncSession,
    *,
    scan_id: uuid.UUID,
    user_id: uuid.UUID,
) -> Scan | None:
    result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.user_id == user_id,
        )
    )

    return result.scalar_one_or_none()


async def get_user_scans(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    page: int,
    page_size: int,
    risk_level: str | None = None,
    category: str | None = None,
) -> tuple[list[Scan], int]:
    offset = (page - 1) * page_size

    filters = [
        Scan.user_id == user_id,
    ]

    if risk_level:
        filters.append(
            AnalysisResult.risk_level == risk_level
        )

    if category:
        filters.append(
            AnalysisResult.category == category
        )

    query = (
        select(Scan)
        .outerjoin(
            AnalysisResult,
            Scan.id == AnalysisResult.scan_id,
        )
        .where(*filters)
        .order_by(Scan.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )

    count_query = (
        select(func.count(Scan.id))
        .outerjoin(
            AnalysisResult,
            Scan.id == AnalysisResult.scan_id,
        )
        .where(*filters)
    )

    total_result = await db.execute(count_query)
    total = total_result.scalar_one()

    result = await db.execute(query)

    scans = list(result.scalars().unique().all())

    return scans, total