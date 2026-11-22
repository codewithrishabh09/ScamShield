import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.dependencies import get_current_user, get_db
from app.models.user import User
from app.schemas.scan import (
    ALLOWED_INPUT_TYPES,
    ScanCreate,
    ScanDetailResponse,
    ScanListResponse,
)
from app.services.analysis import analyze_scan
from app.services.scan import (
    create_scan,
    get_user_scan,
    get_user_scans,
)


router = APIRouter(
    prefix="/scans",
    tags=["Scans"],
)


def build_scan_detail(
    scan,
    risk_summary=None,
) -> ScanDetailResponse:
    analysis = None

    if scan.analysis_result:
        analysis = {
            "risk_score": scan.analysis_result.risk_score,
            "risk_level": scan.analysis_result.risk_level,
            "category": scan.analysis_result.category,
            "verdict": scan.analysis_result.verdict,
            "recommendation": scan.analysis_result.recommendation,
            "summary": risk_summary,
        }

    return ScanDetailResponse(
        id=scan.id,
        input_type=scan.input_type,
        content=scan.content,
        status=scan.status,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        analysis=analysis,
    )


@router.post(
    "",
    response_model=ScanDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_new_scan(
    payload: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    input_type = payload.input_type.lower().strip()

    if input_type not in ALLOWED_INPUT_TYPES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                "Unsupported input_type. "
                "Allowed values: message, url."
            ),
        )

    content = payload.content.strip()

    if not content:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Scan content cannot be empty.",
        )

    user_id = current_user.id

    scan = await create_scan(
        db,
        user_id=user_id,
        input_type=input_type,
        content=content,
    )

    scan_id = scan.id

    output = await analyze_scan(db, scan)

    scan = await get_user_scan(
        db,
        scan_id=scan_id,
        user_id=user_id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan could not be loaded after analysis.",
        )

    return build_scan_detail(
        scan,
        risk_summary=output.risk_summary,
    )


@router.get(
    "",
    response_model=ScanListResponse,
)
async def list_scans(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    risk_level: str | None = Query(default=None),
    category: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    scans, total = await get_user_scans(
        db,
        user_id=current_user.id,
        page=page,
        page_size=page_size,
        risk_level=risk_level,
        category=category,
    )

    return ScanListResponse(
        items=scans,
        page=page,
        page_size=page_size,
        total=total,
    )


@router.get(
    "/{scan_id}",
    response_model=ScanDetailResponse,
)
async def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ScanDetailResponse:
    scan = await get_user_scan(
        db,
        scan_id=scan_id,
        user_id=current_user.id,
    )

    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found.",
        )

    return build_scan_detail(scan)