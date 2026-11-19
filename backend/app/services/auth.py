from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models.user import User


async def get_user_by_email(
    db: AsyncSession,
    email: str,
) -> User | None:
    result = await db.execute(
        select(User).where(User.email == email.lower())
    )

    return result.scalar_one_or_none()


async def register_user(
    db: AsyncSession,
    *,
    full_name: str,
    email: str,
    password: str,
) -> User:
    user = User(
        full_name=full_name.strip(),
        email=email.lower(),
        password_hash=hash_password(password),
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return user


async def authenticate_user(
    db: AsyncSession,
    *,
    email: str,
    password: str,
) -> User | None:
    user = await get_user_by_email(
        db,
        email,
    )

    if user is None:
        return None

    if not user.is_active:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    return user


def generate_access_token(user: User) -> str:
    return create_access_token(
        subject=str(user.id),
    )