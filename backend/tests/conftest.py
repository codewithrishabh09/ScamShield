import pytest_asyncio
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings


@pytest_asyncio.fixture
async def db_session():
    # Use a fresh engine per test so asyncpg connections are never
    # shared across event loops. echo is off to keep test output clean.
    engine = create_async_engine(settings.database_url)

    async with engine.connect() as connection:
        # Wrap the whole test in an outer transaction that is always
        # rolled back, so test rows never persist in the real tables.
        transaction = await connection.begin()

        session_factory = async_sessionmaker(
            bind=connection,
            class_=AsyncSession,
            expire_on_commit=False,
            # session.commit() only releases a savepoint, it does not
            # commit the outer transaction
            join_transaction_mode="create_savepoint",
        )

        async with session_factory() as session:
            yield session

        await transaction.rollback()

    await engine.dispose()