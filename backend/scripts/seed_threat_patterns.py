import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.db.session import AsyncSessionLocal  # noqa: E402
from app.services.threat_patterns import seed_threat_patterns  # noqa: E402


async def main() -> None:
    async with AsyncSessionLocal() as db:
        inserted = await seed_threat_patterns(db)

    print(f"Inserted {inserted} threat patterns.")


if __name__ == "__main__":
    asyncio.run(main())