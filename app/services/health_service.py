import logging

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


async def database_is_ready(session: AsyncSession) -> bool:
    try:
        await session.execute(text("SELECT 1"))
    except SQLAlchemyError, OSError:
        # Details stay server-side (and pass through log redaction); callers get a boolean.
        logger.warning("database readiness check failed", exc_info=True)
        return False
    return True
