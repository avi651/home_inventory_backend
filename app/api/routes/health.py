from fastapi import APIRouter, Response, status

from app.api.dependencies import DbSession
from app.schemas.health import HealthResponse, ReadinessResponse
from app.services.health_service import database_is_ready

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness probe: the process is up. Does not touch the database."""
    return HealthResponse(status="ok")


@router.get(
    "/health/ready",
    response_model=ReadinessResponse,
    responses={status.HTTP_503_SERVICE_UNAVAILABLE: {"model": ReadinessResponse}},
)
async def readiness(session: DbSession, response: Response) -> ReadinessResponse:
    """Readiness probe: dependencies (database) are reachable."""
    if await database_is_ready(session):
        return ReadinessResponse(status="ok", database="ok")
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="unavailable", database="unavailable")
