from typing import Literal

from pydantic import BaseModel

Status = Literal["ok", "unavailable"]


class HealthResponse(BaseModel):
    status: Literal["ok"]


class ReadinessResponse(BaseModel):
    status: Status
    database: Status
