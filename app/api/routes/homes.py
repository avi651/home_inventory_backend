"""Homes: owner-scoped CRUD. The owner is always the authenticated principal, never input."""

import uuid

from fastapi import APIRouter, Response, status

from app.api.dependencies import CurrentPrincipal, HomeServiceDep, rate_limited_per_user
from app.schemas.home import HomeCreate, HomeList, HomeRead, HomeUpdate

router = APIRouter(prefix="/homes", tags=["homes"])


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=HomeRead,
    dependencies=[rate_limited_per_user("homes_create_per_user")],
)
async def create_home(
    body: HomeCreate, principal: CurrentPrincipal, homes: HomeServiceDep
) -> HomeRead:
    home = await homes.create(principal.user.id, name=body.name, currency=body.currency)
    return HomeRead.from_home(home)


@router.get(
    "", response_model=HomeList, dependencies=[rate_limited_per_user("homes_read_per_user")]
)
async def list_homes(principal: CurrentPrincipal, homes: HomeServiceDep) -> HomeList:
    return HomeList(items=[HomeRead.from_home(h) for h in await homes.list(principal.user.id)])


@router.get(
    "/{home_id}",
    response_model=HomeRead,
    dependencies=[rate_limited_per_user("homes_read_per_user")],
)
async def get_home(
    home_id: uuid.UUID, principal: CurrentPrincipal, homes: HomeServiceDep
) -> HomeRead:
    return HomeRead.from_home(await homes.get(principal.user.id, home_id))


@router.patch(
    "/{home_id}",
    response_model=HomeRead,
    dependencies=[rate_limited_per_user("homes_write_per_user")],
)
async def update_home(
    home_id: uuid.UUID, body: HomeUpdate, principal: CurrentPrincipal, homes: HomeServiceDep
) -> HomeRead:
    home = await homes.update(principal.user.id, home_id, name=body.name, currency=body.currency)
    return HomeRead.from_home(home)


@router.delete(
    "/{home_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[rate_limited_per_user("homes_write_per_user")],
)
async def delete_home(
    home_id: uuid.UUID, principal: CurrentPrincipal, homes: HomeServiceDep
) -> Response:
    await homes.delete(principal.user.id, home_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
