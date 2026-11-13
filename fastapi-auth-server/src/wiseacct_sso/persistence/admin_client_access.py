"""Read-only queries for administrator service access management."""

from typing import cast

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_ROLE_PAGE = text("""
WITH role_page AS (
    SELECT id, "serviceKey", name
    FROM "Role"
    ORDER BY "serviceKey", name, id
    LIMIT :page_size OFFSET :offset
)
SELECT jsonb_build_object(
    'items', COALESCE(
        (SELECT jsonb_agg(to_jsonb(r) ORDER BY r."serviceKey", r.name, r.id) FROM role_page r),
        '[]'::jsonb
    ),
    'total', (SELECT count(*) FROM "Role"),
    'page', CAST(:page AS bigint),
    'pageSize', CAST(:page_size AS bigint)
)
""")


async def read_role_page(
    connection: AsyncConnection, *, page: int, page_size: int
) -> dict[str, object]:
    result = await connection.execute(
        _ROLE_PAGE,
        {"page": page, "page_size": page_size, "offset": (page - 1) * page_size},
    )
    return cast(dict[str, object], result.scalar_one())
