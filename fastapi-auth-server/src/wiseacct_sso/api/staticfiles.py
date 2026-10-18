import os
from email.utils import parsedate
from os import PathLike
from pathlib import Path

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, Response
from starlette.staticfiles import NotModifiedResponse, StaticFiles
from starlette.types import Receive, Scope, Send

ASSET_CACHE_CONTROL = "public, max-age=3600, immutable"


def _is_not_modified(response_headers: Headers, request_headers: Headers) -> bool:
    if if_none_match := request_headers.get("if-none-match"):
        candidates = [candidate.strip() for candidate in if_none_match.split(",")]
        if "*" in candidates:
            return True
        etag = response_headers["etag"]
        return etag in [candidate.removeprefix("W/") for candidate in candidates]
    try:
        if_modified_since = parsedate(request_headers["if-modified-since"])
        last_modified = parsedate(response_headers["last-modified"])
        return (
            if_modified_since is not None
            and last_modified is not None
            and if_modified_since >= last_modified
        )
    except KeyError:
        return False


def conditional_file_response(
    path: Path,
    *,
    request_headers: Headers,
    media_type: str,
    cache_control: str,
) -> Response:
    response = FileResponse(
        path,
        media_type=media_type,
        stat_result=path.stat(),
        headers={"cache-control": cache_control},
    )
    if _is_not_modified(response.headers, request_headers):
        return NotModifiedResponse(response.headers)
    return response


class ImmutableStaticFiles(StaticFiles):
    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("path", "").endswith("/"):
            raise HTTPException(status_code=404)
        await super().__call__(scope, receive, send)

    async def get_response(self, path: str, scope: Scope) -> Response:
        if path.endswith("/"):
            raise HTTPException(status_code=404)
        return await super().get_response(path, scope)

    def is_not_modified(self, response_headers: Headers, request_headers: Headers) -> bool:
        return _is_not_modified(response_headers, request_headers)

    def file_response(
        self,
        full_path: str | PathLike[str],
        stat_result: os.stat_result,
        scope: Scope,
        status_code: int = 200,
    ) -> Response:
        request_headers = Headers(scope=scope)
        response = FileResponse(
            full_path,
            status_code=status_code,
            stat_result=stat_result,
            headers={"cache-control": ASSET_CACHE_CONTROL},
        )
        if self.is_not_modified(response.headers, request_headers):
            return NotModifiedResponse(response.headers)
        return response
