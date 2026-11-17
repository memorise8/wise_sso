"""관리자 브라우저 API의 읽기 전용 접근 범위."""

import re

_VIEWER_READ_PATHS = (
    re.compile(r"/summary"),
    re.compile(r"/users"),
    re.compile(r"/users/[^/]+"),
    re.compile(r"/users/[^/]+/sessions"),
    re.compile(r"/clients"),
    re.compile(r"/clients/[^/]+/members"),
    re.compile(r"/roles"),
    re.compile(r"/service-access"),
    re.compile(r"/audit-logs"),
)


def viewer_read_allowed(*, method: str, path: str) -> bool:
    """API 마운트 기준 상대 경로에 대해 허용한 조회만 통과시킵니다."""
    if method not in {"GET", "HEAD"}:
        return False
    return any(pattern.fullmatch(path) is not None for pattern in _VIEWER_READ_PATHS)
