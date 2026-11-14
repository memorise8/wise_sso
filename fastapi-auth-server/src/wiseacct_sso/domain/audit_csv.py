"""Serialize allowlisted audit fields for spreadsheet download."""

import csv
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta, timezone
from io import StringIO

_KST = timezone(timedelta(hours=9))


def audit_csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        instant = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
        return instant.astimezone(_KST).isoformat(timespec="milliseconds")
    text = str(value)
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\\t", "\\r", "\\n")):
        return "'" + text
    return text


def write_audit_csv(rows: Iterable[tuple[object, ...]]) -> bytes:
    output = StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(("시각 (KST)", "이벤트", "결과", "처리 관리자 ID", "대상 사용자 ID", "사유"))
    writer.writerows(tuple(audit_csv_cell(value) for value in row) for row in rows)
    return output.getvalue().encode("utf-8-sig")
