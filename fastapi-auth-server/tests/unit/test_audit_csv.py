import csv
from datetime import UTC, datetime
from io import StringIO

import pytest

from wiseacct_sso.domain.audit_csv import audit_csv_cell, write_audit_csv


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@"])
def test_formula_prefix_is_escaped(prefix: str) -> None:
    value = f"{prefix}1+1"
    assert audit_csv_cell(value) == "'" + value


def test_audit_csv_preserves_quoted_multiline_reason() -> None:
    reason = '검토, "요청"\n두 번째 줄'
    payload = write_audit_csv(
        [
            (
                datetime(2026, 11, 14, tzinfo=UTC),
                "admin_audit_logs_exported",
                "success",
                "admin-1",
                None,
                reason,
            )
        ]
    )
    header, row = list(csv.reader(StringIO(payload.decode("utf-8-sig"), newline="")))
    assert len(header) == len(row) == 6
    assert row[0] == "2026-11-14T09:00:00.000+09:00"
    assert row[-2:] == ["", reason]
