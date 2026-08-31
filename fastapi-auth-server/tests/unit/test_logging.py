from wiseacct_sso.logging import allowlist_request_metric, redact_event_dict


def test_redaction_removes_secret_like_values() -> None:
    event = redact_event_dict(
        None,
        "info",
        {"event": "request", "authorization": "Bearer secret", "password": "value"},
    )

    assert event == {
        "event": "request",
        "authorization": "[REDACTED]",
        "password": "[REDACTED]",
    }


def test_redaction_recurses_into_nested_structures() -> None:
    event = redact_event_dict(
        None,
        "info",
        {
            "context": {
                "headers": {"authorization": "Bearer secret"},
                "items": [{"password": "value"}],
            }
        },
    )

    assert event == {
        "context": {
            "headers": {"authorization": "[REDACTED]"},
            "items": [{"password": "[REDACTED]"}],
        }
    }


def test_request_metric_is_strictly_allowlisted() -> None:
    event = allowlist_request_metric(
        None,
        "info",
        {
            "metric": "sso_http_request",
            "backend": "fastapi",
            "route": "/healthz",
            "query": "token=must-not-appear",
            "user_email": "must-not-appear@example.invalid",
        },
    )

    assert event == {"metric": "sso_http_request", "backend": "fastapi", "route": "/healthz"}
