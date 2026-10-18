import smtplib
from email.message import EmailMessage
from unittest.mock import Mock, patch

import pytest

from wiseacct_sso.config import Settings
from wiseacct_sso.infrastructure.mail import (
    SMTP_TIMEOUT_SECONDS,
    DevMailService,
    FakeMailService,
    SmtpMailService,
    create_mail_service,
    resend_mail_config,
    smtp_mail_config,
)


@pytest.mark.anyio
async def test_fake_mail_captures_exact_links() -> None:
    mail = FakeMailService()

    await mail.send_email_verification(
        to="person@example.com", verification_url="https://auth.example/verify?token=verify"
    )
    await mail.send_password_reset(
        to="person@example.com", reset_url="https://auth.example/reset?token=reset"
    )

    assert [(message.kind, message.to, message.link) for message in mail.messages] == [
        ("email-verification", "person@example.com", "https://auth.example/verify?token=verify"),
        ("password-reset", "person@example.com", "https://auth.example/reset?token=reset"),
    ]


@pytest.mark.anyio
async def test_dev_mail_redacts_only_token_query_value() -> None:
    logger = Mock()
    mail = DevMailService(logger)

    await mail.send_password_reset(
        to="person@example.com",
        reset_url="https://auth.example/reset?keep=value&token=raw-secret#fragment",
    )

    logger.info.assert_called_once_with(
        "dev mail captured",
        kind="password-reset",
        to="person@example.com",
        link="https://auth.example/reset?keep=value&token=%5BREDACTED%5D#fragment",
    )


def test_smtp_and_resend_config_mapping(synthetic_settings: Settings) -> None:
    smtp_settings = synthetic_settings.model_copy(
        update={
            "mail_provider": "smtp",
            "mail_from": "Auth <auth@example.com>",
            "mail_reply_to": "reply@example.com",
            "smtp_host": "smtp.example.com",
            "smtp_port": 2525,
            "smtp_username": "user",
            "smtp_password": "password",
        }
    )
    resend_settings = synthetic_settings.model_copy(
        update={
            "mail_provider": "resend",
            "mail_from": "TEMIS <no-reply@temis.me>",
            "resend_api_key": "re_key",
        }
    )

    smtp = smtp_mail_config(smtp_settings)
    resend = resend_mail_config(resend_settings)

    assert (smtp.host, smtp.port, smtp.username, smtp.reply_to) == (
        "smtp.example.com",
        2525,
        "user",
        "reply@example.com",
    )
    assert (resend.host, resend.port, resend.username, resend.password) == (
        "smtp.resend.com",
        465,
        "resend",
        "re_key",
    )
    assert isinstance(create_mail_service(smtp_settings), SmtpMailService)


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("kind", "subject", "text"),
    [
        ("verification", "Verify your email", "Use this link to verify your email:"),
        ("reset", "Reset your password", "Use this link to reset your password:"),
    ],
)
async def test_smtp_message_and_starttls_contract(
    synthetic_settings: Settings, kind: str, subject: str, text: str
) -> None:
    settings = synthetic_settings.model_copy(
        update={
            "mail_provider": "smtp",
            "mail_from": "Auth <auth@example.com>",
            "mail_reply_to": "reply@example.com",
            "smtp_host": "smtp.example.com",
            "smtp_port": 587,
            "smtp_username": "user",
            "smtp_password": "password",
        }
    )
    smtp = Mock()
    smtp.__enter__ = Mock(return_value=smtp)
    smtp.__exit__ = Mock(return_value=False)
    smtp.has_extn.return_value = True
    mail = SmtpMailService(smtp_mail_config(settings))
    url = "https://auth.example/action?token=secret"

    with patch("wiseacct_sso.infrastructure.mail.smtplib.SMTP", return_value=smtp) as factory:
        if kind == "verification":
            await mail.send_email_verification(to="person@example.com", verification_url=url)
        else:
            await mail.send_password_reset(to="person@example.com", reset_url=url)

    factory.assert_called_once_with("smtp.example.com", 587, timeout=SMTP_TIMEOUT_SECONDS)
    smtp.starttls.assert_called_once()
    smtp.login.assert_called_once_with("user", "password")
    message = smtp.send_message.call_args.args[0]
    assert isinstance(message, EmailMessage)
    assert message["From"] == "Auth <auth@example.com>"
    assert message["Reply-To"] == "reply@example.com"
    assert message["To"] == "person@example.com"
    assert message["Subject"] == subject
    plain_body = message.get_body(preferencelist=("plain",))
    html_body = message.get_body(preferencelist=("html",))
    assert plain_body is not None
    assert html_body is not None
    assert text in plain_body.get_content()
    assert url in html_body.get_content()


@pytest.mark.anyio
async def test_port_465_uses_implicit_tls_without_starttls(
    synthetic_settings: Settings,
) -> None:
    settings = synthetic_settings.model_copy(
        update={"mail_provider": "resend", "resend_api_key": "re_key"}
    )
    smtp = Mock()
    smtp.__enter__ = Mock(return_value=smtp)
    smtp.__exit__ = Mock(return_value=False)
    mail = SmtpMailService(resend_mail_config(settings))

    with patch("wiseacct_sso.infrastructure.mail.smtplib.SMTP_SSL", return_value=smtp) as factory:
        await mail.send_password_reset(
            to="person@example.com", reset_url="https://auth.example/reset?token=secret"
        )

    assert factory.call_args.args == ("smtp.resend.com", 465)
    assert factory.call_args.kwargs["timeout"] == SMTP_TIMEOUT_SECONDS
    smtp.starttls.assert_not_called()
    smtp.login.assert_called_once_with("resend", "re_key")


@pytest.mark.anyio
async def test_non_465_smtp_fails_before_auth_or_send_without_starttls(
    synthetic_settings: Settings,
) -> None:
    settings = synthetic_settings.model_copy(
        update={
            "mail_provider": "smtp",
            "smtp_host": "smtp-relay.example.com",
            "smtp_port": 2525,
            "smtp_username": "smtp-user",
            "smtp_password": "smtp-password",
        }
    )
    smtp = Mock()
    smtp.__enter__ = Mock(return_value=smtp)
    smtp.__exit__ = Mock(return_value=False)
    smtp.has_extn.return_value = False
    mail = SmtpMailService(smtp_mail_config(settings))

    with (
        patch("wiseacct_sso.infrastructure.mail.smtplib.SMTP", return_value=smtp),
        pytest.raises(smtplib.SMTPNotSupportedError, match="STARTTLS is required"),
    ):
        await mail.send_email_verification(
            to="person@example.com", verification_url="https://auth.example/verify?token=secret"
        )

    smtp.starttls.assert_not_called()
    smtp.login.assert_not_called()
    smtp.send_message.assert_not_called()
