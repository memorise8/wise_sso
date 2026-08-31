"""Development, fake, SMTP, and Resend-SMTP mail delivery adapters."""

from __future__ import annotations

import asyncio
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Literal, Protocol
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import structlog

from wiseacct_sso.config import Settings

SMTP_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True, slots=True)
class MailLinkMessage:
    kind: Literal["email-verification", "password-reset"]
    to: str
    link: str


class MailService(Protocol):
    async def send_email_verification(self, *, to: str, verification_url: str) -> None: ...

    async def send_password_reset(self, *, to: str, reset_url: str) -> None: ...


class DevMailLogger(Protocol):
    def info(self, event: str, **metadata: object) -> object: ...


@dataclass(frozen=True, slots=True)
class SmtpMailConfig:
    from_address: str
    reply_to: str | None
    host: str
    port: int
    username: str | None
    password: str | None


def _redact_link_token(message: MailLinkMessage) -> MailLinkMessage:
    parsed = urlsplit(message.link)
    if not parsed.scheme:
        raise ValueError("mail link must be an absolute URL")
    query = [
        (key, "[REDACTED]" if key == "token" else value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return MailLinkMessage(
        message.kind,
        message.to,
        urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)),
    )


class FakeMailService:
    def __init__(self) -> None:
        self.messages: list[MailLinkMessage] = []

    async def send_email_verification(self, *, to: str, verification_url: str) -> None:
        self.messages.append(MailLinkMessage("email-verification", to, verification_url))

    async def send_password_reset(self, *, to: str, reset_url: str) -> None:
        self.messages.append(MailLinkMessage("password-reset", to, reset_url))


class DevMailService:
    def __init__(self, logger: DevMailLogger | None = None) -> None:
        self._logger = logger or structlog.get_logger()

    async def send_email_verification(self, *, to: str, verification_url: str) -> None:
        message = _redact_link_token(MailLinkMessage("email-verification", to, verification_url))
        self._logger.info("dev mail captured", kind=message.kind, to=message.to, link=message.link)

    async def send_password_reset(self, *, to: str, reset_url: str) -> None:
        message = _redact_link_token(MailLinkMessage("password-reset", to, reset_url))
        self._logger.info("dev mail captured", kind=message.kind, to=message.to, link=message.link)


class SmtpMailService:
    def __init__(self, config: SmtpMailConfig) -> None:
        self._config = config

    async def send_email_verification(self, *, to: str, verification_url: str) -> None:
        await asyncio.to_thread(
            self._send,
            to,
            "Verify your email",
            f"Use this link to verify your email: {verification_url}",
            _verification_html(verification_url),
        )

    async def send_password_reset(self, *, to: str, reset_url: str) -> None:
        await asyncio.to_thread(
            self._send,
            to,
            "Reset your password",
            f"Use this link to reset your password: {reset_url}",
            _password_reset_html(reset_url),
        )

    def _send(self, to: str, subject: str, text: str, html: str) -> None:
        message = EmailMessage()
        message["From"] = self._config.from_address
        if self._config.reply_to:
            message["Reply-To"] = self._config.reply_to
        message["To"] = to
        message["Subject"] = subject
        message.set_content(text)
        message.add_alternative(html, subtype="html")

        context = ssl.create_default_context()
        if self._config.port == 465:
            smtp: smtplib.SMTP = smtplib.SMTP_SSL(
                self._config.host,
                self._config.port,
                timeout=SMTP_TIMEOUT_SECONDS,
                context=context,
            )
        else:
            smtp = smtplib.SMTP(self._config.host, self._config.port, timeout=SMTP_TIMEOUT_SECONDS)
        with smtp:
            if self._config.port != 465:
                smtp.ehlo()
                if not smtp.has_extn("starttls"):
                    raise smtplib.SMTPNotSupportedError(
                        "STARTTLS is required for non-465 SMTP connections"
                    )
                smtp.starttls(context=context)
                smtp.ehlo()
            if self._config.username and self._config.password:
                smtp.login(self._config.username, self._config.password)
            smtp.send_message(message)


def _verification_html(url: str) -> str:
    return (
        "\n<p>아래 버튼을 눌러 이메일 인증을 완료해 주세요.</p>\n"
        f'<p><a href="{url}">이메일 인증하기</a></p>\n'
        "<p>버튼이 동작하지 않으면 아래 링크를 브라우저에 붙여넣어 주세요.</p>\n"
        f"<p>{url}</p>"
    )


def _password_reset_html(url: str) -> str:
    return (
        "\n<p>아래 버튼을 눌러 새 비밀번호를 설정해 주세요.</p>\n"
        f'<p><a href="{url}">비밀번호 재설정하기</a></p>\n'
        "<p>버튼이 동작하지 않으면 아래 링크를 브라우저에 붙여넣어 주세요.</p>\n"
        f"<p>{url}</p>"
    )


def smtp_mail_config(settings: Settings) -> SmtpMailConfig:
    if not settings.smtp_host:
        raise ValueError("SMTP_HOST is required when MAIL_PROVIDER=smtp")
    return SmtpMailConfig(
        settings.mail_from,
        settings.mail_reply_to,
        settings.smtp_host,
        settings.smtp_port,
        settings.smtp_username,
        settings.smtp_password,
    )


def resend_mail_config(settings: Settings) -> SmtpMailConfig:
    api_key = settings.resend_api_key or settings.resend_admin_key
    if not api_key:
        raise ValueError("RESEND_API_KEY or RESEND_ADMIN_KEY is required when MAIL_PROVIDER=resend")
    return SmtpMailConfig(
        settings.mail_from,
        settings.mail_reply_to,
        "smtp.resend.com",
        465,
        "resend",
        api_key,
    )


def create_mail_service(settings: Settings, *, logger: DevMailLogger | None = None) -> MailService:
    if settings.mail_provider == "dev":
        return DevMailService(logger)
    if settings.mail_provider == "smtp":
        return SmtpMailService(smtp_mail_config(settings))
    return SmtpMailService(resend_mail_config(settings))
