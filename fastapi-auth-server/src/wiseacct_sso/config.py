import base64
import binascii
import ipaddress
import json
import re
import unicodedata
from functools import lru_cache
from typing import Annotated, Literal, Self
from urllib.parse import quote, unquote_to_bytes, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
OAuthProvider = Literal["google", "naver", "kakao"]
_LOCAL_ORIGINS = ("http://localhost:3000", "http://127.0.0.1:3000")
_PLACEHOLDER_REFRESH_SECRETS = {
    "replace-refresh-secret",
    "synthetic-fastapi-refresh-secret-only",
}
_TEMIS_REDIRECT_URIS = (
    "https://financenow.kr/auth/callback",
    "https://temis.me/auth/callback",
    "https://ti.temis.me/auth/callback",
)
_RSA_ENCRYPTION_OID = bytes.fromhex("2a864886f70d010101")


def _duration_seconds(value: str) -> int:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    text = value.strip()
    if not text:
        raise ValueError("duration is required")
    unit = text[-1] if text[-1] in units else "s"
    amount_text = text[:-1] if text[-1] in units else text
    if not amount_text.isdecimal():
        raise ValueError("duration must be a number with optional s, m, h, or d suffix")
    return int(amount_text) * units[unit]


def _optional_string(value: object) -> object:
    return None if value == "" else value


def _absolute_http_url(value: str, label: str) -> str:
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError as error:
        raise ValueError(f"{label} entries must be valid URLs") from error
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} entries must be valid URLs")
    return value


def _canonical_redirect_uri(value: str) -> str:
    """Canonicalize configured redirects like the common WHATWG URL cases.

    Express normalizes these values with ``new URL(value).toString()`` while
    loading its client policy.  Python's URL parser intentionally implements a
    different standard, so this keeps the compatibility surface explicit and
    limited to absolute HTTP(S) redirects.
    """

    special_input = _escape_special_userinfo(_special_http_url_input(value))
    _absolute_http_url(special_input, "allowedRedirectUris")
    parsed = urlsplit(special_input)
    hostname = parsed.hostname
    if hostname is None:  # Guarded by _absolute_http_url; keeps typing precise.
        raise ValueError("allowedRedirectUris entries must be valid URLs")

    canonical_host = _canonical_hostname(hostname, "allowedRedirectUris")
    if ":" in canonical_host:
        canonical_host = f"[{canonical_host}]"

    userinfo = ""
    if parsed.username is not None:
        userinfo = quote(parsed.username, safe="%!$&'()*+,-._~")
        if parsed.password is not None:
            userinfo += ":" + quote(parsed.password, safe="%!$&'()*+,-._~")
        userinfo += "@"

    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port = parsed.port
    port_suffix = f":{port}" if port is not None and port != default_port else ""
    path = quote(_remove_url_dot_segments(parsed.path or "/"), safe="/%:@!$&'()*+,;=-._~")
    query = quote(parsed.query, safe="/%?:@!$&()*+,;=-._~\\[]|^`{}")
    fragment = quote(parsed.fragment, safe="/%?:@!$&'()*+,;=-._~\\[]|^{}")
    before_fragment, raw_fragment_marker, _ = special_input.partition("#")
    query_marker = "?" if "?" in before_fragment else ""
    fragment_marker = "#" if raw_fragment_marker else ""
    return (
        f"{parsed.scheme.lower()}://{userinfo}{canonical_host}{port_suffix}{path}"
        f"{query_marker}{query}{fragment_marker}{fragment}"
    )


def _special_http_url_input(value: str) -> str:
    """Normalize WHATWG special-scheme separators before stdlib parsing."""

    text = value.strip("\t\n\r ")
    match = re.match(r"(?i)^(https?):", text)
    if match is None:
        return text
    scheme = match.group(1).lower()
    remainder = text[match.end() :]
    separator_positions = [position for marker in "?#" if (position := remainder.find(marker)) >= 0]
    split_at = min(separator_positions, default=len(remainder))
    special_part = remainder[:split_at].replace("\\", "/")
    suffix = remainder[split_at:]
    return f"{scheme}://{special_part.lstrip('/')}{suffix}"


def _escape_special_userinfo(value: str) -> str:
    scheme_separator = value.find("://")
    if scheme_separator < 0:
        return value
    authority_start = scheme_separator + 3
    authority_end = min(
        (position for marker in "/?#" if (position := value.find(marker, authority_start)) >= 0),
        default=len(value),
    )
    authority = value[authority_start:authority_end]
    if "@" not in authority:
        return value
    userinfo, separator, host = authority.rpartition("@")
    escaped_userinfo = userinfo.replace("[", "%5B").replace("]", "%5D")
    return value[:authority_start] + escaped_userinfo + separator + host + value[authority_end:]


def _canonical_hostname(hostname: str, label: str) -> str:
    try:
        if "%" in hostname:
            if re.search(r"%(?![0-9a-fA-F]{2})", hostname):
                raise ValueError("invalid host percent escape")
            hostname = unquote_to_bytes(hostname).decode("utf-8")
        if ":" in hostname:
            return ipaddress.IPv6Address(hostname).compressed
        if re.search(r"[\x00-\x20#%/:<>?@\[\\\]^|]", hostname):
            raise ValueError("invalid hostname code point")
        ipv4 = _whatwg_ipv4(hostname)
        if ipv4 is not None:
            return str(ipaddress.IPv4Address(ipv4))
        return _whatwg_domain_to_ascii(hostname)
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"{label} entries must be valid URLs") from error


def _whatwg_domain_to_ascii(hostname: str) -> str:
    labels: list[str] = []
    mapped_hostname = (
        unicodedata.normalize("NFKC", hostname)
        .replace("\u3002", ".")
        .replace("\uff0e", ".")
        .replace("\uff61", ".")
    )
    for label in mapped_hostname.split("."):
        normalized = unicodedata.normalize("NFC", label).lower()
        if "\u200c" in normalized or "\u200d" in normalized:
            raise ValueError("invalid joiner in hostname")
        try:
            labels.append(normalized.encode("ascii").decode("ascii"))
        except UnicodeEncodeError:
            labels.append("xn--" + normalized.encode("punycode").decode("ascii"))
    return ".".join(labels)


def _whatwg_ipv4(hostname: str) -> int | None:
    parts = hostname.split(".")
    if parts[-1] == "":
        parts.pop()
    if not parts:
        return None
    last_number = _whatwg_ipv4_number(parts[-1])
    if last_number is None and re.fullmatch(r"[0-9]+", parts[-1]) is None:
        return None
    numbers = [_whatwg_ipv4_number(part) for part in parts]
    if any(number is None for number in numbers):
        raise ValueError("invalid IPv4 address")
    if len(numbers) > 4:
        raise ValueError("invalid IPv4 address")

    parsed_numbers = [number for number in numbers if number is not None]
    if any(number > 255 for number in parsed_numbers[:-1]):
        raise ValueError("invalid IPv4 address")
    last_limit = 256 ** (5 - len(parsed_numbers))
    if parsed_numbers[-1] >= last_limit:
        raise ValueError("invalid IPv4 address")

    address = parsed_numbers[-1]
    for index, number in enumerate(parsed_numbers[:-1]):
        address += number * (256 ** (3 - index))
    return address


def _whatwg_ipv4_number(value: str) -> int | None:
    if not value:
        return None
    radix = 10
    digits = value
    if value.lower().startswith("0x"):
        radix = 16
        digits = value[2:]
    elif len(value) >= 2 and value.startswith("0"):
        radix = 8
        digits = value[1:]
    if not digits:
        return 0
    valid_digits = {
        8: r"[0-7]+",
        10: r"[0-9]+",
        16: r"[0-9a-fA-F]+",
    }
    if re.fullmatch(valid_digits[radix], digits) is None:
        return None
    return int(digits, radix)


def _remove_url_dot_segments(path: str) -> str:
    """Apply WHATWG's percent-aware single- and double-dot path handling."""

    segments = path.split("/")
    result: list[str] = []
    final_index = len(segments) - 1
    for index, segment in enumerate(segments):
        normalized = segment.lower()
        if normalized in {".", "%2e"}:
            if index == final_index:
                result.append("")
            continue
        if normalized in {"..", ".%2e", "%2e.", "%2e%2e"}:
            if len(result) > 1:
                result.pop()
            if index == final_index:
                result.append("")
            continue
        result.append(segment)
    return "/".join(result) or "/"


def _origin(value: str, label: str) -> str:
    _absolute_http_url(value, label)
    parsed = urlsplit(value)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError(f"{label} entries must be valid URLs")
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port
    canonical_hostname = _canonical_hostname(hostname, label)
    host = f"[{canonical_hostname}]" if ":" in canonical_hostname else canonical_hostname
    canonical = f"{parsed.scheme}://{host}"
    if port is not None and port != default_port:
        canonical = f"{canonical}:{port}"
    if value != canonical:
        raise ValueError(f"{label} entries must include scheme, host, and optional port only")
    return canonical


def _origin_from_url(value: str) -> str:
    parsed = urlsplit(_absolute_http_url(value, "URL"))
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("URL must contain a hostname")
    default_port = 443 if parsed.scheme == "https" else 80
    canonical_hostname = _canonical_hostname(hostname, "URL")
    host = f"[{canonical_hostname}]" if ":" in canonical_hostname else canonical_hostname
    port = parsed.port
    suffix = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme}://{host}{suffix}"


def _is_local_url(value: str) -> bool:
    return urlsplit(value).hostname in {"localhost", "127.0.0.1", "::1"}


class _DerReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def finished(self) -> bool:
        return self._offset == len(self._data)

    def read(self, expected_tag: int) -> bytes:
        if self._offset >= len(self._data) or self._data[self._offset] != expected_tag:
            raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 RSA private key")
        self._offset += 1
        if self._offset >= len(self._data):
            raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 RSA private key")
        length_byte = self._data[self._offset]
        self._offset += 1
        if length_byte < 0x80:
            length = length_byte
        else:
            length_octets = length_byte & 0x7F
            if length_octets == 0 or length_octets > 4:
                raise ValueError("JWT_ACCESS_PRIVATE_KEY must use definite DER lengths")
            end = self._offset + length_octets
            if end > len(self._data):
                raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 RSA private key")
            length = int.from_bytes(self._data[self._offset : end], "big")
            self._offset = end
        end = self._offset + length
        if end > len(self._data):
            raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 RSA private key")
        value = self._data[self._offset : end]
        self._offset = end
        return value


def _integer(value: bytes) -> int:
    if not value or value[0] & 0x80:
        raise ValueError("JWT_ACCESS_PRIVATE_KEY contains an invalid RSA integer")
    return int.from_bytes(value, "big")


def _rsa_numbers_from_pkcs8(pem: str) -> tuple[int, int]:
    normalized = pem.replace("\\n", "\n")
    match = re.fullmatch(
        r"-----BEGIN PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*",
        normalized,
    )
    if match is None:
        raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a PKCS8 PEM private key")
    try:
        der = base64.b64decode("".join(match.group(1).split()), validate=True)
        outer = _DerReader(der)
        private_key_info = _DerReader(outer.read(0x30))
        if not outer.finished:
            raise ValueError("trailing data")
        _integer(private_key_info.read(0x02))
        algorithm = _DerReader(private_key_info.read(0x30))
        if algorithm.read(0x06) != _RSA_ENCRYPTION_OID:
            raise ValueError("not RSA")
        private_key = private_key_info.read(0x04)
        rsa_outer = _DerReader(private_key)
        rsa = _DerReader(rsa_outer.read(0x30))
        if not rsa_outer.finished:
            raise ValueError("trailing RSA data")
        _integer(rsa.read(0x02))
        modulus = _integer(rsa.read(0x02))
        exponent = _integer(rsa.read(0x02))
    except (ValueError, binascii.Error) as error:
        raise ValueError("JWT_ACCESS_PRIVATE_KEY must be a valid PKCS8 RSA private key") from error
    return modulus, exponent


def _jwk_integer(value: str) -> int:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("JWT_ACCESS_PUBLIC_JWK must contain valid RSA parameters") from error
    if not decoded:
        raise ValueError("JWT_ACCESS_PUBLIC_JWK must contain valid RSA parameters")
    return int.from_bytes(decoded, "big")


class AccessPublicJwk(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kty: Literal["RSA"]
    n: NonEmptyString
    e: NonEmptyString
    alg: Literal["RS256"]
    use: Literal["sig"]
    kid: NonEmptyString

    @model_validator(mode="after")
    def validate_rsa_parameters(self) -> Self:
        _jwk_integer(self.n)
        _jwk_integer(self.e)
        return self


class DefaultRole(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    service_key: NonEmptyString = Field(alias="serviceKey")
    name: NonEmptyString


class RelyingClientPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    client_id: NonEmptyString = Field(alias="clientId")
    audience: NonEmptyString
    allowed_redirect_uris: tuple[NonEmptyString, ...] = Field(
        min_length=1, alias="allowedRedirectUris"
    )
    allowed_origins: tuple[NonEmptyString, ...] = Field(min_length=1, alias="allowedOrigins")
    allow_localhost_in_production: bool | None = Field(
        default=None, alias="allowLocalhostInProduction"
    )
    default_role: DefaultRole = Field(alias="defaultRole")

    @field_validator("allowed_redirect_uris")
    @classmethod
    def validate_redirects(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_canonical_redirect_uri(value) for value in values)

    @field_validator("allowed_origins")
    @classmethod
    def validate_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_origin(value, "allowedOrigins") for value in values)


class Settings(BaseSettings):
    """Phase 1 port of the Express environment contract.

    Unknown process-environment keys are ignored for forward compatibility and
    because a service process necessarily inherits unrelated operating-system
    variables. Every SSO key known at this checkpoint is declared explicitly.
    """

    model_config = SettingsConfigDict(
        env_file=None,
        case_sensitive=True,
        extra="ignore",
        populate_by_name=True,
    )

    node_env: Literal["development", "test", "production"] = Field(
        default="development", validation_alias="NODE_ENV"
    )
    database_url: NonEmptyString = Field(validation_alias="DATABASE_URL")
    port: int = Field(default=4001, gt=0, lt=65536, validation_alias="PORT")
    jwt_access_algorithm: Literal["RS256"] = Field(validation_alias="JWT_ACCESS_ALGORITHM")
    jwt_access_private_key: NonEmptyString = Field(validation_alias="JWT_ACCESS_PRIVATE_KEY")
    jwt_access_public_jwk: AccessPublicJwk = Field(validation_alias="JWT_ACCESS_PUBLIC_JWK")
    jwt_access_key_id: NonEmptyString = Field(validation_alias="JWT_ACCESS_KEY_ID")
    jwt_refresh_secret: str = Field(min_length=16, validation_alias="JWT_REFRESH_SECRET")
    jwt_issuer: NonEmptyString = Field(validation_alias="JWT_ISSUER")
    jwt_audience: NonEmptyString = Field(validation_alias="JWT_AUDIENCE")
    access_token_expires_in: int = Field(default=900, validation_alias="ACCESS_TOKEN_EXPIRES_IN")
    refresh_token_expires_in_days: int = Field(
        default=30, gt=0, validation_alias="REFRESH_TOKEN_EXPIRES_IN_DAYS"
    )
    password_min_length: int = Field(default=8, ge=8, validation_alias="PASSWORD_MIN_LENGTH")
    company_allowed_email_domain: str = Field(
        default="", validation_alias="COMPANY_ALLOWED_EMAIL_DOMAIN"
    )
    cors_allowed_origins: Annotated[tuple[str, ...], NoDecode] = Field(
        default=(), validation_alias="CORS_ALLOWED_ORIGINS"
    )
    auth_rate_limit_window_seconds: int = Field(
        default=60, gt=0, validation_alias="AUTH_RATE_LIMIT_WINDOW_SECONDS"
    )
    auth_rate_limit_max_requests: int = Field(
        default=20, gt=0, validation_alias="AUTH_RATE_LIMIT_MAX_REQUESTS"
    )
    auth_clients: tuple[RelyingClientPolicy, ...] = Field(
        min_length=1, validation_alias="AUTH_CLIENTS_JSON"
    )
    redis_url: NonEmptyString = Field(validation_alias="REDIS_URL")
    frontend_redirect_url: NonEmptyString = Field(validation_alias="FRONTEND_REDIRECT_URL")
    oauth_enabled_providers: Annotated[tuple[OAuthProvider, ...], NoDecode] = Field(
        default=("google",), validation_alias="OAUTH_ENABLED_PROVIDERS"
    )
    google_client_id: str | None = Field(default=None, validation_alias="GOOGLE_CLIENT_ID")
    google_client_secret: str | None = Field(default=None, validation_alias="GOOGLE_CLIENT_SECRET")
    google_redirect_uri: NonEmptyString = Field(validation_alias="GOOGLE_REDIRECT_URI")
    naver_client_id: str | None = Field(default=None, validation_alias="NAVER_CLIENT_ID")
    naver_client_secret: str | None = Field(default=None, validation_alias="NAVER_CLIENT_SECRET")
    naver_redirect_uri: NonEmptyString = Field(validation_alias="NAVER_REDIRECT_URI")
    kakao_client_id: str | None = Field(default=None, validation_alias="KAKAO_CLIENT_ID")
    kakao_client_secret: str | None = Field(default=None, validation_alias="KAKAO_CLIENT_SECRET")
    kakao_redirect_uri: NonEmptyString = Field(validation_alias="KAKAO_REDIRECT_URI")
    mail_provider: Literal["dev", "smtp", "resend"] = Field(
        default="dev", validation_alias="MAIL_PROVIDER"
    )
    mail_from: NonEmptyString = Field(
        default="Auth <no-reply@example.com>", validation_alias="MAIL_FROM"
    )
    mail_reply_to: str | None = Field(default=None, validation_alias="MAIL_REPLY_TO")
    resend_api_key: str | None = Field(default=None, validation_alias="RESEND_API_KEY")
    resend_admin_key: str | None = Field(default=None, validation_alias="RESEND_ADMIN_KEY")
    smtp_host: str | None = Field(default=None, validation_alias="SMTP_HOST")
    smtp_port: int = Field(default=587, gt=0, validation_alias="SMTP_PORT")
    smtp_username: str | None = Field(default=None, validation_alias="SMTP_USERNAME")
    smtp_password: str | None = Field(default=None, validation_alias="SMTP_PASSWORD")

    @field_validator("jwt_access_private_key")
    @classmethod
    def validate_private_key(cls, value: str) -> str:
        normalized = value.replace("\\n", "\n")
        _rsa_numbers_from_pkcs8(normalized)
        return normalized

    @field_validator("jwt_access_public_jwk", "auth_clients", mode="before")
    @classmethod
    def parse_json_fields(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except json.JSONDecodeError as error:
            raise ValueError("environment value must be valid JSON") from error

    @field_validator("access_token_expires_in", mode="before")
    @classmethod
    def parse_access_token_duration(cls, value: object) -> object:
        return _duration_seconds(value) if isinstance(value, str) else value

    @field_validator("cors_allowed_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            origins = tuple(origin.strip() for origin in value.split(",") if origin.strip())
        elif isinstance(value, (tuple, list)):
            origins = tuple(value)
        else:
            return value
        return tuple(_origin(str(origin), "CORS origins") for origin in origins)

    @field_validator("oauth_enabled_providers", mode="before")
    @classmethod
    def parse_oauth_providers(cls, value: object) -> object:
        if not isinstance(value, str):
            return value
        return tuple(dict.fromkeys(entry.strip() for entry in value.split(",") if entry.strip()))

    @field_validator(
        "google_client_id",
        "google_client_secret",
        "naver_client_id",
        "naver_client_secret",
        "kakao_client_id",
        "kakao_client_secret",
        "mail_reply_to",
        "resend_api_key",
        "resend_admin_key",
        "smtp_host",
        "smtp_username",
        "smtp_password",
        mode="before",
    )
    @classmethod
    def normalize_optional_strings(cls, value: object) -> object:
        return _optional_string(value)

    @model_validator(mode="after")
    def validate_cross_field_contract(self) -> Self:
        _absolute_http_url(self.jwt_issuer, "JWT_ISSUER")
        _absolute_http_url(self.frontend_redirect_url, "FRONTEND_REDIRECT_URL")
        _absolute_http_url(self.google_redirect_uri, "GOOGLE_REDIRECT_URI")
        _absolute_http_url(self.naver_redirect_uri, "NAVER_REDIRECT_URI")
        _absolute_http_url(self.kakao_redirect_uri, "KAKAO_REDIRECT_URI")
        private_n, private_e = _rsa_numbers_from_pkcs8(self.jwt_access_private_key)
        if private_n.bit_length() < 2048:
            raise ValueError("JWT_ACCESS_PRIVATE_KEY must be at least 2048 bits")
        if self.jwt_access_public_jwk.kid != self.jwt_access_key_id:
            raise ValueError("JWT_ACCESS_KEY_ID must match JWT_ACCESS_PUBLIC_JWK kid")
        if private_n != _jwk_integer(self.jwt_access_public_jwk.n) or private_e != _jwk_integer(
            self.jwt_access_public_jwk.e
        ):
            raise ValueError("JWT_ACCESS_PRIVATE_KEY must match JWT_ACCESS_PUBLIC_JWK")

        clients = self.auth_clients
        first = clients[0]
        if (
            first.client_id != "temis"
            or first.audience != "temis"
            or first.allowed_redirect_uris != _TEMIS_REDIRECT_URIS
            or first.allowed_origins != ("https://financenow.kr",)
            or first.allow_localhost_in_production is not None
        ):
            raise ValueError("AUTH_CLIENTS_JSON first client must be the required TEMIS policy")
        if first.default_role.service_key != "temis" or first.default_role.name not in {
            "pending",
            "user",
        }:
            raise ValueError("AUTH_CLIENTS_JSON first TEMIS defaultRole is invalid")
        client_ids: set[str] = set()
        for client in clients:
            temis_user = (
                client.client_id == "temis"
                and client.default_role.service_key == "temis"
                and client.default_role.name == "user"
            )
            if client.default_role.name != "pending" and not temis_user:
                raise ValueError("AUTH_CLIENTS_JSON defaultRole must be least-privilege pending")
            if client.client_id in client_ids:
                raise ValueError(
                    f"AUTH_CLIENTS_JSON contains duplicate clientId: {client.client_id}"
                )
            client_ids.add(client.client_id)

        credentials = {
            "google": (self.google_client_id, self.google_client_secret),
            "naver": (self.naver_client_id, self.naver_client_secret),
            "kakao": (self.kakao_client_id, self.kakao_client_secret),
        }
        for provider in self.oauth_enabled_providers:
            client_id, client_secret = credentials[provider]
            if not client_id:
                raise ValueError(f"{provider.upper()}_CLIENT_ID is required when OAuth is enabled")
            if not client_secret:
                raise ValueError(
                    f"{provider.upper()}_CLIENT_SECRET is required when OAuth is enabled"
                )

        frontend_origin = _origin_from_url(self.frontend_redirect_url)
        environment_origins = () if self.node_env == "production" else _LOCAL_ORIGINS
        self.cors_allowed_origins = tuple(
            dict.fromkeys((*self.cors_allowed_origins, frontend_origin, *environment_origins))
        )

        if self.node_env != "production":
            return self
        for client in clients:
            has_localhost = any(
                _is_local_url(value)
                for value in (*client.allowed_redirect_uris, *client.allowed_origins)
            )
            if has_localhost and client.allow_localhost_in_production is not True:
                raise ValueError("AUTH_CLIENTS_JSON localhost clients are forbidden in production")
        if self.mail_provider == "dev":
            raise ValueError("MAIL_PROVIDER must not be dev in production")
        if self.jwt_refresh_secret in _PLACEHOLDER_REFRESH_SECRETS:
            raise ValueError("JWT_REFRESH_SECRET must not be a placeholder in production")
        if self.mail_provider == "smtp" and not self.smtp_host:
            raise ValueError("SMTP_HOST is required when MAIL_PROVIDER=smtp in production")
        if self.mail_provider == "resend" and not (self.resend_api_key or self.resend_admin_key):
            raise ValueError("RESEND_API_KEY or RESEND_ADMIN_KEY is required for Resend")
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be provided together")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
