FROM python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579 AS builder

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

WORKDIR /app
RUN python -m pip install --no-cache-dir "uv==0.12.5"
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579

ARG SOURCE_REVISION
ARG SOURCE_INPUTS_SHA256
ARG BUILD_MATERIALS_SHA256
ARG BASE_IMAGE_DIGEST

LABEL org.opencontainers.image.revision="${SOURCE_REVISION}" \
      com.wiseacct.sso.source-inputs-sha256="${SOURCE_INPUTS_SHA256}" \
      com.wiseacct.sso.build-materials-sha256="${BUILD_MATERIALS_SHA256}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}"

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY --from=builder /app/.venv /app/.venv
COPY src ./src

RUN groupadd --system --gid 10001 fastapi-sso \
    && useradd --system --uid 10001 --gid fastapi-sso --home-dir /nonexistent fastapi-sso
USER fastapi-sso
EXPOSE 4001

CMD ["uvicorn", "wiseacct_sso.main:create_runtime_app", "--factory", "--app-dir", "src", "--host", "0.0.0.0", "--port", "4001", "--no-proxy-headers", "--no-server-header", "--no-access-log"]
