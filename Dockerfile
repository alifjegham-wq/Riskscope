FROM python:3.13-slim AS base
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev && useradd --system --uid 10001 scanner \
    && mkdir /data && chown scanner /data
ENV RISKSCOPE_DATABASE_PATH=/data/riskscope.db
VOLUME /data
USER scanner
EXPOSE 8000
# Hosting platforms (Render, Fly, Railway...) pass the port to listen on in $PORT. Behind such a platform's
# TLS proxy set FORWARDED_ALLOW_IPS='*' so uvicorn trusts its X-Forwarded-* headers (https scheme, client IP).
CMD ["sh", "-c", "exec /app/.venv/bin/uvicorn riskscope.web.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
