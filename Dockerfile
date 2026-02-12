FROM ghcr.io/astral-sh/uv:0.6-python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

EXPOSE 8080

CMD ["uv", "run", "uvicorn", "infraprobe.app:app", "--host", "0.0.0.0", "--port", "8080"]
