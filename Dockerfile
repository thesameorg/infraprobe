# NOTE: Pin this image by digest for reproducible builds. Run:
#   docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/astral-sh/uv:0.6-python3.12-bookworm-slim
FROM ghcr.io/astral-sh/uv:0.6-python3.12-bookworm-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

# Run as non-root user for security
RUN useradd -m -u 1000 infraprobe && chown -R infraprobe:infraprobe /app
USER infraprobe

EXPOSE 8080

CMD ["uv", "run", "uvicorn", "infraprobe.app:app", "--host", "0.0.0.0", "--port", "8080"]
