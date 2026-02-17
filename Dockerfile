# --- build stage: install deps with uv ---
FROM ghcr.io/astral-sh/uv:0.6-python3.12-bookworm-slim AS builder

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

COPY . .
RUN uv sync --frozen --no-dev

# Strip build artifacts: __pycache__, .pyc, test suites, selenium (unused wappalyzer.browser dep)
# WARNING: stripping wappalyzer/browser requires a sys.modules stub in scanners/deep/tech.py
# because wappalyzer's __init__.py unconditionally imports it. If you strip other subpackages
# that are imported at package init time, add a similar stub. See docs/check_approach.md § Debugging.
RUN find /app/.venv -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null; \
    find /app/.venv -name "*.pyc" -delete 2>/dev/null; \
    rm -rf /app/.venv/lib/python3.12/site-packages/selenium \
           /app/.venv/lib/python3.12/site-packages/wappalyzer/browser; \
    find /app/.venv/lib/python3.12/site-packages -type d \( -name "tests" -o -name "test" \) -exec rm -rf {} + 2>/dev/null; \
    true

# --- runtime stage: slim image without uv ---
FROM python:3.12-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1000 infraprobe

WORKDIR /app

# Copy the entire app (including venv) with correct ownership in a single layer
COPY --from=builder --chown=infraprobe:infraprobe /app /app

USER infraprobe

EXPOSE 8080

CMD ["/app/.venv/bin/uvicorn", "infraprobe.app:app", "--host", "0.0.0.0", "--port", "8080"]
