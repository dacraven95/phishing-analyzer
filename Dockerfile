# -----------------------------
# Build & install app
# -----------------------------
FROM python:3.12-slim AS app

# Prevent Python from writing .pyc files and buffering stdout.
# Install Playwright browsers to a shared, read-only-at-runtime location.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Preserve the existing runtime libraries used by Chromium/Playwright.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libasound2 \
    libx11-6 \
    libxext6 \
    libxcb1 \
    libxshmfence1 \
    fonts-liberation \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy only what is needed to run the API:
# - pyproject.toml for dependencies (including fastmcp)
# - your package code (including mcp_server.py and the HTML renderer)
# - the FastAPI entrypoint (api_main.py)
COPY pyproject.toml ./
COPY phish_analyzer ./phish_analyzer
COPY api_main.py ./api_main.py

# Install app and runtime dependencies as root during the image build.
RUN pip install --no-cache-dir .

# Install Chromium and its OS dependencies at build time, never at runtime.
RUN python -m playwright install --with-deps chromium

# Chromium sandboxing requires a non-root runtime user. The bind-mounted
# SQLite/config directory must be writable by UID/GID 10001 on the host.
RUN groupadd --gid 10001 analyzer \
    && useradd --uid 10001 --gid 10001 --create-home \
       --home-dir /home/analyzer --shell /usr/sbin/nologin analyzer \
    && chown -R analyzer:analyzer /app /home/analyzer

ENV HOME=/home/analyzer
USER 10001:10001

EXPOSE 8000

CMD ["uvicorn", "api_main:app", "--host", "0.0.0.0", "--port", "8000"]
