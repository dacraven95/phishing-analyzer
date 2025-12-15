# -----------------------------
# Stage 1: Build & install app
# -----------------------------
FROM python:3.12-slim AS app

# Prevent Python from writing .pyc files and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps (you probably don't need more than this)
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
# - pyproject.toml for dependencies
# - your package code
# - the FastAPI entrypoint (api_main.py)
COPY pyproject.toml ./
COPY phish_analyzer ./phish_analyzer
COPY api_main.py ./api_main.py

# Install the app and its runtime dependencies
# (FastAPI, uvicorn, dnspython, python-multipart, etc. from pyproject.toml)
RUN pip install --no-cache-dir .
RUN python -m playwright install chromium

# Expose API port
EXPOSE 8000

# Run the FastAPI app with uvicorn
CMD ["uvicorn", "api_main:app", "--host", "0.0.0.0", "--port", "8000"]
