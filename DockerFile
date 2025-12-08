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

# Expose API port
EXPOSE 8000

# Run the FastAPI app with uvicorn
CMD ["uvicorn", "api_main:app", "--host", "0.0.0.0", "--port", "8000"]
