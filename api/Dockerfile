FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install only runtime OS deps, then clean apt metadata
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy app module into image
COPY api/abt_api_secure.py /app/abt_api_secure.py

# Upgrade packaging tooling (often fixes pip/wheel CVEs)
RUN python -m pip install --upgrade pip setuptools wheel

# Install runtime Python deps
RUN python -m pip install \
    fastapi \
    "uvicorn[standard]" \
    python-jose \
    slowapi \
    requests \
    pydantic \
    sqlalchemy

# Run as non-root
RUN useradd -m -u 10001 appuser
USER appuser

EXPOSE 8000

CMD ["uvicorn", "abt_api_secure:app", "--host", "0.0.0.0", "--port", "8000"]
