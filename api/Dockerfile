FROM python:3.11-slim-bookworm

WORKDIR /app
RUN apt-get update \
 && apt-get upgrade -y \
 && apt-get install -y --no-install-recommends \
    ca-certificates \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
COPY api/abt_api_secure.py .

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    python-jose \
    slowapi \
    requests \
    pydantic

EXPOSE 8000
RUN useradd -m appuser
USER appuser

CMD ["uvicorn", "abt_api_secure:app", "--host", "0.0.0.0", "--port", "8000"]
