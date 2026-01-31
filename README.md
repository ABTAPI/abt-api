
# ABT API

Secure, production-ready API for ABT scoring. Ships FastAPI service, JWT (JWKS) auth, scopes, rate limiting, idempotency, audit logging, and Traefik HTTPS.

## Quick Start (Docker)

```bash
cd deploy
# Edit compose labels to set your hostnames and (optional) basic auth
docker compose -f docker-compose.abt.full.yml up -d --build
```

## Environment

Copy `api/.env.example` to your runtime env or secret manager and set:
- `ABT_OIDC_ISSUER`, `ABT_OIDC_AUDIENCE`, `ABT_JWKS_URL`
- `ABT_CORS_ORIGINS` (comma separated, e.g., https://app.yourdomain.com)
- `ABT_RATE`, `ABT_REQUEST_MAX_BYTES`, `ABT_ENABLE_DOCS=false`
- Optional: `ABT_DB_URL` (Postgres DSN) for audit persistence

## Endpoints
- `GET /healthz` (no auth)
- `GET /v1/rubric` (scope: read:rubric)
- `POST /v1/score-abt` (scope: score:write)
- `POST /v1/submit-batch` (scope: score:write)

## CI/CD
See `.github/workflows/docker-publish.yml` — pushes `abtapi/abt-api` to Docker Hub.
Secrets required in GitHub repo:
- `DOCKERHUB_USERNAME` → `abtapi`
- `DOCKERHUB_TOKEN` → Docker Hub Access Token

## Tests
```bash
pip install -r requirements-test.txt
export ABT_API_HOST="api.yourdomain.com"
export ABT_TOKEN_READ="<jwt with read:rubric>"
export ABT_TOKEN_WRITE="<jwt with score:write>"
pytest -q
```
