
import os, json, time, hashlib
from datetime import datetime
from typing import Dict, List, Optional

from fastapi import Request
from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from jose import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.responses import JSONResponse

from sqlalchemy import create_engine, Table, Column, BigInteger, Text, DateTime, MetaData
from sqlalchemy.sql import insert

API_VERSION = "v1"
RUBRIC_VERSION = "ABT-v2.5"

# ---------- Config (env-driven) ----------
ISSUER = os.getenv("ABT_OIDC_ISSUER", "https://example-issuer")
AUDIENCE = os.getenv("ABT_OIDC_AUDIENCE", "abt-api")
JWKS_URL = os.getenv("ABT_JWKS_URL", "https://example-issuer/.well-known/jwks.json")
ALLOWED_ALGOS = os.getenv("ABT_JWT_ALGOS", "RS256,ES256").split(",")
CLOCK_SKEW_SECONDS = int(os.getenv("ABT_JWT_SKEW", "60"))
ENABLE_API_KEY_FALLBACK = os.getenv("ABT_ENABLE_API_KEY", "false").lower() == "true"
EXPECTED_API_KEY = os.getenv("ABT_API_KEY", "")

# Rate limiting
DEFAULT_RATE = os.getenv("ABT_RATE", "100/minute")

# Idempotency retention seconds
IDEMPOTENCY_TTL = int(os.getenv("ABT_IDEMPOTENCY_TTL", str(60*60*24)))

# Optional DB
DB_URL = os.getenv("ABT_DB_URL", "")

# ---------- JWKS cache ----------
_JWKS_CACHE = {"keys": [], "fetched_at": 0, "ttl": 900}

def _get_jwks():
    now = time.time()
    if _JWKS_CACHE["keys"] and (now - _JWKS_CACHE["fetched_at"]) < _JWKS_CACHE["ttl"]:
        return _JWKS_CACHE["keys"]
    resp = requests.get(JWKS_URL, timeout=5)
    resp.raise_for_status()
    data = resp.json()
    _JWKS_CACHE["keys"] = data.get("keys", [])
    _JWKS_CACHE["fetched_at"] = now
    return _JWKS_CACHE["keys"]

def _find_key(kid: str) -> Optional[dict]:
    for k in _get_jwks():
        if k.get("kid") == kid:
            return k
    return None

# ---------- Security ----------
def require_auth(required_scopes: List[str]):
    async def _dep(request: Request, authorization: str = Header(None), x_api_key: Optional[str] = Header(None, alias="x-api-key")):
        # Optional API key fallback
        if ENABLE_API_KEY_FALLBACK and x_api_key and EXPECTED_API_KEY and x_api_key == EXPECTED_API_KEY:
            request.state.sub = "apikey"
            request.state.scopes = ["*"]
            return True

        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(401, "Missing bearer token")

        token = authorization.split(" ", 1)[1]
        try:
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if not kid:
                raise HTTPException(401, "Missing kid in token header")
            jwk = _find_key(kid)
            if not jwk:
                _JWKS_CACHE["keys"] = []
                jwk = _find_key(kid)
                if not jwk:
                    raise HTTPException(401, "Unknown kid")
            claims = jwt.decode(
                token,
                jwk,
                algorithms=ALLOWED_ALGOS,
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"leeway": CLOCK_SKEW_SECONDS},
            )
        except Exception as e:
            raise HTTPException(401, f"Invalid token: {str(e)}")

        scopes = (claims.get("scope") or claims.get("scopes") or "")
        scope_list = scopes.split() if isinstance(scopes, str) else list(scopes or [])
        for s in required_scopes:
            if s not in scope_list and "*" not in scope_list:
                raise HTTPException(403, f"Missing scope: {s}")

        request.state.sub = claims.get("sub", "unknown")
        request.state.scopes = scope_list
        request.state.tid = claims.get("tid", None)
        return True
    return _dep

# ---------- Rate Limiter ----------
limiter = Limiter(key_func=lambda req: req.state.sub if getattr(req.state, "sub", None) else get_remote_address(req))

# ---------- Idempotency store (in-memory MVP; can swap to Redis) ----------
IDEMPOTENCY: Dict[str, Dict] = {}

def idem_key(req: Request, body: dict) -> Optional[str]:
    key = req.headers.get("Idempotency-Key")
    if not key:
        return None
    h = hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()
    return f"idem:{key}:{h}"

# ---------- Optional DB Setup ----------
engine = None
audit_events = None
if DB_URL:
    engine = create_engine(DB_URL, future=True)
    meta = MetaData()
    audit_events = Table(
        "audit_events", meta,
        Column("id", BigInteger, primary_key=True, autoincrement=True),
        Column("ts", DateTime(timezone=True), nullable=False),
        Column("sub", Text),
        Column("scopes", Text),
        Column("endpoint", Text, nullable=False),
        Column("case_id", Text, nullable=False),
        Column("status", Text, nullable=False),
        Column("input_hash", Text, nullable=False),
        Column("response_checksum", Text, nullable=False),
    )
    with engine.begin() as conn:
        meta.create_all(conn)

def write_audit(row: dict):
    # If DB not configured, no-op
    if not engine or not audit_events:
        return
    try:
        with engine.begin() as conn:
            conn.execute(insert(audit_events).values(**row))
    except Exception as e:
        # Avoid breaking request path due to audit failure
        print(json.dumps({"audit_error": str(e)}))

# ---------- App ----------
app = FastAPI(title="ABT Risk Scoring API (Secure)", version="1.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.exception_handler(RateLimitExceeded)
def _rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})

# ---------- Models ----------
class ProngInputs(BaseModel):
    __root__: Dict[str, str]

class ABTInputs(BaseModel):
    ATR: Optional[ProngInputs] = None
    POC: Optional[ProngInputs] = None
    TRI: Optional[ProngInputs] = None
    ITR: Optional[ProngInputs] = None

class ScoreRequest(BaseModel):
    case_id: str = Field(..., min_length=1)
    inputs: ABTInputs

class ProngScores(BaseModel):
    ATR: int
    POC: int
    TRI: int
    ITR: int

class ScoreResponse(BaseModel):
    case_id: str
    scores: ProngScores
    total_score: int
    zone: str
    rubric_version: str = RUBRIC_VERSION
    diagnostic_flags: List[str] = []

# ---------- Scoring ----------
PENALTIES = {
    "no representation": 5,
    "blocked access": 5,
    "missing documents": 6,
    "bias": 5,
    "retaliation": 6,
    "delay": 4,
    "emotional harm": 4,
    "financial burden": 4,
    "secrecy": 4,
    "unavailable review": 5
}

def clamp(n, lo, hi):
    return max(lo, min(hi, n))

def score_prong(prong_inputs: Optional[ProngInputs]) -> int:
    base = 20
    if not prong_inputs:
        return base
    text_blob = " ".join((prong_inputs.__root__ or {}).values()).lower()
    score = base
    for kw, weight in PENALTIES.items():
        if kw in text_blob:
            score -= weight
    return clamp(score, 0, 20)

def determine_zone(total: int) -> str:
    if total >= 60:
        return "Light"
    if 40 <= total < 60:
        return "Gray"
    return "Shadow"

# ---------- Endpoints ----------
@app.get("/healthz")
def healthz():
    return {"ok": True, "time": datetime.utcnow().isoformat()}

@app.get(f"/{API_VERSION}/rubric")
@limiter.limit(DEFAULT_RATE)
async def get_rubric(
    request: Request,
    auth=Depends(require_auth(["read:rubric"]))
):
    return {"rubric_version": RUBRIC_VERSION, "scoring_reference": ["ATR","POC","TRI","ITR"]}

@app.post(f"/{API_VERSION}/score-abt", response_model=ScoreResponse)
@limiter.limit(DEFAULT_RATE)
async def score_abt(request: Request, payload: ScoreRequest, auth=Depends(require_auth(["score:write"]))):
    # Idempotency
    key = idem_key(request, payload.dict())
    if key:
        cached = IDEMPOTENCY.get(key)
        if cached and time.time() - cached["ts"] <= IDEMPOTENCY_TTL:
            return cached["resp"]

    scores = {
        "ATR": score_prong(payload.inputs.ATR),
        "POC": score_prong(payload.inputs.POC),
        "TRI": score_prong(payload.inputs.TRI),
        "ITR": score_prong(payload.inputs.ITR),
    }
    total = sum(scores.values())
    zone = determine_zone(total)

    resp = {
        "case_id": payload.case_id,
        "scores": scores,
        "total_score": total,
        "zone": zone,
        "rubric_version": RUBRIC_VERSION,
        "diagnostic_flags": []
    }

    if key:
        IDEMPOTENCY[key] = {"resp": resp, "ts": time.time()}

    # Audit
    audit = {
        "ts": datetime.utcnow(),
        "sub": getattr(request.state, "sub", None),
        "scopes": " ".join(getattr(request.state, "scopes", [])),
        "endpoint": "/v1/score-abt",
        "case_id": payload.case_id,
        "status": "ok",
        "input_hash": hashlib.sha256(json.dumps(payload.inputs.dict(), sort_keys=True).encode()).hexdigest(),
        "response_checksum": hashlib.md5(json.dumps(resp, sort_keys=True).encode()).hexdigest()
    }
    print(json.dumps({"audit": {**audit, "ts": audit["ts"].isoformat()}}))
    write_audit(audit)

    return resp

@app.post(f"/{API_VERSION}/submit-batch")
@limiter.limit(DEFAULT_RATE)
async def submit_batch(request: Request, items: List[ScoreRequest], auth=Depends(require_auth(["score:write"]))):
    results = []
    for it in items:
        r = await score_abt(request, it)  # reuse logic + idempotency + audit
        results.append({"case_id": it.case_id, "ok": True, "result": r})
    return results

@app.get(f"/{API_VERSION}/cases/{{case_id}}")
@limiter.limit(DEFAULT_RATE)
async def get_case(
    request: Request,
    case_id: str,
    auth=Depends(require_auth(["cases:read"]))
):
    # MVP: no persistence of cases beyond audit; extend in v1.2+
    raise HTTPException(
        status_code=404,
        detail="MVP does not persist cases; enable DB-backed cases in v1.2+"
    )

