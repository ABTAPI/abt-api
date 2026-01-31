
import httpx, os, time, pytest
from .conftest import HOST, TOKEN_WRITE, skip_if_env_missing

payload = {
    "case_id": "pytest-demo-001",
    "inputs": {
        "ATR": {"a": "no representation; blocked access"},
        "POC": {"b": "financial burden and emotional harm"},
        "TRI": {"c": "missing documents and secrecy"},
        "ITR": {"d": "unavailable review with bias"}
    }
}

@pytest.mark.skipif(not TOKEN_WRITE, reason="ABT_TOKEN_WRITE not set")
def test_score_and_idempotency():
    skip_if_env_missing()
    url = f"https://{HOST}/v1/score-abt"
    idem = f"pytest-{int(time.time())}"
    headers = {
        "Authorization": f"Bearer {TOKEN_WRITE}",
        "Content-Type": "application/json",
        "Idempotency-Key": idem
    }
    r1 = httpx.post(url, headers=headers, json=payload, timeout=15)
    r2 = httpx.post(url, headers=headers, json=payload, timeout=15)
    assert r1.status_code == 200 and r2.status_code == 200
    j1, j2 = r1.json(), r2.json()
    assert j1 == j2
    assert j1["total_score"] >= 0 and j1["zone"] in ("Light","Gray","Shadow")
