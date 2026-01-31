
import httpx
from .conftest import HOST, skip_if_env_missing

def test_healthz():
    skip_if_env_missing()
    url = f"https://{HOST}/healthz"
    r = httpx.get(url, timeout=10)
    assert r.status_code == 200
    assert r.json().get("ok") is True
