
import httpx, os, pytest
from .conftest import HOST, TOKEN_READ, TOKEN_WRITE, skip_if_env_missing

def test_rubric_unauthorized():
    skip_if_env_missing()
    r = httpx.get(f"https://{HOST}/v1/rubric", timeout=10)
    assert r.status_code in (401, 403)

@pytest.mark.skipif(not TOKEN_READ, reason="ABT_TOKEN_READ not set")
def test_rubric_authorized():
    skip_if_env_missing()
    r = httpx.get(
        f"https://{HOST}/v1/rubric",
        headers={"Authorization": f"Bearer {TOKEN_READ}"},
        timeout=10,
    )
    assert r.status_code == 200
    j = r.json()
    assert "rubric_version" in j and "scoring_reference" in j
