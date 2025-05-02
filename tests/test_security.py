from starlette.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_unauthenticated():
    resp = client.post("/keys/")
    assert resp.status_code == 401

def test_auth_flow():
    # получаем токен
    tok = client.post("/auth/token").json()["access_token"]
    headers = {"Authorization": f"Bearer {tok}"}
    # создаём ключ
    resp = client.post("/keys/", headers=headers)
    assert resp.status_code == 200
