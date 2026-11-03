"""REST, token, CORS and packaged frontend contracts."""
import time
from pathlib import Path
import pytest
pytest.importorskip('fastapi')
pytest.importorskip('httpx')
from fastapi.testclient import TestClient
from ehls.api import create_app

TOKEN = 'test-token-with-at-least-24-characters'
HEADERS = {'Authorization': f'Bearer {TOKEN}'}


@pytest.fixture
def client():
    with TestClient(create_app(api_token=TOKEN, memory_lock=False)) as instance:
        yield instance


def test_auth_required_and_health_redacted(client):
    health = client.get('/health')
    assert health.status_code == 200
    assert health.json()['adapter'] == 'simulator'
    assert TOKEN not in health.text
    for headers in [{}, {'Authorization': 'Bearer wrong'}, {'Authorization': 'Basic abc'}]:
        assert client.post('/v1/simulations', json={}, headers=headers).status_code == 401
    assert client.get('/v1/sessions/unknown').status_code == 401
    assert client.post('/v1/sessions/unknown/cancel').status_code == 401
    assert client.get('/v1/sessions/unknown', headers=HEADERS).status_code == 404


def test_create_poll_and_cancel(client):
    created = client.post('/v1/simulations', json={'segment_count': 2, 'interval_ms': 10}, headers=HEADERS)
    assert created.status_code == 202
    sid = created.json()['session_id']
    for _ in range(100):
        result = client.get(f'/v1/sessions/{sid}', headers=HEADERS)
        if result.json()['status'] == 'completed': break
        time.sleep(.01)
    assert result.json()['status'] == 'completed'
    assert result.json()['completed_segments'] == 2
    assert result.json()['progress'] == 100
    assert result.headers['cache-control'] == 'no-store'
    unchanged = client.post(f'/v1/sessions/{sid}/cancel', headers=HEADERS).json()
    assert unchanged['status'] == 'completed'
    other = client.post('/v1/simulations', json={'segment_count': 100, 'interval_ms': 5000}, headers=HEADERS).json()
    client.post(f"/v1/sessions/{other['session_id']}/cancel", headers=HEADERS)
    for _ in range(100):
        cancelled = client.get(f"/v1/sessions/{other['session_id']}", headers=HEADERS).json()
        if cancelled['status'] == 'cancelled': break
        time.sleep(.01)
    assert cancelled['status'] == 'cancelled'


def test_input_limits_and_capacity(client):
    for payload in [{'segment_count': 0}, {'segment_count': 101}, {'interval_ms': 0}, {'interval_ms': 5001}, {'gcode': 'G28'}]:
        assert client.post('/v1/simulations', json=payload, headers=HEADERS).status_code == 422
    for _ in range(4):
        assert client.post('/v1/simulations', json={'interval_ms': 5000}, headers=HEADERS).status_code == 202
    assert client.post('/v1/simulations', json={}, headers=HEADERS).status_code == 429


def test_cors_restricts_browser_origins(client):
    allowed = client.options('/v1/simulations', headers={'Origin': 'http://localhost:5173',
        'Access-Control-Request-Method': 'POST', 'Access-Control-Request-Headers': 'Authorization,Content-Type'})
    assert allowed.headers['access-control-allow-origin'] == 'http://localhost:5173'
    denied = client.options('/v1/simulations', headers={'Origin': 'https://untrusted.example',
        'Access-Control-Request-Method': 'POST'})
    assert 'access-control-allow-origin' not in denied.headers


def test_browser_demo_sdk_and_openapi_are_packaged(client):
    page = client.get('/')
    assert page.status_code == 200 and 'Simulator mode' in page.text
    assert TOKEN not in page.text
    js = client.get('/sdk/client.js')
    assert js.status_code == 200 and 'class EHLSClient' in js.text
    assert 'javascript' in js.headers['content-type']
    schema = client.get('/openapi.json').json()
    assert schema['paths']['/v1/simulations']['post']['security']
    root = Path(__file__).resolve().parents[1]
    assert (root / 'ehls/static/client.js').read_bytes() == (root / 'sdk/javascript/index.js').read_bytes()


def test_empty_and_short_tokens_rejected():
    for token in ['', 'short', 'é' * 24]:
        with pytest.raises(ValueError):
            create_app(api_token=token)
