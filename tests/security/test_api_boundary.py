"""Reject hostile session traffic before reading or parsing its JSON body."""
import asyncio
import pytest
pytest.importorskip('fastapi')
pytest.importorskip('httpx')
from fastapi.testclient import TestClient
from ehls.api import create_app
from ehls.security import SessionBoundaryMiddleware, MAX_SESSION_BODY_BYTES

TOKEN = 'boundary-test-token-at-least-24-characters'


def test_authentication_runs_before_json_parsing():
    with TestClient(create_app(api_token=TOKEN, memory_lock=False)) as client:
        result = client.post('/v1/simulations', content=b'{invalid-json',
                             headers={'Content-Type': 'application/json'})
        assert result.status_code == 401
        assert result.headers['cache-control'] == 'no-store'
        result = client.post('/v1/simulations', content=b'x' * (MAX_SESSION_BODY_BYTES + 1),
                             headers={'Authorization': 'Bearer ' + TOKEN})
        assert result.status_code == 413
        assert not client.app.state.manager._sessions


def test_unauthenticated_requests_do_not_read_body():
    async def run():
        async def unexpected(*args):
            raise AssertionError('Unauthenticated request was processed')
        sent = []
        async def send(message): sent.append(message)
        boundary = SessionBoundaryMiddleware(unexpected, api_token=TOKEN)
        scope = {'type': 'http', 'method': 'POST', 'path': '/v1/simulations', 'headers': []}
        await boundary(scope, unexpected, send)
        assert sent[0]['status'] == 401
    asyncio.run(run())


def test_chunked_body_cannot_bypass_size_limit():
    async def run():
        async def unexpected(*args): raise AssertionError('Oversized body reached app')
        chunks = iter([{'type': 'http.request', 'body': b'x' * 3000, 'more_body': True},
                       {'type': 'http.request', 'body': b'y' * 3000, 'more_body': True}])
        async def receive(): return next(chunks)
        sent = []
        async def send(message): sent.append(message)
        boundary = SessionBoundaryMiddleware(unexpected, api_token=TOKEN)
        scope = {'type': 'http', 'method': 'POST', 'path': '/v1/simulations',
                 'headers': [(b'authorization', ('Bearer ' + TOKEN).encode())]}
        await boundary(scope, receive, send)
        assert sent[0]['status'] == 413
    asyncio.run(run())


def test_body_read_deadline(monkeypatch):
    monkeypatch.setattr('ehls.security.SESSION_BODY_TIMEOUT_SECONDS', .01)
    async def run():
        async def unexpected(*args): raise AssertionError('Slow body reached app')
        async def receive():
            await asyncio.Event().wait()
        sent = []
        async def send(message): sent.append(message)
        boundary = SessionBoundaryMiddleware(unexpected, api_token=TOKEN)
        scope = {'type': 'http', 'method': 'POST', 'path': '/v1/simulations',
                 'headers': [(b'authorization', ('Bearer ' + TOKEN).encode())]}
        await boundary(scope, receive, send)
        assert sent[0]['status'] == 408
    asyncio.run(run())


@pytest.mark.parametrize('value', [' ' * 32, 'x' * 24 + '\n', 'x' * 24 + '\x00'])
def test_tokens_cannot_contain_whitespace_or_control_characters(value):
    with pytest.raises(ValueError):
        create_app(api_token=value)
