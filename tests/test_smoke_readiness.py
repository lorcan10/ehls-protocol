"""A newly published container port can reset connections before app startup."""
import io
import json
from pathlib import Path
import runpy
from urllib.error import URLError
from types import SimpleNamespace


def test_smoke_readiness_retries_refused_and_reset_connections(monkeypatch, capsys):
    responses = iter([
        URLError('not ready'), ConnectionResetError('container port not ready'),
        {'adapter': 'simulator'}, {'session_id': 'test-session'},
        {'status': 'completed', 'completed_segments': 3, 'progress': 100},
    ])

    def urlopen(req, timeout):
        item = next(responses)
        if isinstance(item, Exception):
            raise item
        return io.BytesIO(json.dumps(item).encode())

    monkeypatch.setenv('EHLS_API_TOKEN', 'smoke-test-token')
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: SimpleNamespace(open=urlopen))
    monkeypatch.setattr('time.sleep', lambda _: None)
    runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/smoke_test.py'))
    assert 'HTTP smoke test passed' in capsys.readouterr().out


def test_smoke_test_rejects_unsupported_url_before_network_access(monkeypatch):
    import pytest
    monkeypatch.setenv('EHLS_API_TOKEN', 'synthetic-smoke-test-token')
    monkeypatch.setenv('EHLS_BASE_URL', 'file:///tmp/unused-audit-fixture')
    def unexpected(*args):
        raise AssertionError('Invalid URL reached the HTTP client')
    monkeypatch.setattr('urllib.request.build_opener', unexpected)
    with pytest.raises(SystemExit, match='HTTP'):
        runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/smoke_test.py'))


def test_smoke_test_refuses_redirects_with_bearer_credentials(monkeypatch):
    import pytest
    from urllib.error import HTTPError
    from urllib.request import Request
    responses = iter([{'adapter': 'simulator'}, {'session_id': 'synthetic'},
                      {'status': 'completed', 'completed_segments': 3, 'progress': 100}])
    def open_mock(req, timeout):
        return io.BytesIO(json.dumps(next(responses)).encode())
    monkeypatch.setenv('EHLS_API_TOKEN', 'synthetic-smoke-test-token')
    monkeypatch.setattr('urllib.request.build_opener', lambda *args: SimpleNamespace(open=open_mock))
    code = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/smoke_test.py'))
    handler = code['NoRedirect']()
    req = Request('http://localhost:8765/health', headers={'Authorization': 'Bearer synthetic-token'})
    with pytest.raises(HTTPError, match='Redirects are disabled'):
        handler.redirect_request(req, None, 302, 'Found', {}, 'https://untrusted.example')
