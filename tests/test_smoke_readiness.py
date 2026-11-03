"""A newly published container port can reset connections before app startup."""
import io
import json
from pathlib import Path
import runpy
from urllib.error import URLError


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
    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    monkeypatch.setattr('time.sleep', lambda _: None)
    runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/smoke_test.py'))
    assert 'HTTP smoke test passed' in capsys.readouterr().out
