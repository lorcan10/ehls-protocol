"""Verify a running EHLS service through its public HTTP interface.

Set EHLS_API_TOKEN and optionally EHLS_BASE_URL. No printer commands are sent.
"""
import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

base_url = os.environ.get('EHLS_BASE_URL', 'http://127.0.0.1:8765').rstrip('/')
token = os.environ['EHLS_API_TOKEN']
parsed_url = urlsplit(base_url)
if (parsed_url.scheme not in {'http', 'https'} or not parsed_url.hostname
        or parsed_url.username or parsed_url.password or parsed_url.query or parsed_url.fragment):
    raise SystemExit('EHLS_BASE_URL must be an HTTP(S) URL without credentials, query or fragment')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward the bearer token to a redirect target.
        raise HTTPError(req.full_url, code, 'Redirects are disabled', headers, fp)


opener = build_opener(NoRedirect())


def request(path, data=None):
    body = None if data is None else json.dumps(data).encode()
    req = Request(base_url + path, data=body, headers={
        'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    with opener.open(req, timeout=5) as response:
        return json.load(response)


deadline = time.monotonic() + 30
while True:
    try:
        health = request('/health')
        break
    except (URLError, ConnectionError, TimeoutError):
        if time.monotonic() >= deadline:
            raise SystemExit('Service did not become healthy within 30 seconds')
        time.sleep(.1)
if health['adapter'] != 'simulator':
    raise SystemExit('Expected a simulator service')
created = request('/v1/simulations', {'segment_count': 3, 'interval_ms': 10})
while time.monotonic() < deadline:
    session = request('/v1/sessions/' + created['session_id'])
    if session['status'] in {'failed', 'cancelled'}:
        raise SystemExit('Simulation did not complete: ' + str(session['error']))
    if session['status'] == 'completed':
        if session['completed_segments'] != 3 or session['progress'] != 100:
            raise SystemExit('Simulation reported incomplete acknowledgement counts')
        print('HTTP smoke test passed: 3 simulated segments acknowledged')
        break
    time.sleep(.05)
else:
    raise SystemExit('Simulation timed out')
