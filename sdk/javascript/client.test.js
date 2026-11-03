import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EHLSClient, EHLSError } from './index.js';

function mockClient(responses, requests = []) {
  return new EHLSClient({ token: 'test-token', fetchImpl: async (url, options) => {
    requests.push({ url, options });
    const item = responses.shift();
    return new Response(JSON.stringify(item.body), { status: item.status ?? 200 });
  }});
}

test('start maps parameters and sends authorization without credentials or redirects', async () => {
  const requests = [];
  const client = mockClient([{ status: 202, body: { session_id: 's1' } }], requests);
  assert.equal((await client.startSimulation({ segmentCount: 3, intervalMs: 10 })).session_id, 's1');
  assert.equal(requests[0].url, 'http://localhost:8765/v1/simulations');
  assert.equal(requests[0].options.headers.Authorization, 'Bearer test-token');
  assert.deepEqual(JSON.parse(requests[0].options.body), { segment_count: 3, interval_ms: 10 });
  assert.equal(requests[0].options.credentials, 'omit');
  assert.equal(requests[0].options.redirect, 'error');
});

test('polling delivers progress and returns the terminal snapshot', async () => {
  const client = mockClient([{ body: { status: 'streaming', progress: 50 } },
                             { body: { status: 'completed', progress: 100 } }]);
  const progress = [];
  const result = await client.waitForSession('s1', { intervalMs: 20, onUpdate: s => progress.push(s.progress) });
  assert.deepEqual(progress, [50, 100]);
  assert.equal(result.status, 'completed');
});

test('failed sessions are returned so applications can display error details', async () => {
  const client = mockClient([{ body: { status: 'failed', error: 'memory_lock_failed' } }]);
  assert.equal((await client.waitForSession('s1')).error, 'memory_lock_failed');
});

test('API errors preserve HTTP status', async () => {
  const client = mockClient([{ status: 401, body: { detail: 'Unauthorized' } }]);
  await assert.rejects(client.getSession('s1'), e => e instanceof EHLSError && e.status === 401);
});

test('cancellation encodes session ID and uses POST', async () => {
  const requests = [];
  const client = mockClient([{ body: { status: 'cancelled' } }], requests);
  await client.cancelSession('a/b');
  assert.equal(requests[0].url, 'http://localhost:8765/v1/sessions/a%2Fb/cancel');
  assert.equal(requests[0].options.method, 'POST');
});

test('abort stops polling without cancelling the remote session', async () => {
  const requests = [];
  const controller = new AbortController();
  const client = mockClient([{ body: { status: 'streaming' } }], requests);
  await assert.rejects(client.waitForSession('s1', { signal: controller.signal,
    onUpdate: () => controller.abort(new Error('Stopped')) }), /Stopped/);
  assert.equal(requests.length, 1);
});

test('polling has an overall deadline', async () => {
  const client = mockClient([{ body: { status: 'streaming' } }]);
  await assert.rejects(client.waitForSession('s1', { timeoutMs: 10, intervalMs: 1000 }), /Timed out/);
});

test('credentials and non-HTTP base URLs are rejected', () => {
  for (const baseUrl of ['file:///tmp/test', 'https://user:password@example.com', 'https://example.com/?token=x']) {
    assert.throws(() => new EHLSClient({ baseUrl, token: 'test' }), TypeError);
  }
  assert.throws(() => new EHLSClient(), TypeError);
});

test('fetch is bound to the browser global rather than the client instance', async () => {
  const client = new EHLSClient({ token: 'test', fetchImpl: function () {
    assert.equal(this, globalThis);
    return Promise.resolve(new Response(JSON.stringify({ status: 'completed' })));
  }});
  assert.equal((await client.getSession('s1')).status, 'completed');
});
