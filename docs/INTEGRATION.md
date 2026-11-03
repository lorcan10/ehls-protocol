# Frontend integration guide

## Architecture

Run the EHLS simulator service beside your application. Your frontend calls its REST API through the JavaScript client or normal HTTP requests. The Python service handles encryption, key derivation, message verification and buffer cleanup. Your frontend handles buttons, progress and application-specific UI.

```text
Local React / Vue / HTML frontend
             │  bearer-authenticated HTTP
             ▼
       EHLS integration API
             │
       In-process simulator
       sender → receiver → simulated execution → buffer wipe → ACK
```

This release does not send protocol traffic to another machine. Its sender and receiver serialize and verify real protocol messages within one service process. Synthetic instructions are generated a segment at a time, with at most four active simulations. No instruction file is created by the simulator. This does not establish that the OS cannot persist memory through swap, dumps or other mechanisms.

## Python installation

See the [README](../README.md#start-in-a-few-minutes) for platform-specific commands. Once installed, `ehls serve` starts the service on `127.0.0.1:8765`. There is no separate database, Node build, slicer or printer prerequisite.

If `ehls` is not on your shell's path, run your environment's Python executable with `-m ehls.cli serve`. Use `--port 8766` if the default port is busy.

Without `EHLS_API_TOKEN`, startup generates a temporary token and prints it once. Copy it into the browser example or API documentation's **Authorize** control. Restarting generates a new token. To retain the same token, set `EHLS_API_TOKEN` in the launching process's environment.

For a development simulation where the OS refuses memory locking:

```sh
ehls serve --no-memory-lock
```

This is an explicit unlocked mode. It does not demonstrate locked-memory enforcement.

## Docker alternative

Clone this repository and change into it. Docker with Compose is required. Create a local `.env` containing a random token; this command refuses to overwrite an existing file:

```sh
python -c "import secrets; open('.env', 'x').write('EHLS_API_TOKEN=' + secrets.token_urlsafe(32) + '\n')"
docker compose up --build
```

On systems that use `python3` or `py` instead, use that executable for the first command. Read your local `.env` to obtain the token, then open `http://localhost:8765`. The file is gitignored. `.env.example` documents the other variables.

Compose binds the host port to loopback, runs as a non-root container user and requests an 8 MiB memory-lock limit. If locking is unavailable, either configure the host appropriately or explicitly add `EHLS_MEMORY_LOCK=0` to `.env` and recreate the container for an unlocked simulation. Stop with `docker compose down`.

The Python CLI does not automatically read `.env`; Compose uses it for substitution. Set environment variables explicitly when launching Python directly.

## JavaScript client

From your frontend directory, install the local package:

```sh
npm install ../ehls-protocol/sdk/javascript
```

Adjust the relative path to your checkout. The client has no runtime dependencies and requires modern browser `fetch` or Node 18+. It is included in this repository, not published on npm. A served browser module is also available at `/sdk/client.js`.

```js
import { EHLSClient } from 'ehls-protocol-client';

const ehls = new EHLSClient({
  baseUrl: 'http://localhost:8765',
  token, // runtime value; do not commit a service token into your app
});

const session = await ehls.startSimulation({
  segmentCount: 10,
  intervalMs: 300,
});

const finalSession = await ehls.waitForSession(session.session_id, {
  intervalMs: 250,     // progress polling interval
  timeoutMs: 60000,   // deadline for this wait, not the server simulation
  onUpdate: current => renderProgress(current.progress, current.status),
});

if (finalSession.status === 'failed') showError(finalSession.error);
```

In React, update component state in `onUpdate`; in Vue, assign to a ref. The client doesn't require either framework.

To stop the actual session:

```js
await ehls.cancelSession(session.session_id);
```

Cancellation is a request. Poll until the service reports `cancelled` after buffer cleanup. Cancelling an already terminal session leaves its final state unchanged.

`waitForSession()` accepts an `AbortSignal`. Aborting the wait, closing a tab, or hitting its timeout **does not cancel the server simulation**; use `cancelSession()` separately when that is intended. The method returns terminal snapshots for `completed`, `cancelled` and `failed`. HTTP, timeout and network errors throw. HTTP errors have an `EHLSError.status`.

The client has a 10-second per-request timeout. A simulation can take up to approximately 500 seconds at the maximum count and delay; increase `timeoutMs` when deliberately running long simulations.

## Plain HTML without npm

This can run on the service's origin, or on an explicitly allowed local frontend origin. Supply a runtime token from your own input element:

```html
<input id="token" type="password" placeholder="Local API token">
<button id="run">Run simulation</button>
<output id="status"></output>
<script type="module">
  import { EHLSClient } from 'http://localhost:8765/sdk/client.js';
  document.querySelector('#run').onclick = async () => {
    const output = document.querySelector('#status');
    try {
      const ehls = new EHLSClient({ token: document.querySelector('#token').value });
      const session = await ehls.startSimulation();
      await ehls.waitForSession(session.session_id, {
        onUpdate: s => { output.textContent = `${s.status}: ${s.progress}%`; },
      });
    } catch (error) { output.textContent = error.message; }
  };
</script>
```

Serve your HTML through a local development server; a `file://` page has an origin that is not allowed by default. The included example at the service root already supplies controls, progress and cancellation.

## REST API

All session endpoints require `Authorization: Bearer <token>`. `/health`, the browser example, the SDK module, `/docs`, and `/openapi.json` are public within the local service.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/health` | Version, simulator mode and memory-lock configuration |
| POST | `/v1/simulations` | Start a simulation; returns HTTP 202 and a session snapshot |
| GET | `/v1/sessions/{id}` | Read progress and terminal state |
| POST | `/v1/sessions/{id}/cancel` | Request cancellation and cleanup |

Example request body:

```json
{"segment_count": 5, "interval_ms": 250}
```

`segment_count` is 1–100 and `interval_ms` is 10–5000. These are synthetic instruction segments and the execution delay for each segment. This API does not accept arbitrary G-code, geometry files or printer addresses.

A snapshot has `session_id`, `adapter`, `status`, `total_segments`, `completed_segments`, `progress` (0–100), `memory_lock_requested`, `created_at`, `updated_at`, `last_event`, and nullable `error`. Status is `queued`, `streaming`, `completed`, `cancelled`, or `failed`. Timestamps use Unix seconds. `completed_segments` increments after simulated execution, working-buffer release and signed acknowledgement verification.

Session requests are authenticated before their bodies are read. Bodies are limited to 4 KiB and must arrive within 10 seconds. Error responses include 401 for a missing/invalid token, 404 for unknown/expired sessions, 408 for a body-read timeout, 413 for an oversized body, 422 for invalid input, and 429 when active capacity is exhausted. Locking failure appears in the asynchronous snapshot as `status: failed` and `error: memory_lock_failed`. Do not treat HTTP 202 as successful execution.

Session snapshots contain no protocol keys, plaintext instructions or ciphertext. They are retained in memory for up to one hour after completion. The service keeps at most 100 records; older terminal records can be evicted earlier at capacity. A service restart loses all state. There is no reconnect/resume guarantee.

The generated OpenAPI schema at `/openapi.json` supports client generation for other languages. Session routes are versioned with `/v1`.

## Configuration

| Setting | Default | Purpose |
| --- | --- | --- |
| `EHLS_API_TOKEN` | Generated at startup | At least 24 printable ASCII characters without spaces; local service access |
| `EHLS_ALLOWED_ORIGINS` | Localhost/127.0.0.1 on ports 5173 and 3000 | Comma-separated browser origins |
| `EHLS_MEMORY_LOCK` | `1` | Set `0` only for an explicitly unlocked development simulation |
| `--host` | `127.0.0.1` | Listening address; container binds internally to `0.0.0.0` |
| `--port` | `8765` | Listening port |
| `--no-memory-lock` | Off | Explicit unlocked development mode |

CORS authorizes browser origins, not users. The service still requires its bearer token for every session request. One shared token permits access to all sessions in this process. This is a developer integration boundary, not a multi-user authorization system.

## Hosted applications

For local development, a browser can call the loopback service directly. A hosted frontend should call **its own authenticated backend**, which verifies the user, maps their authorized sessions, and forwards requests to the appropriate EHLS service. Keep the EHLS service token on that backend.

Use an authenticated HTTPS transport and an explicit routing model when moving beyond a local machine. A cloud backend cannot reach a user's `localhost`; that deployment needs an enrolled gateway connection or other intentionally configured network path. Hosted HTTPS pages calling local HTTP may also be blocked by browser mixed-content or local-network policies.

Do not embed a shared service token in a shipped JavaScript bundle. The bundled demo keeps a pasted token only in page memory. A browser token is visible to that browser's user and scripts, and is not a replacement for server-side authorization.

Run the simulator with **one worker**. Multiple independent workers do not share in-memory session records, so a poll could reach a different process and return 404.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `ehls` not found | Use the virtual environment's executable or `python -m ehls.cli serve` |
| `401` | Copy the current startup token; a generated token changes on restart |
| Browser CORS error | Set the exact frontend origin in `EHLS_ALLOWED_ORIGINS`, then restart |
| Session `memory_lock_failed` | Check OS/container lock limits; use explicit unlocked mode for development |
| `404` for a previous session | It may have expired, been evicted, or belonged to a previous service process |
| Wait timed out | Query/cancel the session; the wait deadline does not stop processing |
| `429` | At most four simulations can run at once; finish or cancel one |

## Next printer adapter

The next milestone is an optional **K1C/Moonraker execution adapter** while retaining the frontend's session/progress concept. This release deliberately exposes `/v1/simulations`, so a future physical job API can require its own explicit inputs and authorization.

The adapter must supply:

1. Printer enrollment and live identity collection in place of synthetic profiles.
2. Authenticated session establishment between separate endpoints.
3. Bounded instruction delivery through Moonraker and correlated execution feedback from telemetry.
4. Working-buffer cleanup before an acknowledgement is counted as complete.
5. Cancellation/halt semantics for already queued physical commands.
6. Reconciliation of uncertain execution before retries or recovery.

A Python adapter interface alone would not prove these properties. Hardware-backed tests and non-persistence evidence are required before describing a real print as verified. The simulator's `cancelled` state is not a physical emergency-stop guarantee.
