# EHLS JavaScript client

A dependency-free client for the local EHLS simulator API. Requires modern browser `fetch` or Node 18+. MIT licensed.

Install this directory from your application with `npm install ../ehls-protocol/sdk/javascript`, adjusting the path to your checkout. This package has not been published on npm.

```js
import { EHLSClient } from 'ehls-protocol-client';
const client = new EHLSClient({ baseUrl: 'http://localhost:8765', token });
const session = await client.startSimulation({ segmentCount: 5 });
const result = await client.waitForSession(session.session_id, {
  onUpdate: state => console.log(state.progress),
});
if (result.status === 'failed') console.error(result.error);
```

Methods: `startSimulation({segmentCount, intervalMs, signal})`, `getSession(id, {signal})`, `cancelSession(id, {signal})`, `waitForSession(id, {onUpdate, intervalMs, timeoutMs, signal})`.

Session snapshots use the API's snake_case field names. `progress` is a percentage from 0 to 100. Waiting returns `completed`, `cancelled`, or `failed` snapshots; check the status. Network/API errors throw. Aborting or timing out a wait does not cancel the service's session; call `cancelSession` explicitly.

Supply the API token at runtime in local development. A hosted app should keep the shared service token on an authenticated backend proxy, not in a public bundle.

See the repository's [integration guide](https://github.com/lorcan10/ehls-protocol/blob/main/docs/INTEGRATION.md). The browser-served copy and this package's module are kept byte-identical by a test.
