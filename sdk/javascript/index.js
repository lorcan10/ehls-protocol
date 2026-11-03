/** Dependency-free EHLS simulator client. Works in browsers and Node 18+. */
export class EHLSError extends Error {
  constructor(message, status = 0) {
    super(message);
    this.name = 'EHLSError';
    this.status = status;
  }
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => { clearTimeout(timer); reject(signal.reason ?? new Error('Aborted')); };
    const timer = setTimeout(() => { signal.removeEventListener('abort', abort); resolve(); }, ms);
    if (signal.aborted) abort();
    else signal.addEventListener('abort', abort, { once: true });
  });
}

export class EHLSClient {
  constructor({ baseUrl = 'http://localhost:8765', token, fetchImpl = globalThis.fetch } = {}) {
    const url = new URL(baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new TypeError('baseUrl must be an HTTP(S) URL without credentials, query or fragment');
    }
    if (typeof token !== 'string' || !token) throw new TypeError('An EHLS API token is required');
    if (typeof fetchImpl !== 'function') throw new TypeError('fetch is required (Node 18+ or a modern browser)');
    this.baseUrl = url.href.replace(/\/$/, '');
    this.token = token;
    this.fetch = fetchImpl.bind(globalThis);
  }

  async request(path, { method = 'GET', body, signal } = {}) {
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(new EHLSError('EHLS request timed out')), 10000);
    try {
      const response = await this.fetch(`${this.baseUrl}${path}`, {
        method, signal: controller.signal, redirect: 'error', credentials: 'omit',
        headers: { Authorization: `Bearer ${this.token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      });
      const data = await response.json();
      if (!response.ok) {
        const detail = typeof data.detail === 'string' ? data.detail : 'EHLS API rejected the request';
        throw new EHLSError(detail, response.status);
      }
      return data;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }

  startSimulation({ segmentCount = 5, intervalMs = 250, signal } = {}) {
    return this.request('/v1/simulations', { method: 'POST',
      body: { segment_count: segmentCount, interval_ms: intervalMs }, signal });
  }

  getSession(sessionId, { signal } = {}) {
    return this.request(`/v1/sessions/${encodeURIComponent(sessionId)}`, { signal });
  }

  cancelSession(sessionId, { signal } = {}) {
    return this.request(`/v1/sessions/${encodeURIComponent(sessionId)}/cancel`, { method: 'POST', signal });
  }

  /** Poll until terminal; returns completed/cancelled/failed snapshots.
   * Aborting this wait does NOT cancel the service's simulation: call cancelSession.
   */
  async waitForSession(sessionId, { onUpdate = () => {}, intervalMs = 250,
                                   timeoutMs = 60000, signal } = {}) {
    if (!Number.isFinite(intervalMs) || intervalMs < 20 || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('intervalMs must be >= 20 and timeoutMs must be positive');
    }
    const controller = new AbortController();
    const abort = () => controller.abort(signal.reason);
    if (signal?.aborted) abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timer = setTimeout(() => controller.abort(new EHLSError('Timed out waiting for EHLS session')), timeoutMs);
    try {
      while (true) {
        if (controller.signal.aborted) throw controller.signal.reason;
        const session = await this.getSession(sessionId, { signal: controller.signal });
        await onUpdate(session);
        if (['completed', 'cancelled', 'failed'].includes(session.status)) return session;
        await sleep(intervalMs, controller.signal);
      }
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
    }
  }
}
