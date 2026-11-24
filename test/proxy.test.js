import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';

/** Starts an app with a tiny login rate limit (2 per window) and returns a login helper. */
async function start(options) {
  const app = createApp({ authRateLimit: { windowMs: 60_000, max: 2 }, ...options });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${app.server.address().port}/api/auth/login`;
  const login = (forwardedFor) =>
    fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(forwardedFor ? { 'X-Forwarded-For': forwardedFor } : {}),
      },
      body: JSON.stringify({ email: 'a@example.com', password: 'guess-guess' }),
    }).then((r) => r.status);
  const stop = () => {
    app.server.close();
    app.store.close();
  };
  return { login, stop };
}

test('behind one proxy, each visitor gets their own rate limit', async () => {
  const { login, stop } = await start({ trustProxy: 1 });
  // Visitor A uses up their attempts...
  assert.deepEqual([await login('1.1.1.1'), await login('1.1.1.1'), await login('1.1.1.1')], [401, 401, 429]);
  // ...but visitor B is not blocked because of A.
  assert.equal(await login('2.2.2.2'), 401);
  stop();
});

test('a visitor cannot dodge the limit by faking X-Forwarded-For', async () => {
  const { login, stop } = await start({ trustProxy: 1 });
  // The proxy appends the real IP (9.9.9.9) after whatever the client sent.
  assert.equal(await login('fake-1, 9.9.9.9'), 401);
  assert.equal(await login('fake-2, 9.9.9.9'), 401);
  assert.equal(await login('fake-3, 9.9.9.9'), 429);
  stop();
});

test('without trustProxy the header is ignored', async () => {
  const { login, stop } = await start({ trustProxy: 0 });
  // Different headers, same socket: all count as one visitor.
  assert.deepEqual([await login('1.1.1.1'), await login('2.2.2.2'), await login('3.3.3.3')], [401, 401, 429]);
  stop();
});

test('a missing header falls back to the socket address', async () => {
  const { login, stop } = await start({ trustProxy: 1 });
  assert.deepEqual([await login(), await login(), await login()], [401, 401, 429]);
  stop();
});
