import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { sealNote, openNote, unlockPassword, isValidKey } from '../public/js/crypto.js';

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.now();
let app;
let base;

before(async () => {
  app = createApp({ now: () => clock, rateLimit: { windowMs: 60_000, max: 1000 } });
  await new Promise((resolve) => app.server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${app.server.address().port}`;
});

after(() => {
  app.server.close();
  app.store.close();
});

beforeEach(() => {
  clock = Date.now();
});

function post(path, body) {
  return fetch(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

async function createNote(text, { password = '', days = 7 } = {}) {
  const sealed = await sealNote(text, password);
  const res = await post('/api/notes', {
    ciphertext: sealed.ciphertext,
    expiresInDays: days,
    password: sealed.password,
  });
  assert.equal(res.status, 201);
  const { id } = await res.json();
  return { id, key: sealed.key };
}

test('crypto: seal and open round-trip, including Turkish and emoji', async () => {
  const text = 'Gizli şifre: çğıöşü İĞÜ 👻\nsatır 2';
  const sealed = await sealNote(text);
  assert.ok(isValidKey(sealed.key));
  assert.equal(sealed.password, null);
  assert.equal(await openNote(sealed.ciphertext, sealed.key), text);
});

test('crypto: wrong key fails to decrypt', async () => {
  const sealed = await sealNote('secret');
  const other = await sealNote('other');
  await assert.rejects(openNote(sealed.ciphertext, other.key));
});

test('crypto: password layer needs the password key', async () => {
  const sealed = await sealNote('secret', 'hunter2');
  await assert.rejects(openNote(sealed.ciphertext, sealed.key));
  const right = await unlockPassword('hunter2', sealed.password.salt);
  assert.equal(right.auth, sealed.password.auth);
  assert.equal(await openNote(sealed.ciphertext, sealed.key, right.encKey), 'secret');
  const wrong = await unlockPassword('wrong', sealed.password.salt);
  assert.notEqual(wrong.auth, sealed.password.auth);
});

test('crypto: isValidKey rejects truncated or garbage keys', () => {
  assert.equal(isValidKey(''), false);
  assert.equal(isValidKey('abc'), false);
  assert.equal(isValidKey('not valid!'), false);
});

test('note is readable exactly once', async () => {
  const { id, key } = await createNote('burn after reading');

  const meta = await fetch(`${base}/api/notes/${id}`);
  assert.equal(meta.status, 200);
  assert.deepEqual(
    { hasPassword: false, salt: null },
    (({ hasPassword, salt }) => ({ hasPassword, salt }))(await meta.json()),
  );

  // Checking metadata twice must not burn the note.
  assert.equal((await fetch(`${base}/api/notes/${id}`)).status, 200);

  const first = await post(`/api/notes/${id}/open`, {});
  assert.equal(first.status, 200);
  const { ciphertext } = await first.json();
  assert.equal(await openNote(ciphertext, key), 'burn after reading');

  assert.equal((await post(`/api/notes/${id}/open`, {})).status, 404);
  assert.equal((await fetch(`${base}/api/notes/${id}`)).status, 404);
});

test('server never receives plaintext or key', async () => {
  const sealed = await sealNote('top secret plaintext');
  const res = await post('/api/notes', { ciphertext: sealed.ciphertext, expiresInDays: 1 });
  const { id } = await res.json();
  const row = app.store.get(id);
  assert.ok(!row.ciphertext.includes('top secret'));
  assert.ok(!JSON.stringify(row).includes(sealed.key));
});

test('password-protected note: wrong password does not burn, right one does', async () => {
  const { id, key } = await createNote('pw note', { password: 'correct horse' });

  const meta = await (await fetch(`${base}/api/notes/${id}`)).json();
  assert.equal(meta.hasPassword, true);

  const wrong = await unlockPassword('nope', meta.salt);
  const bad = await post(`/api/notes/${id}/open`, { auth: wrong.auth });
  assert.equal(bad.status, 403);
  assert.equal((await bad.json()).attemptsLeft, 4);

  // Missing auth also counts as a wrong attempt.
  assert.equal((await post(`/api/notes/${id}/open`, {})).status, 403);

  const right = await unlockPassword('correct horse', meta.salt);
  const ok = await post(`/api/notes/${id}/open`, { auth: right.auth });
  assert.equal(ok.status, 200);
  const { ciphertext } = await ok.json();
  assert.equal(await openNote(ciphertext, key, right.encKey), 'pw note');
  assert.equal((await post(`/api/notes/${id}/open`, { auth: right.auth })).status, 404);
});

test('password-protected note is destroyed after 5 wrong attempts', async () => {
  const { id } = await createNote('locked', { password: 'pw' });
  const meta = await (await fetch(`${base}/api/notes/${id}`)).json();
  const wrong = await unlockPassword('bad', meta.salt);

  for (let left = 4; left >= 1; left--) {
    const res = await post(`/api/notes/${id}/open`, { auth: wrong.auth });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).attemptsLeft, left);
  }
  assert.equal((await post(`/api/notes/${id}/open`, { auth: wrong.auth })).status, 410);

  const right = await unlockPassword('pw', meta.salt);
  assert.equal((await post(`/api/notes/${id}/open`, { auth: right.auth })).status, 404);
});

test('expired notes are not readable and get purged', async () => {
  const a = await createNote('expires', { days: 1 });
  const b = await createNote('also expires', { days: 1 });
  const keep = await createNote('stays', { days: 3 });

  clock += DAY + 1;
  assert.equal((await fetch(`${base}/api/notes/${a.id}`)).status, 404);
  // b (and any 1-day notes left by earlier tests); a was already removed on access.
  assert.ok(app.store.purgeExpired() >= 1);
  assert.equal(app.store.stmt.get.get(b.id), undefined);
  assert.equal(app.store.purgeExpired(), 0);
  assert.equal((await fetch(`${base}/api/notes/${keep.id}`)).status, 200);
});

test('destroyed counter goes up when a note is burned', async () => {
  const before = (await (await fetch(`${base}/api/stats`)).json()).destroyed;
  const { id } = await createNote('count me');
  await post(`/api/notes/${id}/open`, {});
  const after = (await (await fetch(`${base}/api/stats`)).json()).destroyed;
  assert.equal(after, before + 1);
});

test('rejects invalid input', async () => {
  const sealed = await sealNote('x');
  const cases = [
    [{ ciphertext: 'short', expiresInDays: 7 }, 400],
    [{ ciphertext: 'has spaces and !!!'.repeat(5), expiresInDays: 7 }, 400],
    [{ ciphertext: sealed.ciphertext, expiresInDays: 0 }, 400],
    [{ ciphertext: sealed.ciphertext, expiresInDays: 31 }, 400],
    [{ ciphertext: sealed.ciphertext, expiresInDays: 2.5 }, 400],
    [{ ciphertext: sealed.ciphertext, expiresInDays: '7' }, 400],
    [{ ciphertext: sealed.ciphertext, expiresInDays: 7, password: { salt: 'x', auth: 'y' } }, 400],
    [{ ciphertext: 'A'.repeat(210_001), expiresInDays: 7 }, 413],
  ];
  for (const [body, status] of cases) {
    const res = await post('/api/notes', body);
    assert.equal(res.status, status, JSON.stringify(body).slice(0, 80));
  }

  const notJson = await fetch(`${base}/api/notes`, { method: 'POST', body: 'hello' });
  assert.equal(notJson.status, 415);

  const huge = await fetch(`${base}/api/notes`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: 'x'.repeat(300 * 1024),
  });
  assert.equal(huge.status, 413);
});

test('unknown or malformed note ids return 404', async () => {
  assert.equal((await fetch(`${base}/api/notes/doesnotexist`)).status, 404);
  assert.equal((await fetch(`${base}/api/notes/${'A'.repeat(22)}`)).status, 404);
  assert.equal((await post(`/api/notes/${'A'.repeat(22)}/open`, {})).status, 404);
});

test('wrong HTTP methods are rejected', async () => {
  assert.equal((await fetch(`${base}/api/notes`)).status, 405);
  const { id } = await createNote('method test');
  // GET on /open must never burn a note (link previews, prefetching).
  assert.equal((await fetch(`${base}/api/notes/${id}/open`)).status, 405);
  assert.equal((await fetch(`${base}/api/notes/${id}`)).status, 200);
});

test('pages are served with security headers', async () => {
  for (const path of ['/', '/about', `/n/${'A'.repeat(22)}`, '/js/crypto.js', '/css/style.css']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 200, path);
    assert.match(res.headers.get('content-security-policy'), /script-src 'self'/);
    assert.equal(res.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  }
  const note = await fetch(`${base}/n/${'A'.repeat(22)}`);
  assert.equal(note.headers.get('cache-control'), 'no-store');
});

test('static files cannot escape the public folder', async () => {
  for (const path of ['/../src/server.js', '/%2e%2e/src/server.js', '/..%2fpackage.json', '/missing.js']) {
    const res = await fetch(base + path);
    assert.equal(res.status, 404, path);
  }
});

test('rate limiter blocks bursts', async () => {
  const limited = createApp({ rateLimit: { windowMs: 60_000, max: 2 } });
  await new Promise((resolve) => limited.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${limited.server.address().port}/api/notes`;
  const sealed = await sealNote('x');
  const send = () =>
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ciphertext: sealed.ciphertext, expiresInDays: 1 }),
    });
  assert.equal((await send()).status, 201);
  assert.equal((await send()).status, 201);
  assert.equal((await send()).status, 429);
  limited.server.close();
  limited.store.close();
});
