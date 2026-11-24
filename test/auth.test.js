import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/server.js';
import { sealNote, unlockPassword } from '../public/js/crypto.js';
import { hashPassword, verifyPassword, parseCookies, normalizeEmail } from '../src/auth.js';

const DAY = 24 * 60 * 60 * 1000;
let clock = Date.now();
let app;
let base;
let emailCounter = 0;

before(async () => {
  app = createApp({
    now: () => clock,
    rateLimit: { windowMs: 60_000, max: 1000 },
    authRateLimit: { windowMs: 60_000, max: 1000 },
  });
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

/** A tiny client that remembers its session cookie, like a browser. */
function client() {
  let cookie = '';
  async function request(method, path, body, headers = {}) {
    const res = await fetch(base + path, {
      method,
      headers: {
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair] = c.split(';');
      cookie = pair.endsWith('=') ? '' : pair;
    }
    const data = await res.json().catch(() => null);
    return { status: res.status, data, res };
  }
  return {
    get: (path) => request('GET', path),
    post: (path, body = {}, headers) => request('POST', path, body, headers),
    del: (path, headers) => request('DELETE', path, undefined, headers),
    get cookie() {
      return cookie;
    },
  };
}

const uniqueEmail = () => `user${++emailCounter}@example.com`;

async function signedIn() {
  const c = client();
  const email = uniqueEmail();
  const res = await c.post('/api/auth/register', { email, password: 'correct-horse' });
  assert.equal(res.status, 201);
  return { c, email };
}

async function createNote(c, { password = '', days = 7 } = {}) {
  const sealed = await sealNote('secret', password);
  const res = await c.post('/api/notes', {
    ciphertext: sealed.ciphertext,
    expiresInDays: days,
    password: sealed.password,
  });
  assert.equal(res.status, 201);
  return { id: res.data.id, tracked: res.data.tracked, sealed };
}

test('password hashing round-trips and rejects wrong passwords', async () => {
  const hash = await hashPassword('s3cret-pass');
  assert.match(hash, /^scrypt\$[A-Za-z0-9_-]+\$[A-Za-z0-9_-]+$/);
  assert.notEqual(hash, await hashPassword('s3cret-pass')); // random salt
  assert.equal(await verifyPassword('s3cret-pass', hash), true);
  assert.equal(await verifyPassword('wrong', hash), false);
  assert.equal(await verifyPassword('x', 'garbage'), false);
});

test('helpers: email normalizing and cookie parsing', () => {
  assert.equal(normalizeEmail('  Ali@Example.COM '), 'ali@example.com');
  assert.equal(normalizeEmail('not-an-email'), null);
  assert.equal(normalizeEmail(42), null);
  assert.deepEqual(parseCookies('a=1; gn_session=xyz; b=2'), { a: '1', gn_session: 'xyz', b: '2' });
  assert.deepEqual(parseCookies(undefined), {});
});

test('register signs the user in with a secure session cookie', async () => {
  const c = client();
  const email = uniqueEmail();
  const res = await c.post('/api/auth/register', { email: email.toUpperCase(), password: 'correct-horse' });
  assert.equal(res.status, 201);
  assert.equal(res.data.user.email, email);

  const setCookie = res.res.headers.getSetCookie()[0];
  assert.match(setCookie, /^gn_session=[A-Za-z0-9_-]{43};/);
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Lax/);
  assert.match(setCookie, /Path=\//);

  const me = await c.get('/api/auth/me');
  assert.equal(me.status, 200);
  assert.equal(me.data.user.email, email);
});

test('the database stores hashes, never the password or session token', async () => {
  const { c, email } = await signedIn();
  const user = app.store.getUserByEmail(email);
  assert.ok(!user.password_hash.includes('correct-horse'));
  const token = c.cookie.split('=')[1];
  const sessions = app.store.db.prepare('SELECT token_hash FROM sessions').all();
  assert.ok(sessions.length > 0);
  assert.ok(sessions.every((s) => s.token_hash !== token));
});

test('register rejects bad input and duplicate emails', async () => {
  const c = client();
  assert.equal((await c.post('/api/auth/register', { email: 'nope', password: 'longenough' })).data.error, 'invalid_email');
  assert.equal((await c.post('/api/auth/register', { email: uniqueEmail(), password: 'short' })).data.error, 'invalid_password');
  assert.equal((await c.post('/api/auth/register', { email: uniqueEmail(), password: 12345678 })).status, 400);

  const email = uniqueEmail();
  assert.equal((await c.post('/api/auth/register', { email, password: 'longenough' })).status, 201);
  const again = await client().post('/api/auth/register', { email: ` ${email.toUpperCase()} `, password: 'other-pass' });
  assert.equal(again.status, 409);
  assert.equal(again.data.error, 'email_taken');
});

test('login works with the right password and fails the same way otherwise', async () => {
  const { email } = await signedIn();

  const wrongPassword = await client().post('/api/auth/login', { email, password: 'wrong-password' });
  const unknownEmail = await client().post('/api/auth/login', { email: 'ghost@example.com', password: 'whatever' });
  assert.equal(wrongPassword.status, 401);
  assert.equal(unknownEmail.status, 401);
  // Same error, so attackers cannot tell which emails have accounts.
  assert.deepEqual(wrongPassword.data, unknownEmail.data);

  const c = client();
  const ok = await c.post('/api/auth/login', { email: email.toUpperCase(), password: 'correct-horse' });
  assert.equal(ok.status, 200);
  assert.equal((await c.get('/api/auth/me')).data.user.email, email);
});

test('logout ends the session on the server', async () => {
  const { c } = await signedIn();
  const stolenCookie = c.cookie;

  const out = await c.post('/api/auth/logout');
  assert.equal(out.status, 200);
  assert.match(out.res.headers.getSetCookie()[0], /Max-Age=0/);
  assert.equal((await c.get('/api/auth/me')).data.user, null);

  // The old cookie no longer works, even if someone kept a copy.
  const replay = await fetch(`${base}/api/auth/me`, { headers: { Cookie: stolenCookie } });
  assert.equal((await replay.json()).user, null);
});

test('sessions expire after 30 days', async () => {
  const { c } = await signedIn();
  clock += 29 * DAY;
  assert.ok((await c.get('/api/auth/me')).data.user);
  clock += 2 * DAY;
  assert.equal((await c.get('/api/auth/me')).data.user, null);
});

test('garbage session cookies are ignored', async () => {
  const res = await fetch(`${base}/api/auth/me`, { headers: { Cookie: 'gn_session=../../etc; other=1' } });
  assert.equal((await res.json()).user, null);
});

test('anonymous notes still work and are not tracked', async () => {
  const note = await createNote(client());
  assert.equal(note.tracked, false);
  assert.equal(app.store.getReceipt(note.id), null);
});

test('my notes shows status changes: pending, read, expired, destroyed', async () => {
  const { c } = await signedIn();
  const reader = client();

  const willBeRead = await createNote(c);
  const willExpire = await createNote(c, { days: 1 });
  const willBeDestroyed = await createNote(c, { password: 'pw' });
  const stillPending = await createNote(c, { days: 7 });
  assert.equal(willBeRead.tracked, true);

  let list = (await c.get('/api/my/notes')).data.notes;
  assert.equal(list.length, 4);
  assert.ok(list.every((n) => n.status === 'pending'));
  assert.equal(list[0].id, stillPending.id); // newest first
  // Receipts never contain the note content or key.
  assert.ok(!JSON.stringify(list).includes(willBeRead.sealed.key));
  assert.ok(!JSON.stringify(list).includes(willBeRead.sealed.ciphertext));

  assert.equal((await reader.post(`/api/notes/${willBeRead.id}/open`)).status, 200);

  const meta = (await reader.get(`/api/notes/${willBeDestroyed.id}`)).data;
  const wrong = await unlockPassword('bad', meta.salt);
  for (let i = 0; i < 5; i++) await reader.post(`/api/notes/${willBeDestroyed.id}/open`, { auth: wrong.auth });

  clock += DAY + 1;
  list = (await c.get('/api/my/notes')).data.notes;
  const byId = Object.fromEntries(list.map((n) => [n.id, n]));
  assert.equal(byId[willBeRead.id].status, 'read');
  assert.ok(byId[willBeRead.id].closedAt);
  assert.equal(byId[willExpire.id].status, 'expired');
  assert.equal(byId[willBeDestroyed.id].status, 'destroyed');
  assert.equal(byId[willBeDestroyed.id].hasPassword, true);
  assert.equal(byId[stillPending.id].status, 'pending');
});

test('owners can delete their unread notes, nobody else can', async () => {
  const owner = await signedIn();
  const other = await signedIn();
  const note = await createNote(owner.c);

  assert.equal((await other.c.del(`/api/my/notes/${note.id}`)).status, 404);
  assert.equal((await client().del(`/api/my/notes/${note.id}`)).status, 401);
  assert.equal((await client().get(`/api/notes/${note.id}`)).status, 200);

  assert.equal((await owner.c.del(`/api/my/notes/${note.id}`)).status, 200);
  assert.equal((await client().get(`/api/notes/${note.id}`)).status, 404);
  const [receipt] = (await owner.c.get('/api/my/notes')).data.notes;
  assert.equal(receipt.status, 'deleted');

  // Deleting twice, or deleting a note that was already read, is a conflict.
  assert.equal((await owner.c.del(`/api/my/notes/${note.id}`)).status, 409);
  const read = await createNote(owner.c);
  await client().post(`/api/notes/${read.id}/open`);
  assert.equal((await owner.c.del(`/api/my/notes/${read.id}`)).status, 409);
});

test('my notes requires a session', async () => {
  assert.equal((await client().get('/api/my/notes')).status, 401);
});

test('cross-site requests are rejected', async () => {
  const { c } = await signedIn();
  const note = await createNote(c);
  const evil = { Origin: 'https://evil.example' };

  assert.equal((await c.post('/api/auth/logout', {}, evil)).status, 403);
  assert.equal((await c.del(`/api/my/notes/${note.id}`, evil)).status, 403);
  assert.equal((await client().post('/api/auth/login', { email: 'a@b.co', password: 'x' }, evil)).status, 403);
  assert.ok((await c.get('/api/auth/me')).data.user, 'still signed in');

  // Same-origin requests (what the browser sends from our own pages) work.
  const sameOrigin = { Origin: base };
  assert.equal((await c.del(`/api/my/notes/${note.id}`, sameOrigin)).status, 200);
});

test('login is rate limited', async () => {
  const limited = createApp({ authRateLimit: { windowMs: 60_000, max: 3 } });
  await new Promise((resolve) => limited.server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${limited.server.address().port}/api/auth/login`;
  const attempt = () =>
    fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'a@example.com', password: 'guess-guess' }),
    }).then((r) => r.status);

  assert.deepEqual([await attempt(), await attempt(), await attempt(), await attempt()], [401, 401, 401, 429]);
  limited.server.close();
  limited.store.close();
});

test('auth pages are served', async () => {
  for (const path of ['/login', '/register', '/notes', '/js/nav.js', '/js/auth-page.js', '/js/notes.js']) {
    assert.equal((await fetch(base + path)).status, 200, path);
  }
});
