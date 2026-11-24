import http from 'node:http';
import crypto from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NoteStore } from './store.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const PUBLIC_DIR = path.join(ROOT, 'public');

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 256 * 1024;
const MAX_CIPHERTEXT_CHARS = 210_000;
const MIN_CIPHERTEXT_CHARS = 38; // 12-byte IV + 16-byte GCM tag, base64url
const MAX_PASSWORD_ATTEMPTS = 5;
const MIN_DAYS = 1;
const MAX_DAYS = 30;

const ID_RE = /^[A-Za-z0-9_-]{22}$/;
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const SALT_RE = /^[A-Za-z0-9_-]{22}$/; // 16 bytes
const AUTH_RE = /^[A-Za-z0-9_-]{43}$/; // 32 bytes

const SECURITY_HEADERS = {
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
};

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
};

const PAGES = { '/': 'index.html', '/about': 'about.html' };

class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  res.end(body);
}

function sendJson(res, status, data) {
  send(res, status, JSON.stringify(data), {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
}

async function readJson(req) {
  const type = req.headers['content-type'] ?? '';
  if (!type.startsWith('application/json')) throw new HttpError(415, 'json_required');

  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'too_large');
    chunks.push(chunk);
  }
  try {
    const data = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new Error();
    return data;
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
}

/** Fixed-window rate limiter, keyed by client IP. */
function createRateLimiter({ windowMs, max }, now) {
  const hits = new Map();
  return function allow(key) {
    const t = now();
    if (hits.size > 10_000) {
      for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k);
    }
    const entry = hits.get(key);
    if (!entry || entry.resetAt <= t) {
      hits.set(key, { count: 1, resetAt: t + windowMs });
      return true;
    }
    entry.count += 1;
    return entry.count <= max;
  };
}

function hashAuth(authB64, saltB64) {
  return crypto.scryptSync(Buffer.from(authB64, 'base64url'), Buffer.from(saltB64, 'base64url'), 32);
}

export function createApp({
  dbFile = ':memory:',
  now = Date.now,
  rateLimit = { windowMs: 60_000, max: 30 },
} = {}) {
  const store = new NoteStore(dbFile, { now });
  const allow = createRateLimiter(rateLimit, now);

  function checkRate(req) {
    if (!allow(req.socket.remoteAddress ?? 'unknown')) throw new HttpError(429, 'rate_limited');
  }

  async function createNote(req, res) {
    checkRate(req);
    const body = await readJson(req);
    const { ciphertext, expiresInDays, password } = body;

    if (
      typeof ciphertext !== 'string' ||
      ciphertext.length < MIN_CIPHERTEXT_CHARS ||
      !B64URL_RE.test(ciphertext)
    ) {
      throw new HttpError(400, 'invalid_ciphertext');
    }
    if (ciphertext.length > MAX_CIPHERTEXT_CHARS) throw new HttpError(413, 'too_large');
    if (!Number.isInteger(expiresInDays) || expiresInDays < MIN_DAYS || expiresInDays > MAX_DAYS) {
      throw new HttpError(400, 'invalid_expiry');
    }

    let pwSalt = null;
    let pwVerifier = null;
    if (password !== undefined && password !== null) {
      if (
        typeof password !== 'object' ||
        typeof password.salt !== 'string' ||
        typeof password.auth !== 'string' ||
        !SALT_RE.test(password.salt) ||
        !AUTH_RE.test(password.auth)
      ) {
        throw new HttpError(400, 'invalid_password');
      }
      pwSalt = password.salt;
      pwVerifier = hashAuth(password.auth, password.salt);
    }

    const id = crypto.randomBytes(16).toString('base64url');
    store.create({ id, ciphertext, pwSalt, pwVerifier, expiresAt: now() + expiresInDays * DAY_MS });
    sendJson(res, 201, { id });
  }

  function noteMeta(res, id) {
    const note = store.get(id);
    if (!note) throw new HttpError(404, 'not_found');
    sendJson(res, 200, {
      hasPassword: note.pw_verifier !== null,
      salt: note.pw_salt,
      expiresAt: note.expires_at,
    });
  }

  async function openNote(req, res, id) {
    checkRate(req);
    const body = await readJson(req);
    const note = store.get(id);
    if (!note) throw new HttpError(404, 'not_found');

    if (note.pw_verifier !== null) {
      const ok =
        typeof body.auth === 'string' &&
        AUTH_RE.test(body.auth) &&
        crypto.timingSafeEqual(hashAuth(body.auth, note.pw_salt), note.pw_verifier);

      if (!ok) {
        const attempts = store.failAttempt(id);
        if (attempts >= MAX_PASSWORD_ATTEMPTS) {
          store.burn(id);
          throw new HttpError(410, 'too_many_attempts');
        }
        return sendJson(res, 403, {
          error: 'wrong_password',
          attemptsLeft: MAX_PASSWORD_ATTEMPTS - attempts,
        });
      }
    }

    // Burn before responding: once the ciphertext leaves the server, it is gone.
    store.burn(id);
    sendJson(res, 200, { ciphertext: note.ciphertext });
  }

  async function handleApi(req, res, pathname) {
    if (pathname === '/api/notes') {
      if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed');
      return createNote(req, res);
    }
    if (pathname === '/api/stats') {
      if (req.method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      return sendJson(res, 200, { destroyed: store.destroyedCount() });
    }

    const match = pathname.match(/^\/api\/notes\/([^/]+)(\/open)?$/);
    if (match) {
      const [, id, open] = match;
      if (!ID_RE.test(id)) throw new HttpError(404, 'not_found');
      if (open) {
        if (req.method !== 'POST') throw new HttpError(405, 'method_not_allowed');
        return openNote(req, res, id);
      }
      if (req.method !== 'GET') throw new HttpError(405, 'method_not_allowed');
      return noteMeta(res, id);
    }
    throw new HttpError(404, 'not_found');
  }

  async function sendFile(req, res, relPath, extraHeaders = {}) {
    const filePath = path.join(PUBLIC_DIR, relPath);
    if (!filePath.startsWith(PUBLIC_DIR + path.sep)) return send(res, 404, 'Not found');
    let data;
    try {
      data = await readFile(filePath);
    } catch (err) {
      if (err.code === 'ENOENT' || err.code === 'EISDIR') return send(res, 404, 'Not found');
      throw err;
    }
    const type = MIME_TYPES[path.extname(filePath)] ?? 'application/octet-stream';
    send(res, 200, req.method === 'HEAD' ? undefined : data, {
      'Content-Type': type,
      'Cache-Control': 'no-cache',
      ...extraHeaders,
    });
  }

  async function handle(req, res) {
    let pathname;
    try {
      pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    } catch {
      return send(res, 400, 'Bad request');
    }

    if (pathname.startsWith('/api/')) {
      try {
        return await handleApi(req, res, pathname);
      } catch (err) {
        if (err instanceof HttpError) return sendJson(res, err.status, { error: err.code });
        throw err;
      }
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, 'Method not allowed');
    if (PAGES[pathname]) return sendFile(req, res, PAGES[pathname]);
    if (/^\/n\/[A-Za-z0-9_-]+$/.test(pathname)) {
      return sendFile(req, res, 'note.html', { 'Cache-Control': 'no-store' });
    }
    return sendFile(req, res, pathname);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal' });
      else res.end();
    });
  });

  return { server, store };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 3000);
  const dbFile = process.env.DB_FILE ?? path.join(ROOT, 'data', 'ghostnote.db');
  if (dbFile !== ':memory:') mkdirSync(path.dirname(dbFile), { recursive: true });

  const { server, store } = createApp({ dbFile });
  const purge = () => {
    const n = store.purgeExpired();
    if (n > 0) console.log(`Purged ${n} expired note(s)`);
  };
  purge();
  setInterval(purge, 60 * 60 * 1000).unref();

  server.listen(port, () => console.log(`Ghostnote running at http://localhost:${port}`));
}
