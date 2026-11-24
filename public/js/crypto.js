// Client-side encryption. Runs in the browser (and in Node for tests).
// The server never sees the key or the password.

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const KEY_BYTES = 32; // AES-256
const IV_BYTES = 12; // 96-bit IV for AES-GCM
const SALT_BYTES = 16;
const PBKDF2_ITERATIONS = 310_000;

export function toBase64Url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(str) {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error('Invalid base64url');
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

function importAesKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/** Encrypts with AES-256-GCM and returns IV || ciphertext. */
async function aesEncrypt(rawKey, data) {
  const iv = randomBytes(IV_BYTES);
  const key = await importAesKey(rawKey);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
  const out = new Uint8Array(IV_BYTES + ct.length);
  out.set(iv);
  out.set(ct, IV_BYTES);
  return out;
}

async function aesDecrypt(rawKey, data) {
  const key = await importAesKey(rawKey);
  const iv = data.subarray(0, IV_BYTES);
  const ct = data.subarray(IV_BYTES);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
}

/**
 * Turns a password into two independent 256-bit values:
 * - encKey encrypts the note (never leaves the browser)
 * - auth proves the password to the server (the server stores only a hash)
 */
async function derivePassword(password, salt) {
  const base = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
      base,
      512,
    ),
  );
  return { encKey: bits.slice(0, 32), auth: bits.slice(32) };
}

/**
 * Encrypts a note.
 * Returns the key for the URL fragment, the ciphertext for the server,
 * and (if a password was given) the salt and auth token for the server.
 */
export async function sealNote(text, password = '') {
  const key = randomBytes(KEY_BYTES);
  let payload = await aesEncrypt(key, encoder.encode(text));

  let pw = null;
  if (password) {
    const salt = randomBytes(SALT_BYTES);
    const derived = await derivePassword(password, salt);
    payload = await aesEncrypt(derived.encKey, payload);
    pw = { salt: toBase64Url(salt), auth: toBase64Url(derived.auth) };
  }

  return { key: toBase64Url(key), ciphertext: toBase64Url(payload), password: pw };
}

/** Derives the auth token (for the server) and the password key (kept local). */
export async function unlockPassword(password, saltB64) {
  const derived = await derivePassword(password, fromBase64Url(saltB64));
  return { auth: toBase64Url(derived.auth), encKey: derived.encKey };
}

/** True if the string looks like a valid note key. */
export function isValidKey(keyB64) {
  try {
    return fromBase64Url(keyB64).length === KEY_BYTES;
  } catch {
    return false;
  }
}

/** Decrypts a note. Throws if the key or password key is wrong. */
export async function openNote(ciphertextB64, keyB64, passwordKey = null) {
  let data = fromBase64Url(ciphertextB64);
  if (passwordKey) data = await aesDecrypt(passwordKey, data);
  const key = fromBase64Url(keyB64);
  if (key.length !== KEY_BYTES) throw new Error('Invalid key');
  return decoder.decode(await aesDecrypt(key, data));
}
