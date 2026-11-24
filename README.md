# Ghostnote 👻

Self-destructing, end-to-end encrypted notes. Write a note, get a link, and the note is deleted the moment it is read.

> Inspired by the idea behind burnernote.com. Written from scratch.

## Run it

Requires Node.js 22.13 or newer. No dependencies to install.

```bash
npm start        # http://localhost:3000
npm run dev      # same, restarts on file changes
npm test         # run the test suite
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `DB_FILE` | `data/ghostnote.db` | SQLite database file |

## How it works

1. The browser generates a random 256-bit AES-GCM key (Web Crypto API).
2. The note is encrypted in the browser. A random 96-bit IV is prepended to the ciphertext.
3. Only the ciphertext is sent to the server.
4. The key goes in the URL fragment (`#...`), which browsers never send to the server.
5. Opening the link shows a confirmation screen first, so link previews and bots cannot burn the note.
6. On "Show note", the server returns the ciphertext and deletes it in the same request. The browser decrypts it locally and removes the key from the address bar.

The server never sees the key, so it can never read a note.

### Password protection

If a password is set, PBKDF2-SHA256 (310,000 iterations) turns it into two independent 256-bit values:

- **encKey** adds a second layer of AES-GCM encryption. It never leaves the browser.
- **auth** proves the password to the server, which stores only an scrypt hash of it.

A wrong password does not burn the note. After 5 wrong attempts, the note is destroyed.

## Features

- [x] Client-side AES-256-GCM encryption, key in the URL fragment
- [x] Burn after reading (1 view), hard delete
- [x] Expiry in days (1 to 30, default 7), with an hourly cleanup job
- [x] Optional password, 5 attempts max
- [x] Confirmation screen before opening (safe from link previews)
- [x] Dark / light theme
- [x] "Notes destroyed" counter
- [x] Strict security headers (CSP, no referrer, no framing), rate limiting

## Later

- [ ] Multiple allowed views
- [ ] Read receipts
- [ ] Encrypted file attachments
- [ ] Accounts and a public inbox

## Project layout

```
src/server.js       HTTP server, API, static files
src/store.js        SQLite storage (node:sqlite)
public/             Pages, styles and browser code
public/js/crypto.js All encryption (shared by browser and tests)
test/               Tests (node:test)
```

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/notes` | Create a note: `{ ciphertext, expiresInDays, password?: { salt, auth } }` → `{ id }` |
| `GET` | `/api/notes/:id` | Check a note exists, without burning it → `{ hasPassword, salt, expiresAt }` |
| `POST` | `/api/notes/:id/open` | Get the ciphertext and burn the note: `{ auth? }` → `{ ciphertext }` |
| `GET` | `/api/stats` | `{ destroyed }` |

## Security notes

- Client-side encryption cannot protect against a compromised device, malicious browser extensions, or someone copying the text after it is decrypted.
- Run behind HTTPS in production. The rate limiter uses the socket IP, so behind a reverse proxy it needs to read the forwarded client IP instead.

## License

To be decided.
