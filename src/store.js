import { DatabaseSync } from 'node:sqlite';

/**
 * Stores encrypted notes, user accounts and sessions.
 *
 * The server only ever sees a note's ciphertext: the key lives in the URL
 * fragment, which browsers never send to the server. For signed-in users we
 * also keep a "receipt" per note (status and dates, never the content or
 * key), so they can see whether their note was read.
 */
export class NoteStore {
  constructor(file, { now = Date.now } = {}) {
    this.now = now;
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;

      CREATE TABLE IF NOT EXISTS notes (
        id          TEXT PRIMARY KEY,
        ciphertext  TEXT NOT NULL,
        pw_salt     TEXT,
        pw_verifier BLOB,
        pw_attempts INTEGER NOT NULL DEFAULT 0,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS notes_expires_at ON notes (expires_at);

      CREATE TABLE IF NOT EXISTS stats (
        key   TEXT PRIMARY KEY,
        value INTEGER NOT NULL
      );
      INSERT OR IGNORE INTO stats (key, value) VALUES ('destroyed', 0);

      CREATE TABLE IF NOT EXISTS users (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        email         TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at    INTEGER NOT NULL
      );

      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS sessions_expires_at ON sessions (expires_at);

      -- status: pending | read | expired | destroyed | deleted
      CREATE TABLE IF NOT EXISTS note_receipts (
        note_id      TEXT PRIMARY KEY,
        user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
        has_password INTEGER NOT NULL,
        status       TEXT NOT NULL DEFAULT 'pending',
        created_at   INTEGER NOT NULL,
        expires_at   INTEGER NOT NULL,
        closed_at    INTEGER
      );
      CREATE INDEX IF NOT EXISTS note_receipts_user ON note_receipts (user_id, created_at);
    `);

    const q = (sql) => this.db.prepare(sql);
    this.stmt = {
      insert: q(`INSERT INTO notes (id, ciphertext, pw_salt, pw_verifier, created_at, expires_at)
                 VALUES (?, ?, ?, ?, ?, ?)`),
      get: q('SELECT * FROM notes WHERE id = ?'),
      delete: q('DELETE FROM notes WHERE id = ?'),
      failAttempt: q('UPDATE notes SET pw_attempts = pw_attempts + 1 WHERE id = ? RETURNING pw_attempts'),
      purge: q('DELETE FROM notes WHERE expires_at <= ?'),
      addDestroyed: q("UPDATE stats SET value = value + ? WHERE key = 'destroyed'"),
      destroyed: q("SELECT value FROM stats WHERE key = 'destroyed'"),

      insertReceipt: q(`INSERT INTO note_receipts (note_id, user_id, has_password, created_at, expires_at)
                        VALUES (?, ?, ?, ?, ?)`),
      closeReceipt: q(`UPDATE note_receipts SET status = ?, closed_at = ?
                       WHERE note_id = ? AND status = 'pending'`),
      expireReceipts: q(`UPDATE note_receipts SET status = 'expired', closed_at = expires_at
                         WHERE status = 'pending' AND expires_at <= ?`),
      getReceipt: q('SELECT * FROM note_receipts WHERE note_id = ?'),
      listReceipts: q(`SELECT * FROM note_receipts WHERE user_id = ?
                       ORDER BY created_at DESC, rowid DESC LIMIT ?`),

      insertUser: q('INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?) RETURNING id'),
      userByEmail: q('SELECT * FROM users WHERE email = ?'),

      insertSession: q('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)'),
      sessionUser: q(`SELECT users.id, users.email, users.created_at FROM sessions
                      JOIN users ON users.id = sessions.user_id
                      WHERE sessions.token_hash = ? AND sessions.expires_at > ?`),
      deleteSession: q('DELETE FROM sessions WHERE token_hash = ?'),
      purgeSessions: q('DELETE FROM sessions WHERE expires_at <= ?'),
    };
  }

  transaction(fn) {
    this.db.exec('BEGIN');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  // ----- Notes -----

  create({ id, ciphertext, pwSalt = null, pwVerifier = null, expiresAt, ownerId = null }) {
    const createdAt = this.now();
    this.transaction(() => {
      this.stmt.insert.run(id, ciphertext, pwSalt, pwVerifier, createdAt, expiresAt);
      if (ownerId !== null) {
        this.stmt.insertReceipt.run(id, ownerId, pwVerifier !== null ? 1 : 0, createdAt, expiresAt);
      }
    });
  }

  /** Returns the note, or null if it does not exist or has expired. */
  get(id) {
    const row = this.stmt.get.get(id);
    if (!row) return null;
    if (row.expires_at <= this.now()) {
      this.burn(id, 'expired');
      return null;
    }
    return row;
  }

  /**
   * Permanently deletes a note and records why on its receipt:
   * read, expired, destroyed (too many wrong passwords) or deleted (by its owner).
   * Returns true if a note was deleted.
   */
  burn(id, reason = 'read') {
    return this.transaction(() => {
      const { changes } = this.stmt.delete.run(id);
      if (changes > 0) {
        this.stmt.addDestroyed.run(changes);
        this.stmt.closeReceipt.run(reason, this.now(), id);
      }
      return changes > 0;
    });
  }

  /** Records a wrong password and returns the total number of failed attempts. */
  failAttempt(id) {
    return this.stmt.failAttempt.get(id)?.pw_attempts ?? 0;
  }

  /** Deletes every expired note and session. Returns how many notes were deleted. */
  purgeExpired() {
    const t = this.now();
    return this.transaction(() => {
      const { changes } = this.stmt.purge.run(t);
      if (changes > 0) this.stmt.addDestroyed.run(changes);
      this.stmt.expireReceipts.run(t);
      this.stmt.purgeSessions.run(t);
      return Number(changes);
    });
  }

  destroyedCount() {
    return Number(this.stmt.destroyed.get().value);
  }

  // ----- Receipts -----

  getReceipt(noteId) {
    return this.stmt.getReceipt.get(noteId) ?? null;
  }

  listReceipts(userId, limit = 100) {
    // Notes that expired since the last purge still say "pending"; fix that on read.
    this.stmt.expireReceipts.run(this.now());
    return this.stmt.listReceipts.all(userId, limit);
  }

  // ----- Users & sessions -----

  /** Creates a user and returns its id, or null if the email is taken. */
  createUser(email, passwordHash) {
    try {
      return Number(this.stmt.insertUser.get(email, passwordHash, this.now()).id);
    } catch (err) {
      if (String(err.message).includes('UNIQUE')) return null;
      throw err;
    }
  }

  getUserByEmail(email) {
    return this.stmt.userByEmail.get(email) ?? null;
  }

  createSession(tokenHash, userId, expiresAt) {
    this.stmt.insertSession.run(tokenHash, userId, this.now(), expiresAt);
  }

  /** The signed-in user for a session token hash, or null. */
  getSessionUser(tokenHash) {
    return this.stmt.sessionUser.get(tokenHash, this.now()) ?? null;
  }

  deleteSession(tokenHash) {
    this.stmt.deleteSession.run(tokenHash);
  }

  close() {
    this.db.close();
  }
}
