import { DatabaseSync } from 'node:sqlite';

/**
 * Stores encrypted notes. The server only ever sees ciphertext: the key
 * lives in the URL fragment, which browsers never send to the server.
 */
export class NoteStore {
  constructor(file, { now = Date.now } = {}) {
    this.now = now;
    this.db = new DatabaseSync(file);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
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
    `);

    this.stmt = {
      insert: this.db.prepare(`
        INSERT INTO notes (id, ciphertext, pw_salt, pw_verifier, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)`),
      get: this.db.prepare('SELECT * FROM notes WHERE id = ?'),
      delete: this.db.prepare('DELETE FROM notes WHERE id = ?'),
      failAttempt: this.db.prepare(
        'UPDATE notes SET pw_attempts = pw_attempts + 1 WHERE id = ? RETURNING pw_attempts'),
      purge: this.db.prepare('DELETE FROM notes WHERE expires_at <= ?'),
      addDestroyed: this.db.prepare(
        "UPDATE stats SET value = value + ? WHERE key = 'destroyed'"),
      destroyed: this.db.prepare("SELECT value FROM stats WHERE key = 'destroyed'"),
    };
  }

  create({ id, ciphertext, pwSalt = null, pwVerifier = null, expiresAt }) {
    this.stmt.insert.run(id, ciphertext, pwSalt, pwVerifier, this.now(), expiresAt);
  }

  /** Returns the note, or null if it does not exist or has expired. */
  get(id) {
    const row = this.stmt.get.get(id);
    if (!row) return null;
    if (row.expires_at <= this.now()) {
      this.burn(id);
      return null;
    }
    return row;
  }

  /** Permanently deletes a note. Returns true if a note was deleted. */
  burn(id) {
    const { changes } = this.stmt.delete.run(id);
    if (changes > 0) this.stmt.addDestroyed.run(changes);
    return changes > 0;
  }

  /** Records a wrong password and returns the total number of failed attempts. */
  failAttempt(id) {
    return this.stmt.failAttempt.get(id)?.pw_attempts ?? 0;
  }

  /** Deletes every expired note. Returns how many were deleted. */
  purgeExpired() {
    const { changes } = this.stmt.purge.run(this.now());
    if (changes > 0) this.stmt.addDestroyed.run(changes);
    return Number(changes);
  }

  destroyedCount() {
    return Number(this.stmt.destroyed.get().value);
  }

  close() {
    this.db.close();
  }
}
