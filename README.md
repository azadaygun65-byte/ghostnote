# Ghostnote

Self-destructing, end-to-end encrypted notes. Write a note, get a link, and the note is deleted the moment it is read.

> Status: planning. Inspired by the idea behind burnernote.com; this project is written from scratch.

## How it works

1. The browser generates a random 256-bit AES-GCM key (Web Crypto API).
2. The note is encrypted in the browser. A random 96-bit IV is prepended to the ciphertext.
3. Only the ciphertext is sent to the server.
4. The key goes in the URL fragment (`#...`), which browsers never send to the server.
5. When the link is opened, the browser fetches the ciphertext and decrypts it locally.
6. After the view limit is reached, the server hard-deletes the note.

The server never sees the key, so it can never read a note.

## MVP features

- [ ] Create a note (client-side encryption)
- [ ] Share link with key in the fragment
- [ ] Burn after reading (1 view), then hard delete
- [ ] Expiry in days (default 7), with a cleanup job
- [ ] Optional password protection
- [ ] Dark / light theme
- [ ] Notes counter ("N notes destroyed")

## Later

- [ ] Multiple allowed views
- [ ] Read receipts
- [ ] Encrypted file attachments
- [ ] Accounts and a public inbox ("burn box")

## Pages

| Route | Purpose |
|---|---|
| `/` | Create a note (textarea, advanced options, "Get Link") |
| `/n/{id}#key` | Read and burn a note |
| `/about` | Explains the encryption |
| `/privacy` | Privacy policy |

## Stack

To be decided.

## Security notes

Client-side encryption cannot protect against a compromised device, malicious browser extensions, or someone copying the text after it is decrypted.

## License

To be decided.
