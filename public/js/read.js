import { isValidKey, openNote, unlockPassword } from './crypto.js';

const $ = (id) => document.getElementById(id);
const views = ['view-loading', 'view-confirm', 'view-note', 'view-gone', 'view-invalid'];

function show(viewId) {
  for (const id of views) $(id).hidden = id !== viewId;
}

const id = location.pathname.split('/').pop();
const key = location.hash.slice(1);

const passwordField = $('password-field');
const passwordInput = $('read-password');
const revealButton = $('reveal-button');
const errorBox = $('read-error');

let meta = null;

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function gone(message) {
  if (message) $('gone-message').textContent = message;
  show('view-gone');
}

async function init() {
  if (!isValidKey(key)) return show('view-invalid');

  const res = await fetch(`/api/notes/${encodeURIComponent(id)}`).catch(() => null);
  if (!res) return gone('Sunucuya ulaşılamadı. Bağlantını kontrol et.');
  if (res.status === 404) return gone();
  if (!res.ok) return gone('Bir şeyler ters gitti. Daha sonra tekrar dene.');

  meta = await res.json();
  passwordField.hidden = !meta.hasPassword;
  show('view-confirm');
  if (meta.hasPassword) passwordInput.focus();
}

async function reveal(event) {
  event.preventDefault();
  showError('');

  if (meta.hasPassword && !passwordInput.value) return showError('Şifreyi gir.');

  revealButton.disabled = true;
  try {
    let passwordKey = null;
    const body = {};
    if (meta.hasPassword) {
      revealButton.textContent = 'Şifre kontrol ediliyor…';
      const unlocked = await unlockPassword(passwordInput.value, meta.salt);
      body.auth = unlocked.auth;
      passwordKey = unlocked.encKey;
    }

    revealButton.textContent = 'Açılıyor…';
    const res = await fetch(`/api/notes/${encodeURIComponent(id)}/open`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));

    if (res.status === 403) {
      passwordInput.value = '';
      passwordInput.focus();
      return showError(`Yanlış şifre. ${data.attemptsLeft} deneme hakkın kaldı.`);
    }
    if (res.status === 410) {
      return gone('Çok fazla yanlış şifre denendi, not güvenlik için yok edildi.');
    }
    if (res.status === 404) return gone();
    if (res.status === 429) return showError('Çok fazla deneme. Biraz bekleyip tekrar dene.');
    if (!res.ok) return showError('Bir şeyler ters gitti. Tekrar dene.');

    // Remove the key from the address bar and history.
    history.replaceState(null, '', location.pathname);

    try {
      $('note-content').textContent = await openNote(data.ciphertext, key, passwordKey);
      show('view-note');
    } catch {
      gone('Not açıldı ama çözülemedi. Link eksik ya da bozuk kopyalanmış olabilir. Not artık silindi.');
    }
  } catch {
    showError('Sunucuya ulaşılamadı. Bağlantını kontrol edip tekrar dene.');
  } finally {
    revealButton.disabled = false;
    revealButton.textContent = 'Notu göster';
  }
}

$('confirm-form').addEventListener('submit', reveal);

$('copy-note').addEventListener('click', async () => {
  const button = $('copy-note');
  try {
    await navigator.clipboard.writeText($('note-content').textContent);
    button.textContent = 'Kopyalandı ✓';
  } catch {
    button.textContent = 'Kopyalanamadı';
  }
  setTimeout(() => (button.textContent = 'Metni kopyala'), 2000);
});

init();
