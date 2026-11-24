import { sealNote } from './crypto.js';

const MAX_BYTES = 150_000;

const $ = (id) => document.getElementById(id);
const form = $('create-form');
const textarea = $('note-text');
const counter = $('char-count');
const advancedToggle = $('advanced-toggle');
const advancedPanel = $('advanced-panel');
const passwordInput = $('note-password');
const daysSelect = $('note-days');
const submitButton = $('submit-button');
const errorBox = $('create-error');
const resultBox = $('result');
const linkInput = $('result-link');
const copyButton = $('copy-button');
const newNoteButton = $('new-note-button');
const resultInfo = $('result-info');
const destroyedCount = $('destroyed-count');

const ERRORS = {
  rate_limited: 'Çok fazla istek gönderdin. Biraz bekleyip tekrar dene.',
  too_large: 'Not çok uzun.',
};

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

function byteLength(text) {
  return new TextEncoder().encode(text).length;
}

textarea.addEventListener('input', () => {
  const bytes = byteLength(textarea.value);
  counter.textContent = `${bytes.toLocaleString('tr-TR')} / ${MAX_BYTES.toLocaleString('tr-TR')}`;
  counter.classList.toggle('over', bytes > MAX_BYTES);
});

advancedToggle.addEventListener('click', () => {
  const open = advancedPanel.hidden;
  advancedPanel.hidden = !open;
  advancedToggle.setAttribute('aria-expanded', String(open));
  advancedToggle.textContent = open ? 'Seçenekleri gizle' : 'Gelişmiş seçenekler';
});

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');

  const text = textarea.value;
  if (!text.trim()) return showError('Önce bir not yaz.');
  if (byteLength(text) > MAX_BYTES) return showError('Not çok uzun.');

  submitButton.disabled = true;
  submitButton.textContent = 'Şifreleniyor…';

  try {
    const password = passwordInput.value;
    const days = Number(daysSelect.value);
    const sealed = await sealNote(text, password);

    const res = await fetch('/api/notes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ciphertext: sealed.ciphertext,
        expiresInDays: days,
        password: sealed.password,
      }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(ERRORS[data.error] ?? 'Not oluşturulamadı. Tekrar dene.');

    linkInput.value = `${location.origin}/n/${data.id}#${sealed.key}`;
    resultInfo.textContent =
      `Bu link bir kez açılabilir. Açılmazsa ${days} gün sonra kendini siler.` +
      (password ? ' Şifreyi alıcıya ayrı bir yoldan ilet.' : '') +
      (data.tracked ? ' Okunup okunmadığını Notlarım sayfasından takip edebilirsin.' : '');

    textarea.value = '';
    passwordInput.value = '';
    textarea.dispatchEvent(new Event('input'));
    form.hidden = true;
    resultBox.hidden = false;
    linkInput.focus();
    linkInput.select();
  } catch (err) {
    showError(err.message || 'Bir şeyler ters gitti.');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = 'Link oluştur';
  }
});

copyButton.addEventListener('click', async () => {
  try {
    await navigator.clipboard.writeText(linkInput.value);
  } catch {
    linkInput.select();
    document.execCommand('copy');
  }
  copyButton.textContent = 'Kopyalandı ✓';
  setTimeout(() => (copyButton.textContent = 'Kopyala'), 2000);
});

newNoteButton.addEventListener('click', () => {
  linkInput.value = '';
  resultBox.hidden = true;
  form.hidden = false;
  textarea.focus();
});

fetch('/api/stats')
  .then((res) => (res.ok ? res.json() : null))
  .then((data) => {
    if (data) destroyedCount.textContent = data.destroyed.toLocaleString('tr-TR');
  })
  .catch(() => {});
