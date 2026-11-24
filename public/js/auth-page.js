// Login and register pages.
import { getUser } from './nav.js';

const form = document.getElementById('auth-form');
const mode = form.dataset.mode; // "login" | "register"
const emailInput = document.getElementById('auth-email');
const passwordInput = document.getElementById('auth-password');
const confirmInput = document.getElementById('auth-password-confirm');
const submitButton = document.getElementById('auth-submit');
const errorBox = document.getElementById('auth-error');

const ERRORS = {
  invalid_email: 'Geçerli bir e-posta adresi gir.',
  invalid_password: 'Şifre en az 8 karakter olmalı.',
  email_taken: 'Bu e-posta ile zaten bir hesap var. Giriş yapmayı dene.',
  invalid_credentials: 'E-posta ya da şifre yanlış.',
  rate_limited: 'Çok fazla deneme yaptın. 15 dakika sonra tekrar dene.',
};

/** Only allow redirects to paths on this site. */
function nextPath() {
  const next = new URLSearchParams(location.search).get('next');
  return next && next.startsWith('/') && !next.startsWith('//') ? next : '/notes';
}

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = !message;
}

// Already signed in? Skip this page.
getUser().then((user) => {
  if (user) location.replace(nextPath());
});

// Keep ?next= when switching between login and register.
const switchLink = document.getElementById('auth-switch');
if (switchLink && location.search) switchLink.href += location.search;

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  showError('');

  const email = emailInput.value.trim();
  const password = passwordInput.value;
  if (!email || !password) return showError('E-posta ve şifreyi doldur.');
  if (mode === 'register') {
    if (password.length < 8) return showError(ERRORS.invalid_password);
    if (password !== confirmInput.value) return showError('Şifreler aynı değil.');
  }

  submitButton.disabled = true;
  const label = submitButton.textContent;
  submitButton.textContent = mode === 'register' ? 'Hesap oluşturuluyor…' : 'Giriş yapılıyor…';

  try {
    const res = await fetch(`/api/auth/${mode}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      passwordInput.value = '';
      if (confirmInput) confirmInput.value = '';
      return showError(ERRORS[data.error] ?? 'Bir şeyler ters gitti. Tekrar dene.');
    }
    location.href = nextPath();
  } catch {
    showError('Sunucuya ulaşılamadı. Bağlantını kontrol et.');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = label;
  }
});
