// Shared by every page: knows who is signed in and fills the header links.

let userPromise;

/** The signed-in user ({ email, createdAt }) or null. Fetched once per page. */
export function getUser() {
  userPromise ??= fetch('/api/auth/me')
    .then((res) => (res.ok ? res.json() : { user: null }))
    .then((data) => data.user ?? null)
    .catch(() => null);
  return userPromise;
}

export async function logout() {
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  }).catch(() => {});
  location.href = '/';
}

function link(href, text, className = '') {
  const a = document.createElement('a');
  a.href = href;
  a.textContent = text;
  if (className) a.className = className;
  return a;
}

async function renderNav() {
  const slot = document.getElementById('auth-nav');
  if (!slot) return;
  const user = await getUser();

  if (user) {
    const logoutButton = document.createElement('button');
    logoutButton.type = 'button';
    logoutButton.className = 'link-button';
    logoutButton.textContent = 'Çıkış';
    logoutButton.addEventListener('click', logout);
    slot.replaceChildren(link('/notes', 'Notlarım'), logoutButton);
  } else {
    slot.replaceChildren(link('/login', 'Giriş yap', 'nav-cta'));
  }
}

renderNav();
