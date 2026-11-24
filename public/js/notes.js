// "Notlarım": the signed-in user's notes and whether they were read.
import { getUser } from './nav.js';

const $ = (id) => document.getElementById(id);

const STATUS = {
  pending: { label: 'Bekliyor', className: 'badge-pending', closed: null },
  read: { label: 'Okundu', className: 'badge-read', closed: 'Okunma' },
  expired: { label: 'Süresi doldu', className: 'badge-muted', closed: 'Silinme' },
  destroyed: { label: 'Yok edildi', className: 'badge-danger', closed: 'Yok edilme' },
  deleted: { label: 'Sen sildin', className: 'badge-muted', closed: 'Silinme' },
};

const formatDate = (ms) =>
  new Date(ms).toLocaleString('tr-TR', { dateStyle: 'medium', timeStyle: 'short' });

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderNote(note) {
  const status = STATUS[note.status] ?? STATUS.pending;
  const item = el('li', 'note-item');

  const head = el('div', 'note-item-head');
  head.append(el('span', `badge ${status.className}`, status.label));
  if (note.hasPassword) head.append(el('span', 'note-lock', '🔒 Şifreli'));
  item.append(head);

  const dates = el('dl', 'note-dates');
  const add = (label, value) => dates.append(el('dt', '', label), el('dd', '', value));
  add('Oluşturma', formatDate(note.createdAt));
  if (note.status === 'pending') add('Son gün', formatDate(note.expiresAt));
  else if (note.closedAt) add(status.closed, formatDate(note.closedAt));
  if (note.status === 'destroyed') add('Neden', '5 kez yanlış şifre girildi');
  item.append(dates);

  if (note.status === 'pending') {
    const button = el('button', 'secondary danger-button', 'Notu sil');
    button.type = 'button';
    button.addEventListener('click', () => deleteNote(note, button));
    item.append(button);
  }
  return item;
}

async function deleteNote(note, button) {
  if (!confirm('Bu not kalıcı olarak silinsin mi? Link artık çalışmayacak.')) return;
  button.disabled = true;
  const res = await fetch(`/api/my/notes/${encodeURIComponent(note.id)}`, { method: 'DELETE' }).catch(() => null);
  if (!res || (!res.ok && res.status !== 409)) {
    button.disabled = false;
    return alert('Not silinemedi. Tekrar dene.');
  }
  load();
}

async function load() {
  const res = await fetch('/api/my/notes').catch(() => null);
  if (res?.status === 401) return location.replace('/login?next=/notes');
  if (!res?.ok) {
    $('notes-loading').textContent = 'Notlar yüklenemedi. Sayfayı yenile.';
    return;
  }
  const { notes } = await res.json();
  $('notes-loading').hidden = true;
  $('notes-empty').hidden = notes.length > 0;
  $('notes-list').replaceChildren(...notes.map(renderNote));

  const counts = notes.reduce((acc, n) => ((acc[n.status] = (acc[n.status] ?? 0) + 1), acc), {});
  $('notes-summary').textContent = notes.length
    ? `${notes.length} not · ${counts.pending ?? 0} bekliyor · ${counts.read ?? 0} okundu`
    : '';
}

getUser().then((user) => {
  if (!user) return location.replace('/login?next=/notes');
  $('account-email').textContent = user.email;
  load();
});
