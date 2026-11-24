// Loaded in <head> so the theme is applied before the page paints.
(function () {
  const root = document.documentElement;
  let saved = null;
  try {
    saved = localStorage.getItem('theme');
  } catch {}
  const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
  root.dataset.theme = saved || (prefersLight ? 'light' : 'dark');

  document.addEventListener('DOMContentLoaded', function () {
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    button.addEventListener('click', function () {
      const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
      root.dataset.theme = next;
      try {
        localStorage.setItem('theme', next);
      } catch {}
    });
  });
})();
