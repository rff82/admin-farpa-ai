/* icons.js — SVG line icons (Lucide-style) para o ecossistema farpa
   v1.0 · 2026-04-18
   Uso: <span data-icon="dumbbell"></span> — substituído no DOMContentLoaded.
   Ou: icon('dumbbell') retorna string SVG.
   Regra: nunca emojis em UI funcional (02-design-system/02-identidade-visual.md). */

(function() {
  'use strict';

  const S = 'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"';
  const V = 'xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" viewBox="0 0 24 24"';

  const ICONS = {
    // Ação / navegação
    'arrow-left':    `<path d="M19 12H5M12 19l-7-7 7-7"/>`,
    'arrow-right':   `<path d="M5 12h14M12 5l7 7-7 7"/>`,
    'arrow-up':      `<path d="M12 19V5M5 12l7-7 7 7"/>`,
    'arrow-down':    `<path d="M12 5v14M19 12l-7 7-7-7"/>`,
    'chevron-right': `<path d="m9 18 6-6-6-6"/>`,
    'plus':          `<path d="M12 5v14M5 12h14"/>`,
    'x':             `<path d="M18 6 6 18M6 6l12 12"/>`,
    'check':         `<path d="M20 6 9 17l-5-5"/>`,
    'check-circle':  `<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>`,
    'alert':         `<circle cx="12" cy="12" r="10"/><path d="M12 8v4M12 16h.01"/>`,

    // Usuário / conta
    'user':          `<circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 0 0-16 0"/>`,
    'users':         `<circle cx="9" cy="8" r="4"/><path d="M17 21a7 7 0 0 0-14 0"/><circle cx="17" cy="8" r="3"/><path d="M21 21a5 5 0 0 0-5-5"/>`,
    'user-plus':     `<circle cx="10" cy="8" r="4"/><path d="M16 21a7 7 0 0 0-14 0"/><path d="M19 8v6M22 11h-6"/>`,
    'eye':           `<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>`,
    'eye-off':       `<path d="M9.88 9.88A3 3 0 0 0 14.12 14.12"/><path d="M10.73 5.08A10.4 10.4 0 0 1 12 5c6.5 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68"/><path d="M6.61 6.61A13.5 13.5 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 5.39-1.61"/><path d="M2 2l20 20"/>`,
    'log-out':       `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5M21 12H9"/>`,
    'log-in':        `<path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><path d="m10 17 5-5-5-5M15 12H3"/>`,
    'home':          `<path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"/><path d="M9 22V12h6v10"/>`,
    'external-link': `<path d="M15 3h6v6"/><path d="M10 14 21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>`,
    'activity':      `<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>`,
    'shield':        `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>`,

    // Produto farpa Forte
    'dumbbell':      `<path d="m6.5 6.5 11 11"/><path d="m21 21-1.5-1.5"/><path d="M3.5 3.5 5 5"/><path d="M6 4 4 6l3 3 2-2Z"/><path d="m20 16-2 2-3-3 2-2Z"/><path d="m14.5 4.5 5 5"/><path d="m4.5 14.5 5 5"/>`,
    'calendar':      `<rect width="18" height="18" x="3" y="4" rx="2"/><path d="M16 2v4M8 2v4M3 10h18"/>`,
    'credit-card':   `<rect width="20" height="14" x="2" y="5" rx="2"/><path d="M2 10h20"/>`,
    'trending-up':   `<path d="m22 7-8.5 8.5-5-5L2 17"/><path d="M16 7h6v6"/>`,
    'activity':      `<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>`,
    'heart-pulse':   `<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78Z"/><path d="M3.22 12h3.1L8 8.5 11 14l2.5-6.5L15.5 12h5.3"/>`,
    'sparkles':      `<path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1"/>`,
    'target':        `<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>`,
    'bot':           `<rect width="18" height="10" x="3" y="11" rx="2"/><path d="M12 5v6M8 16h.01M16 16h.01M5 18v2M19 18v2"/><path d="M10 5a2 2 0 1 1 4 0"/>`,

    // Interface
    'grid':          `<rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/>`,
    'settings':      `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h0a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h0a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>`,
    'search':        `<circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/>`,
    'menu':          `<path d="M3 12h18M3 6h18M3 18h18"/>`,
    'bell':          `<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.94 1.94 0 0 0 3.4 0"/>`,
    'contrast':      `<circle cx="12" cy="12" r="10"/><path d="M12 2v20" fill="currentColor"/><path d="M12 2a10 10 0 0 0 0 20z" fill="currentColor"/>`,
    'moon':          `<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/>`,
    'sun':           `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>`,

    // Dados / stats
    'chart-bar':     `<path d="M3 3v18h18"/><rect width="4" height="7" x="7" y="10"/><rect width="4" height="12" x="15" y="5"/>`,
    'wallet':        `<path d="M21 12V7H5a2 2 0 0 1 0-4h14v4"/><path d="M3 5v14a2 2 0 0 0 2 2h16v-5"/><path d="M18 12a2 2 0 0 0 0 4h4v-4Z"/>`,
    'clock':         `<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>`,
    'inbox':         `<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11Z"/>`,
    'edit':          `<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5Z"/>`,
    'scale':         `<path d="M4 3h16l-2 5H6Z"/><path d="M12 8v13"/><path d="M4 21h16"/><path d="m6 13 3 4H3Z"/>`,
    'flame':         `<path d="M8.5 14.5A2.5 2.5 0 0 0 11 17c1.9 0 3-1.5 3-3.5 0-2-1.5-3.5-3-5-1 2-2.5 3-3.5 3.5-1 .5-1 1.5-1 1.5Z"/><path d="M12 2c1 3 2.5 4 4 5.5 1.5 1.5 3 3 3 6.5 0 3.9-3.1 7-7 7s-7-3.1-7-7c0-1.5.5-3 1-4"/>`,
    'loader':        `<path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>`,
  };

  function buildSvg(name, extraClass) {
    const d = ICONS[name];
    if (!d) return '';
    return `<svg class="icon${extraClass ? ' ' + extraClass : ''}" data-icon-name="${name}" ${V} ${S}>${d}</svg>`;
  }

  // API global
  window.farpaIcon = buildSvg;

  // Auto-hidrata elementos com [data-icon]
  function hydrate(root = document) {
    root.querySelectorAll('[data-icon]').forEach((el) => {
      const name = el.getAttribute('data-icon');
      if (!ICONS[name]) return;
      el.innerHTML = buildSvg(name);
      el.setAttribute('aria-hidden', 'true');
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => hydrate());
  } else {
    hydrate();
  }
  window.farpaIconsHydrate = hydrate;
})();
