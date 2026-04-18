/* theme-engine.js — farpa ecosystem theme switcher
   Fonte: farpa-reengenharia/02-design-system/01-tokens-e-temas.md v1.0
   NÃO modificar sem versionar e documentar no laboratório.
   ─────────────────────────────────────────────────────────────── */

// FOUC prevention — restaurar tema salvo IMEDIATAMENTE (script síncrono)
(function () {
  var saved = localStorage.getItem('farpa-tema');
  if (saved && /^theme-(claro|escuro|sepia|alto-contraste|trader)$/.test(saved)) {
    document.documentElement.className = saved;
    // Aplicar na body quando disponível
    document.addEventListener('DOMContentLoaded', function () {
      document.body.className = saved;
    });
  }
})();

document.addEventListener('DOMContentLoaded', function () {
  var TEMAS_VALIDOS = [
    'theme-claro',
    'theme-escuro',
    'theme-sepia',
    'theme-alto-contraste',
    'theme-trader',
  ];

  function aplicarTema(tema) {
    if (!TEMAS_VALIDOS.includes(tema)) return;
    document.body.className = tema;
    localStorage.setItem('farpa-tema', tema);

    // Atualizar aria-pressed do botão alto contraste
    var btnAC = document.getElementById('btn-alto-contraste');
    if (btnAC) {
      btnAC.setAttribute(
        'aria-pressed',
        String(tema === 'theme-alto-contraste')
      );
    }

    // Atualizar seletor de tema se existir
    var sel = document.getElementById('theme-select');
    if (sel) sel.value = tema;
  }

  // Restaurar tema salvo na body (complementa o script inline de FOUC)
  var temaAtual = localStorage.getItem('farpa-tema') || 'theme-claro';
  aplicarTema(temaAtual);

  // ── Botão Alto Contraste (sempre presente) ─────────────────────
  var btnAC = document.getElementById('btn-alto-contraste');
  if (btnAC) {
    btnAC.addEventListener('click', function () {
      var atual = document.body.className;
      var novoTema = atual === 'theme-alto-contraste'
        ? (localStorage.getItem('farpa-tema-anterior') || 'theme-claro')
        : 'theme-alto-contraste';

      if (atual !== 'theme-alto-contraste') {
        localStorage.setItem('farpa-tema-anterior', atual);
      }

      aplicarTema(novoTema);
    });

    btnAC.setAttribute(
      'aria-pressed',
      String(document.body.className === 'theme-alto-contraste')
    );
  }

  // ── Seletor de tema completo (opcional — 5 temas) ──────────────
  var themeSelect = document.getElementById('theme-select');
  if (themeSelect) {
    themeSelect.value = temaAtual;
    themeSelect.addEventListener('change', function () {
      aplicarTema(this.value);
    });
  }
});
