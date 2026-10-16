// ═══════════════════════════════════════════════════════════════════
// FUIN RECOVERY & HARD RESET UI CONTROLLER
// renderer/modules/recoveryController.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  function generateRecoveryKey() {
    const arr = crypto.getRandomValues(new Uint8Array(32));
    return Array.from(arr)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase()
      .match(/.{1,8}/g)
      .join('-');
  }

  function showForgotMsg(text, type) {
    const el = document.getElementById('forgotMsg');
    if (!el) return;
    const colors = {
      green: 'rgba(61,107,79,.08)',
      red: 'rgba(160,52,42,.08)',
      amber: 'rgba(176,112,32,.08)',
    };
    const borders = {
      green: 'rgba(61,107,79,.2)',
      red: 'rgba(160,52,42,.2)',
      amber: 'rgba(176,112,32,.2)',
    };
    el.style.display = 'block';
    el.style.color = `var(--${type})`;
    el.style.background = colors[type];
    el.style.border = `1px solid ${borders[type]}`;
    el.textContent = text;
  }

  function resetForgotModalUI(t) {
    const msgEl = document.getElementById('forgotMsg');
    if (msgEl) {
      msgEl.style.display = 'none';
      msgEl.textContent = '';
    }
    const newPwGroup = document.getElementById('newPwGroup');
    if (newPwGroup) newPwGroup.style.display = 'none';
    const forgotBtn = document.getElementById('forgotBtn');
    if (forgotBtn) forgotBtn.textContent = t('forgotVerifyBtn');
    const recInp = document.getElementById('recoveryInp');
    if (recInp) recInp.value = '';
    const newPwInp = document.getElementById('newPwInp');
    if (newPwInp) newPwInp.value = '';
    document.getElementById('forgotOverlay')?.classList.add('open');
  }

  window.FuinRecoveryUI = {
    generateRecoveryKey,
    showForgotMsg,
    resetForgotModalUI,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinRecoveryUI;
  }
})(typeof window !== 'undefined' ? window : globalThis);
