// ═══════════════════════════════════════════════════════════════════
// FUIN HEALTH & HIBP SCANNER
// renderer/modules/healthScanner.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  async function checkPwned(pw, sha1hexFn) {
    if (!pw) return 0;
    const h = await sha1hexFn(pw);
    const pre = h.slice(0, 5), suf = h.slice(5);
    try {
      const r = await fetch(`https://api.pwnedpasswords.com/range/${pre}`, {
        cache: 'no-store',
        headers: { 'Add-Padding': 'true' }
      });
      if (!r.ok) return -1;
      for (const line of (await r.text()).split('\n')) {
        const [hh, c] = line.trim().split(':');
        if (hh === suf) return parseInt(c, 10);
      }
      return 0;
    } catch {
      return -1;
    }
  }

  function calculateHealthSummary({ entries, scores }) {
    const weak = entries.filter((_, i) => scores[i] <= 1);
    const medium = entries.filter((_, i) => scores[i] === 2);
    const strong = entries.filter((_, i) => scores[i] >= 3);
    const totpCount = entries.filter(e => e.totp).length;
    return { weak, medium, strong, totpCount };
  }

  window.FuinHealthScanner = {
    checkPwned,
    calculateHealthSummary,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinHealthScanner;
  }
})(typeof window !== 'undefined' ? window : globalThis);
