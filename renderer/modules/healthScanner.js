// ═══════════════════════════════════════════════════════════════════
// FUIN HEALTH & HIBP SCANNER
// renderer/modules/healthScanner.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  const HIBP_TIMEOUT_MS = 8000;
  const HIBP_MAX_RESPONSE_CHARS = 262144;

  async function checkPwned(pw, sha1hexFn) {
    if (!pw) return 0;
    const h = String(await sha1hexFn(pw)).toUpperCase();
    const pre = h.slice(0, 5), suf = h.slice(5);
    if (!/^[0-9A-F]{5}$/.test(pre)) return -1;

    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => {
      try { controller.abort(); } catch {}
    }, HIBP_TIMEOUT_MS) : null;

    try {
      const r = await fetch(`https://api.pwnedpasswords.com/range/${pre}`, {
        cache: 'no-store',
        redirect: 'error',
        headers: { 'Add-Padding': 'true' },
        signal: controller ? controller.signal : undefined
      });
      if (!r.ok) return -1;
      if (r.url && !r.url.startsWith('https://api.pwnedpasswords.com/')) return -1;
      const text = await r.text();
      if (typeof text !== 'string' || text.length > HIBP_MAX_RESPONSE_CHARS) return -1;
      for (const line of text.split('\n')) {
        const [hh, c] = line.trim().split(':');
        if (hh === suf) {
          const parsed = parseInt(c, 10);
          return Number.isFinite(parsed) && parsed >= 0 ? parsed : -1;
        }
      }
      return 0;
    } catch {
      return -1;
    } finally {
      if (timer) clearTimeout(timer);
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
