'use strict';
// ═══════════════════════════════════════════════════════════════════
// Sayfadaki giriş formlarını tespit eder, şifre alanının yanına bir
// "Fuin ile doldur" ikonu koyar. Tıklanınca background'dan mevcut
// domain için eşleşen kayıtları ister, birden fazlaysa seçim listesi
// gösterir, seçilen kayıt için background'dan gerçek şifreyi (reveal)
// ister ve formu doldurur.
// ═══════════════════════════════════════════════════════════════════
(function () {
  const PROCESSED = new WeakSet();
  const FIELD_MAP = new WeakMap();

  function findLoginForms() {
    const pwFields = Array.from(document.querySelectorAll('input[type="password"]'));
    return pwFields.filter(f => !PROCESSED.has(f));
  }

  function findUsernameField(pwField) {
    const form = pwField.closest('form') || document;
    const candidates = Array.from(form.querySelectorAll(
      'input[type="text"], input[type="email"], input:not([type])'
    ));
    // Şifre alanına DOM sırasında en yakın olanı tercih et
    let best = null, bestDist = Infinity;
    const all = Array.from(document.querySelectorAll('input'));
    const pwIdx = all.indexOf(pwField);
    for (const c of candidates) {
      const idx = all.indexOf(c);
      const dist = Math.abs(pwIdx - idx);
      if (dist < bestDist) { bestDist = dist; best = c; }
    }
    return best;
  }

  function injectIcon(pwField) {
    PROCESSED.add(pwField);
    const host = document.createElement('fuin-ext-host');
    Object.assign(host.style, {
      position: 'absolute', top: '0', left: '0', width: '100%', height: '100%', 
      pointerEvents: 'none', zIndex: '2147483647'
    });
    const shadow = host.attachShadow({ mode: 'closed' });
    const icon = document.createElement('div');
    icon.className = 'fuin-ext-icon';
    icon.textContent = '⬡';
    icon.title = 'Fuin ile doldur';
    const isHttp = location.protocol === 'http:';
    
    Object.assign(icon.style, {
      position: 'absolute', width: '22px', height: '22px', lineHeight: '22px',
      textAlign: 'center', cursor: 'pointer', fontSize: '14px',
      background: '#2a2520', color: isHttp ? '#ff4d4f' : '#f5f0e8', borderRadius: '3px',
      border: isHttp ? '1px solid #ff4d4f' : 'none',
      fontFamily: 'monospace', userSelect: 'none', pointerEvents: 'auto'
    });

    if (isHttp) {
      icon.title = 'Fuin: DİKKAT! Bu bağlantı güvenli değil (HTTP).';
    }
    shadow.appendChild(icon);
    document.body.appendChild(host);
    FIELD_MAP.set(pwField, { host, shadow, icon });

    function position() {
      if (!document.body.contains(pwField) || !document.body.contains(host)) {
        window.removeEventListener('scroll', position, true);
        window.removeEventListener('resize', position);
        if (host.parentNode) host.remove();
        FIELD_MAP.delete(pwField);
        return;
      }
      const r = pwField.getBoundingClientRect();
      icon.style.top  = (window.scrollY + r.top + (r.height - 22) / 2) + 'px';
      icon.style.left = (window.scrollX + r.right - 26) + 'px';
    }
    position();
    window.addEventListener('scroll', position, true);
    window.addEventListener('resize', position);

    icon.addEventListener('click', async (e) => {
      if (!e.isTrusted) return;
      e.preventDefault(); e.stopPropagation();
      await handleFillClick(pwField, icon, shadow);
    });
  }

  async function handleFillClick(pwField, icon, shadowRoot) {
    if (!shadowRoot) return;
    if (location.protocol === 'http:') {
      showMenu(icon, shadowRoot, ['⚠ Güvenli olmayan bağlantı — Fuin bu sayfada şifre doldurmaz']);
      return;
    }
    const domain = location.hostname;
    icon.textContent = '…';
    const res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
    icon.textContent = '⬡';

    if (res.error === 'locked')   return showMenu(icon, shadowRoot, ['Fuin kilitli — önce açın']);
    if (res.error)                return showMenu(icon, shadowRoot, ['Fuin\'e ulaşılamıyor']);
    if (!res.matches || !res.matches.length) return showMenu(icon, shadowRoot, ['Bu site için kayıt yok']);

    // Tek eşleşme varsa seçim menüsünü atla, direkt izin iste
    if (res.matches.length === 1) {
      const match = res.matches[0];
      const revealRes = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: match.id, domain });
      if (revealRes.error) { if (revealRes.error !== 'denied') alert('Fuin: ' + revealRes.error); return; }
      fillForm(pwField, revealRes);
      return;
    }

    showMenu(icon, shadowRoot, res.matches.map(m => m.username ? `${m.site} (${m.username})` : m.site), async (idx) => {
      const match = res.matches[idx];
      const revealRes = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: match.id, domain });
      if (revealRes.error) { alert('Fuin: ' + revealRes.error); return; }
      fillForm(pwField, revealRes);
    });
  }

  function fillForm(pwField, creds) {
    const userField = findUsernameField(pwField);
    const setVal = (el, val) => {
      if (!el || val == null) return;
      const proto = Object.getPrototypeOf(el);
      const setter = Object.getOwnPropertyDescriptor(proto, 'value').set;
      setter.call(el, val);
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    };
    setVal(userField, creds.username);
    setVal(pwField, creds.password);
  }

  function showMenu(anchor, parent, items, onSelect) {
    if (!parent || parent === document.body) return;
    const existing = parent.querySelectorAll ? parent.querySelectorAll('.fuin-ext-menu') : [];
    existing.forEach(m => m.remove());
    const menu = document.createElement('div');
    menu.className = 'fuin-ext-menu';
    Object.assign(menu.style, {
      position: 'absolute', background: '#fff', border: '1px solid #ccc',
      borderRadius: '4px', fontFamily: 'monospace', fontSize: '12px',
      zIndex: 2147483647, boxShadow: '0 2px 8px rgba(0,0,0,.15)', minWidth: '180px',
      pointerEvents: 'auto'
    });
    const r = anchor.getBoundingClientRect();
    menu.style.top  = (window.scrollY + r.bottom + 4) + 'px';
    menu.style.left = (window.scrollX + r.left - 160) + 'px';

    items.forEach((label, idx) => {
      const row = document.createElement('div');
      row.textContent = label;
      Object.assign(row.style, { padding: '8px 10px', cursor: onSelect ? 'pointer' : 'default', color: '#333' });
      if (onSelect) {
        row.addEventListener('mouseenter', () => row.style.background = '#f0f0f0');
        row.addEventListener('mouseleave', () => row.style.background = '#fff');
        row.addEventListener('click', () => { onSelect(idx); menu.remove(); });
      }
      menu.appendChild(row);
    });
    parent.appendChild(menu);
    const hostEl = parent.host;
    setTimeout(() => document.addEventListener('click', function close(e) {
      if (e.target !== hostEl && !menu.contains(e.target)) {
        menu.remove();
        document.removeEventListener('click', close);
      }
    }), 0);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'fuin-trigger-fill') {
      const activePw = document.activeElement && document.activeElement.matches && document.activeElement.matches('input[type="password"]') ? document.activeElement : null;
      const pwField = activePw || document.querySelector('input[type="password"]');
      if (pwField) {
        let entry = FIELD_MAP.get(pwField);
        if (!entry) {
          injectIcon(pwField);
          entry = FIELD_MAP.get(pwField);
        }
        if (entry && entry.shadow) {
          handleFillClick(pwField, entry.icon || pwField, entry.shadow);
        }
      }
    }
  });

  function scan() {
    findLoginForms().forEach(injectIcon);
  }

  scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });
})();
