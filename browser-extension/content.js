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
      'input[type="text"], input[type="email"], input[type="tel"], input[autocomplete*="user"], input:not([type])'
    )).filter(c => {
      if (c === pwField || c.disabled || c.readOnly || c.type === 'hidden') return false;
      const rect = c.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    });
    const all = Array.from(document.querySelectorAll('input'));
    const pwIdx = all.indexOf(pwField);

    // Öncelikle şifre alanından ÖNCE gelen görünür input'ları tercih et
    let bestBefore = null, bestBeforeDist = Infinity;
    let bestAny = null, bestAnyDist = Infinity;
    for (const c of candidates) {
      const idx = all.indexOf(c);
      const dist = Math.abs(pwIdx - idx);
      if (idx < pwIdx && (pwIdx - idx) < bestBeforeDist) {
        bestBeforeDist = pwIdx - idx;
        bestBefore = c;
      }
      if (dist < bestAnyDist) {
        bestAnyDist = dist;
        bestAny = c;
      }
    }
    return bestBefore || bestAny;
  }

  function formatRevealError(err) {
    if (err === 'locked') return '🔒 Fuin kilitli — önce masaüstü uygulamasını açın';
    if (err === 'busy') return '⏳ Fuin şu an başka bir onay bekliyor';
    if (err === 'timeout') return '⏱ Onay süresi doldu — tekrar deneyin';
    if (err === 'domain-mismatch') return '⚠ Alan adı eşleşmedi';
    if (err === 'not-found') return '⚠ Kayıt bulunamadı';
    return '⚠ Fuin bağlantısı başarısız (' + err + ')';
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
      background: '#2a2520', color: isHttp ? '#ff4d4f' : '#c8a96e', borderRadius: '4px',
      border: isHttp ? '1px solid #ff4d4f' : '1px solid #3a332c',
      boxShadow: '0 1px 4px rgba(0,0,0,.25)',
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
        pwField.removeEventListener('focus', position);
        if (host.parentNode) host.remove();
        FIELD_MAP.delete(pwField);
        return;
      }
      const r = pwField.getBoundingClientRect();
      if (r.width < 40 || r.height < 14) {
        icon.style.display = 'none';
        return;
      }
      icon.style.display = 'block';
      icon.style.top  = (window.scrollY + r.top + (r.height - 22) / 2) + 'px';
      icon.style.left = (window.scrollX + r.right - 28) + 'px';
    }
    position();
    window.addEventListener('scroll', position, true);
    window.addEventListener('resize', position);
    pwField.addEventListener('focus', position);

    icon.addEventListener('click', async (e) => {
      if (!e.isTrusted) return;
      e.preventDefault(); e.stopPropagation();
      await handleFillClick(pwField, icon, shadow);
    });
  }

  async function requestAndFill(pwField, icon, shadowRoot, matchId, domain) {
    icon.textContent = '…';
    let revealRes;
    try {
      revealRes = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: matchId, domain });
    } catch {
      revealRes = { error: 'native-host-unreachable' };
    }
    icon.textContent = '⬡';
    if (!revealRes || revealRes.error) {
      const err = revealRes?.error || 'unknown';
      if (err === 'denied' || err === 'navigation-cancelled') return;
      showMenu(icon, shadowRoot, [formatRevealError(err)]);
      return;
    }
    fillForm(pwField, revealRes);
  }

  async function handleFillClick(pwField, icon, shadowRoot) {
    if (!shadowRoot) return;
    if (location.protocol === 'http:') {
      showMenu(icon, shadowRoot, ['⚠ Güvenli olmayan bağlantı — Fuin bu sayfada şifre doldurmaz']);
      return;
    }
    const domain = location.hostname;
    icon.textContent = '…';
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
    } catch {
      res = { error: 'native-host-unreachable' };
    }
    icon.textContent = '⬡';

    if (!res || res.error === 'locked') return showMenu(icon, shadowRoot, ['🔒 Fuin kilitli — önce açın']);
    if (res.error)                      return showMenu(icon, shadowRoot, ['⚠ Fuin masaüstü uygulamasına ulaşılamıyor']);
    if (!res.matches || !res.matches.length) return showMenu(icon, shadowRoot, ['Bu site için kayıtlı şifre yok']);

    // Tek eşleşme varsa seçim menüsünü atla, direkt izin iste
    if (res.matches.length === 1) {
      await requestAndFill(pwField, icon, shadowRoot, res.matches[0].id, domain);
      return;
    }

    showMenu(icon, shadowRoot, res.matches.map(m => m.username ? `${m.site} (${m.username})` : m.site), async (idx) => {
      const match = res.matches[idx];
      if (match) await requestAndFill(pwField, icon, shadowRoot, match.id, domain);
    });
  }

  function fillForm(pwField, creds) {
    const userField = findUsernameField(pwField);
    const setVal = (el, val) => {
      if (!el || val == null) return;
      el.focus();
      const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
      const protoSetter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value')?.set;
      const setter = nativeSetter || protoSetter;
      if (setter) {
        setter.call(el, val);
      } else {
        el.value = val;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      el.dispatchEvent(new Event('blur', { bubbles: true }));
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
      position: 'absolute', background: '#1f1c18', border: '1px solid #3a332c',
      borderRadius: '6px', fontFamily: 'monospace', fontSize: '12px', color: '#f5f0e8',
      zIndex: 2147483647, boxShadow: '0 6px 20px rgba(0,0,0,.45)', minWidth: '210px',
      maxWidth: '320px', overflow: 'hidden', pointerEvents: 'auto'
    });
    const r = anchor.getBoundingClientRect();
    menu.style.top  = (window.scrollY + r.bottom + 6) + 'px';
    menu.style.left = Math.max(8, window.scrollX + r.right - 210) + 'px';

    items.forEach((label, idx) => {
      const row = document.createElement('div');
      row.textContent = label;
      Object.assign(row.style, {
        padding: '9px 12px',
        cursor: onSelect ? 'pointer' : 'default',
        color: onSelect ? '#f5f0e8' : '#b8afa3',
        borderBottom: idx < items.length - 1 ? '1px solid #2d2722' : 'none',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis'
      });
      if (onSelect) {
        row.addEventListener('mouseenter', () => { row.style.background = '#2a2520'; row.style.color = '#c8a96e'; });
        row.addEventListener('mouseleave', () => { row.style.background = 'transparent'; row.style.color = '#f5f0e8'; });
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
