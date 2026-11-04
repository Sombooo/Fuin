'use strict';
// ═══════════════════════════════════════════════════════════════════
// FUIN BROWSER EXTENSION — CONTENT SCRIPT
//
// Sade ve kesintisiz otomatik doldurma (input içine ikon gömmeden,
// sayfadaki şifre göster/gizle 👁 ikonlarını kapatmadan çalışır):
// 1. Eklenti araç çubuğu menüsünden ("Doldur") veya klavye kısayoluyla
//    (Cmd+Shift+L / Ctrl+Shift+L) standart ve bölünmüş (Split Login)
//    formları otomatik doldurur.
// 2. Form gönderildiğinde yeni/güncel şifreleri Closed Shadow DOM
//    bildirimi ile kaydetmeyi önerir.
// ═══════════════════════════════════════════════════════════════════
(function () {
  const PROCESSED = new WeakSet();
  const FIELD_MAP = new WeakMap();
  let _pendingDirectFillEntryId = null;

  function isVisibleInput(el) {
    if (!el || el.disabled || el.readOnly || el.type === 'hidden') return false;
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  function findLoginForms() {
    const pwFields = Array.from(document.querySelectorAll('input[type="password"]')).filter(isVisibleInput);
    if (pwFields.length > 0) {
      return pwFields.filter(f => !PROCESSED.has(f));
    }

    // Bölünmüş giriş formları (Split login: Google/MS gibi sayfada şifre alanı olmayan 1. adım)
    return findStandaloneUsernameFields().filter(f => !PROCESSED.has(f));
  }

  function findStandaloneUsernameFields() {
    const candidates = Array.from(document.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input:not([type])'
    )).filter(isVisibleInput);

    const matches = [];
    const idNameRegex = /(?:user(?:name)?|login|email|identifier|auth|account|eposta|kullanici)/i;

    for (const c of candidates) {
      const autocomplete = (c.getAttribute('autocomplete') || '').toLowerCase();
      const name = c.getAttribute('name') || '';
      const id = c.getAttribute('id') || '';
      const placeholder = c.getAttribute('placeholder') || '';

      if (autocomplete.includes('username') || autocomplete.includes('email')) {
        matches.push(c);
        break; // Öncelikli eşleşme
      }
      if (idNameRegex.test(name) || idNameRegex.test(id) || idNameRegex.test(placeholder) || c.type === 'email') {
        matches.push(c);
        break;
      }
    }
    return matches;
  }

  function findUsernameField(pwField) {
    const form = pwField ? (pwField.closest('form') || document) : document;
    // Form veya document içindeki tüm olası kullanıcı adı inputlarını tara (gizli veya disabled olanlar da dahil)
    const allInputs = Array.from(form.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input[autocomplete*="user"], input[autocomplete*="email"], input:not([type]), input[name*="user"], input[name*="login"], input[name*="email"], input[id*="user"], input[id*="login"], input[id*="email"]'
    )).filter(c => c !== pwField && c.type !== 'password' && c.type !== 'hidden' && c.type !== 'checkbox' && c.type !== 'radio' && c.type !== 'submit');

    const idNameRegex = /(?:user(?:name)?|login|email|identifier|auth|account|eposta|kullanici)/i;

    // 1. Değeri dolu ve meta bilgisi kullanıcı adına uyan alanlar (En yüksek doğruluk)
    const withVal = allInputs.filter(c => c.value && c.value.trim().length > 0);
    const namedWithVal = withVal.find(c => {
      const meta = ((c.name || '') + ' ' + (c.id || '') + ' ' + (c.getAttribute('autocomplete') || '') + ' ' + (c.placeholder || '') + ' ' + (c.getAttribute('aria-label') || '')).toLowerCase();
      return c.type === 'email' || idNameRegex.test(meta) || (c.value && c.value.includes('@'));
    });
    if (namedWithVal) return namedWithVal;

    // 2. Değeri dolu herhangi bir aday (şifreye en yakın olan)
    if (withVal.length > 0) {
      if (pwField) {
        const all = Array.from(document.querySelectorAll('input'));
        const pwIdx = all.indexOf(pwField);
        let best = null, bestDist = Infinity;
        for (const c of withVal) {
          const idx = all.indexOf(c);
          const dist = Math.abs(pwIdx - idx);
          if (dist < bestDist) {
            bestDist = dist;
            best = c;
          }
        }
        if (best) return best;
      }
      return withVal[0];
    }

    // 3. Değeri henüz dolu değilse (görünür alanlara öncelik ver)
    const visibleCandidates = allInputs.filter(isVisibleInput);
    const visibleNamed = visibleCandidates.find(c => {
      const meta = ((c.name || '') + ' ' + (c.id || '') + ' ' + (c.getAttribute('autocomplete') || '') + ' ' + (c.placeholder || '') + ' ' + (c.getAttribute('aria-label') || '')).toLowerCase();
      return c.type === 'email' || idNameRegex.test(meta);
    });
    if (visibleNamed) return visibleNamed;

    return visibleCandidates[0] || allInputs[0] || null;
  }

  function createExtSvg(name, size = 14) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('width', String(size));
    svg.setAttribute('height', String(size));
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.style.display = 'block';
    svg.style.flexShrink = '0';

    const el = (tag, attrs) => {
      const node = document.createElementNS(ns, tag);
      for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
      return node;
    };

    if (name === 'hex') {
      svg.appendChild(el('polygon', { points: '12 2 20.66 7 20.66 17 12 22 3.34 17 3.34 7 12 2' }));
    } else if (name === 'globe') {
      svg.appendChild(el('circle', { cx: '12', cy: '12', r: '10' }));
      svg.appendChild(el('line', { x1: '2', y1: '12', x2: '22', y2: '12' }));
      svg.appendChild(el('path', { d: 'M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z' }));
    } else if (name === 'eye') {
      svg.appendChild(el('path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }));
      svg.appendChild(el('circle', { cx: '12', cy: '12', r: '3' }));
    } else if (name === 'eyeOff') {
      svg.appendChild(el('path', { d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24' }));
      svg.appendChild(el('line', { x1: '1', y1: '1', x2: '23', y2: '23' }));
    } else if (name === 'close') {
      svg.appendChild(el('line', { x1: '18', y1: '6', x2: '6', y2: '18' }));
      svg.appendChild(el('line', { x1: '6', y1: '6', x2: '18', y2: '18' }));
    }
    return svg;
  }

  function formatRevealError(err) {
    if (err === 'locked') return 'Fuin kilitli — önce masaüstü uygulamasını açın';
    if (err === 'busy') return 'Fuin şu an başka bir onay bekliyor';
    if (err === 'timeout') return 'Onay süresi doldu — tekrar deneyin';
    if (err === 'domain-mismatch') return 'Alan adı eşleşmedi';
    if (err === 'not-found') return 'Kayıt bulunamadı';
    return 'Fuin bağlantısı başarısız (' + err + ')';
  }

  function injectIcon(pwField) {
    PROCESSED.add(pwField);
    const host = document.createElement('fuin-ext-host');
    Object.assign(host.style, {
      position: 'absolute', top: '0', left: '0', width: '0', height: '0',
      pointerEvents: 'none', zIndex: '2147483647'
    });
    const shadow = host.attachShadow({ mode: 'closed' });
    // Fuin tasarım prensibi: input içine görünür ikon gömülmez (göz ikonlarını kapatmamak için).
    // Yalnızca Cmd+Shift+L çoklu hesap seçim menüsü için kapalı Shadow DOM çapa referansı tutulur.
    const icon = document.createElement('div');
    icon.className = 'fuin-ext-anchor';
    icon._targetField = pwField;
    icon.style.display = 'none';

    shadow.appendChild(icon);
    document.body.appendChild(host);
    FIELD_MAP.set(pwField, { host, shadow, icon });

    function cleanupIfDetached() {
      if (!document.body.contains(pwField) || !document.body.contains(host)) {
        window.removeEventListener('scroll', cleanupIfDetached, true);
        window.removeEventListener('resize', cleanupIfDetached);
        if (host.parentNode) host.remove();
        FIELD_MAP.delete(pwField);
      }
    }
    window.addEventListener('scroll', cleanupIfDetached, true);
    window.addEventListener('resize', cleanupIfDetached);
  }

  async function requestAndFill(targetField, icon, shadowRoot, matchId, domain) {
    let revealRes;
    try {
      revealRes = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: matchId, domain });
    } catch {
      revealRes = { error: 'native-host-unreachable' };
    }
    if (!revealRes || revealRes.error) {
      const err = revealRes?.error || 'unknown';
      if (err === 'denied' || err === 'navigation-cancelled') return;
      showMenu(icon, shadowRoot, [formatRevealError(err)]);
      return;
    }

    // TOTP Otomatik Kopyalama (Eğer kayıtta 2FA varsa)
    if (revealRes.totp) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(revealRes.totp);
        }
      } catch {}
    }

    fillForm(targetField, revealRes);
  }

  async function handleFillClick(targetField, icon, shadowRoot) {
    if (!shadowRoot) return;
    if (location.protocol === 'http:') {
      showMenu(icon, shadowRoot, ['Güvenli olmayan bağlantı (HTTP) — Fuin bu sayfada şifre doldurmaz']);
      return;
    }
    const domain = location.hostname;

    const directEntryId = _pendingDirectFillEntryId;
    _pendingDirectFillEntryId = null;
    if (directEntryId) {
      await requestAndFill(targetField, icon, shadowRoot, directEntryId, domain);
      return;
    }

    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
    } catch {
      res = { error: 'native-host-unreachable' };
    }

    if (!res || res.error === 'locked') return showMenu(icon, shadowRoot, ['Fuin kilitli — önce masaüstü kilidini açın']);
    if (res.error)                      return showMenu(icon, shadowRoot, ['Fuin masaüstü uygulamasına ulaşılamıyor']);
    if (!res.matches || !res.matches.length) return showMenu(icon, shadowRoot, ['Bu site için kayıtlı şifre yok']);

    // Tek eşleşme varsa seçim menüsünü atla, direkt izin iste
    if (res.matches.length === 1) {
      await requestAndFill(targetField, icon, shadowRoot, res.matches[0].id, domain);
      return;
    }

    showMenu(icon, shadowRoot, res.matches.map(m => m.username ? `${m.site} (${m.username})` : m.site), async (idx) => {
      const match = res.matches[idx];
      if (match) await requestAndFill(targetField, icon, shadowRoot, match.id, domain);
    });
  }

  function setFieldValue(el, val) {
    if (!el || val == null) return;
    try { el.focus(); } catch {}
    const nativeSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value')?.set;
    const protoSetter = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el), 'value')?.set;
    const setter = nativeSetter || protoSetter;
    if (setter) {
      setter.call(el, val);
    } else {
      el.value = val;
    }
    try {
      el.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: String(val) }));
    } catch {
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }
    el.dispatchEvent(new Event('change', { bubbles: true }));
    try { el.dispatchEvent(new Event('blur', { bubbles: true })); } catch {}
  }

  function fillForm(targetField, creds) {
    if (!creds) return;
    const form = targetField?.closest?.('form') || document;

    // 1. Kullanıcı adı alanlarını bul ve doldur
    const userField = targetField ? findUsernameField(targetField) : null;
    const allUsers = Array.from(form.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input[autocomplete*="user"], input[autocomplete*="email"], input[name*="user"], input[name*="login"], input[name*="email"], input[id*="user"], input[id*="login"], input[id*="email"], input:not([type])'
    )).filter(c => c.type !== 'password' && c.type !== 'checkbox' && c.type !== 'radio' && c.type !== 'submit');

    const visibleUsers = allUsers.filter(isVisibleInput);
    if (visibleUsers.length > 0) {
      visibleUsers.forEach(u => setFieldValue(u, creds.username));
    } else if (userField) {
      setFieldValue(userField, creds.username);
    }

    // 2. Şifre alanlarını bul ve doldur
    const allPws = Array.from(form.querySelectorAll('input[type="password"]'));
    const visiblePws = allPws.filter(isVisibleInput);
    if (visiblePws.length > 0) {
      visiblePws.forEach(p => setFieldValue(p, creds.password));
    } else if (targetField && targetField.type === 'password') {
      setFieldValue(targetField, creds.password);
    } else if (allPws.length > 0) {
      allPws.forEach(p => setFieldValue(p, creds.password));
    }
  }

  function showMenu(anchor, parent, items, onSelect) {
    if (!parent || parent === document.body) return;
    const existing = parent.querySelectorAll ? parent.querySelectorAll('.fuin-ext-menu') : [];
    existing.forEach(m => m.remove());
    const menu = document.createElement('div');
    menu.className = 'fuin-ext-menu';
    Object.assign(menu.style, {
      position: 'absolute', background: '#1f1c18', border: '1px solid #3d3830',
      borderRadius: '6px', fontFamily: 'monospace', fontSize: '12px', color: '#e8e2d8',
      zIndex: 2147483647, boxShadow: '0 6px 20px rgba(0,0,0,.45)', minWidth: '220px',
      maxWidth: '340px', overflow: 'hidden', pointerEvents: 'auto'
    });
    const targetEl = (anchor && anchor._targetField) ? anchor._targetField : anchor;
    const r = targetEl.getBoundingClientRect();
    menu.style.top  = (window.scrollY + r.bottom + 6) + 'px';
    menu.style.left = Math.max(8, window.scrollX + r.left) + 'px';

    items.forEach((label, idx) => {
      const row = document.createElement('div');
      row.textContent = label;
      Object.assign(row.style, {
        padding: '9px 12px',
        cursor: onSelect ? 'pointer' : 'default',
        color: onSelect ? '#e8e2d8' : '#a69d92',
        borderBottom: idx < items.length - 1 ? '1px solid #2a2720' : 'none',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        transition: 'background 0.1s ease, color 0.1s ease'
      });
      if (onSelect) {
        row.addEventListener('mouseenter', () => { row.style.background = '#2a2720'; row.style.color = '#6bb382'; });
        row.addEventListener('mouseleave', () => { row.style.background = 'transparent'; row.style.color = '#e8e2d8'; });
        row.addEventListener('click', (e) => {
          if (!e.isTrusted) return;
          onSelect(idx);
          menu.remove();
        });
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

  function findBestFillField() {
    const activeEl = document.activeElement && document.activeElement.matches && document.activeElement.matches('input') ? document.activeElement : null;
    if (activeEl && isVisibleInput(activeEl)) return activeEl;

    // 1. Önce sayfadaki görünür şifre alanını ara
    const allPws = Array.from(document.querySelectorAll('input[type="password"]'));
    const visiblePw = allPws.find(isVisibleInput);
    if (visiblePw) return visiblePw;

    // 2. Görünür bölünmüş giriş (split login) kullanıcı adı alanını ara
    const standalone = findStandaloneUsernameFields().find(isVisibleInput);
    if (standalone) return standalone;

    // 3. Herhangi bir görünür kullanıcı adı/e-posta alanını ara
    const allInputs = Array.from(document.querySelectorAll('input[type="text"], input[type="email"], input:not([type])'));
    const visibleUser = allInputs.find(isVisibleInput);
    if (visibleUser) return visibleUser;

    return allPws[0] || null;
  }

  function triggerFill() {
    const pwField = findBestFillField();
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

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'fuin-trigger-fill') {
      if (msg.entryId) _pendingDirectFillEntryId = msg.entryId;
      const pwField = findBestFillField();
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

  // Sayfa içi klavye kısayolu dinleyicisi:
  // Cmd+Shift+L (macOS) veya Ctrl+Shift+L (Windows/Linux)
  // Güvenlik: Yalnızca gerçek kullanıcı tuş vuruşları (e.isTrusted) kabul edilir;
  // zararlı sayfa betiklerinin sentetik KeyboardEvent ile şifre çalması engellenir.
  window.addEventListener('keydown', (e) => {
    if (!e.isTrusted) return;
    const hasModifier = e.metaKey || e.ctrlKey;
    const isKeyL = e.key === 'l' || e.key === 'L' || e.code === 'KeyL';

    if (hasModifier && e.shiftKey && isKeyL) {
      e.preventDefault();
      e.stopPropagation();
      triggerFill();
    }
  }, true);

  const _knownPasswordInputs = new WeakSet();

  function scan() {
    document.querySelectorAll('input[type="password"]').forEach(el => _knownPasswordInputs.add(el));
  }

  scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });

  // ── YENİ ŞİFRE KAYDETME / GÜNCELLEME BİLDİRİMİ (SAVE PROMPT) ────────
  let activeSaveHost = null;
  let lastProcessedSubmitTime = 0;
  let _lastTypedUsername = '';
  let _lastTypedPassword = '';
  let _passwordDirty = false;
  let _domainExcluded = false;
  const _dismissedKeys = new Set();

  function makeCredKey(username, password) {
    return `${String(username || '').trim().toLowerCase()}|${String(password || '')}`;
  }

  function markLocalDismissed(username, password) {
    if (password) {
      _dismissedKeys.add(makeCredKey(username, password));
      _dismissedKeys.add(makeCredKey('', password));
    }
    _passwordDirty = false;
    _lastTypedPassword = '';
  }

  function isLocallyDismissed(username, password) {
    if (_domainExcluded) return true;
    if (!password) return false;
    return _dismissedKeys.has(makeCredKey(username, password)) || _dismissedKeys.has(makeCredKey('', password));
  }

  document.addEventListener('input', (e) => {
    if (!e.isTrusted) return;
    const el = e.target;
    if (!el || el.tagName !== 'INPUT') return;
    if (el.type === 'password' || _knownPasswordInputs.has(el)) {
      if (el.type === 'password') _knownPasswordInputs.add(el);
      if (el.value) {
        _lastTypedPassword = el.value;
        _passwordDirty = true;
      } else {
        _passwordDirty = false;
      }
      const uField = findUsernameField(el);
      if (uField && uField.value && uField.value.trim()) {
        _lastTypedUsername = uField.value.trim();
      }
    } else {
      const meta = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('autocomplete') || '') + ' ' + (el.placeholder || '')).toLowerCase();
      const idNameRegex = /(?:user(?:name)?|login|email|identifier|auth|account|eposta|kullanici)/i;
      if (el.type === 'email' || idNameRegex.test(meta) || (el.value && el.value.includes('@'))) {
        if (el.value) _lastTypedUsername = el.value.trim();
      }
    }
  }, true);

  document.addEventListener('change', (e) => {
    if (!e.isTrusted) return;
    const el = e.target;
    if (!el || el.tagName !== 'INPUT') return;
    if (el.type === 'password' || _knownPasswordInputs.has(el)) {
      if (el.type === 'password') _knownPasswordInputs.add(el);
      if (el.value) {
        _lastTypedPassword = el.value;
        _passwordDirty = true;
      }
    } else if (el.value && (el.type === 'email' || el.value.includes('@') || /user|login|email/i.test(el.name || ''))) {
      _lastTypedUsername = el.value.trim();
    }
  }, true);

  function captureFormCredentials(contextEl) {
    const pwCandidates = Array.from(document.querySelectorAll('input')).filter(
      el => el.type === 'password' || _knownPasswordInputs.has(el)
    );
    const scopeForm = contextEl && contextEl.closest ? contextEl.closest('form') : null;
    const scopedPws = scopeForm ? pwCandidates.filter(f => scopeForm.contains(f)) : [];
    const pool = scopedPws.length > 0 ? scopedPws : pwCandidates;

    // Güvenlik: Gizli (görünmeyen) şifre alanları yalnızca kullanıcı gerçekten klavyeden yazdıysa (_passwordDirty) okunur
    const visibleFilledPw = pool.find(f => isVisibleInput(f) && f.value && f.value.length > 0);
    const hiddenDirtyPw = _passwordDirty ? pool.find(f => f.value && f.value.length > 0) : null;
    const filledPw = visibleFilledPw || hiddenDirtyPw || null;

    const password = (filledPw && filledPw.value)
      ? filledPw.value
      : (_passwordDirty ? _lastTypedPassword : '');
    if (!password || password.length < 2) return null;

    let username = '';
    const userField = filledPw ? findUsernameField(filledPw) : null;
    if (userField && userField.value && userField.value.trim()) {
      username = userField.value.trim();
    }
    if (!username && _lastTypedUsername) {
      username = _lastTypedUsername;
    }
    if (!username) {
      const anyEmailInput = Array.from(document.querySelectorAll('input')).find(
        i => isVisibleInput(i) && i.value && (i.value.includes('@') || i.type === 'email')
      );
      if (anyEmailInput) username = anyEmailInput.value.trim();
    }
    if (!username) {
      const standalone = findStandaloneUsernameFields()[0];
      if (standalone && standalone.value && standalone.value.trim()) {
        username = standalone.value.trim();
      }
    }

    return { username, password };
  }

  function isFuinInternalNode(node) {
    if (!node || typeof node !== 'object') return false;
    const tag = (node.tagName || '').toLowerCase();
    if (tag === 'fuin-save-prompt' || tag === 'fuin-ext-host') return true;
    if (typeof node.closest === 'function' && node.closest('fuin-save-prompt, fuin-ext-host')) return true;
    return false;
  }

  function isLikelySubmitControl(btn) {
    if (!btn || isFuinInternalNode(btn)) return false;
    const tag = (btn.tagName || '').toUpperCase();
    const typeAttr = (btn.getAttribute('type') || '').toLowerCase();
    if (typeAttr === 'reset' || typeAttr === 'checkbox' || typeAttr === 'radio') return false;

    const labelText = (
      (btn.textContent || '') + ' ' +
      (btn.value || '') + ' ' +
      (btn.getAttribute('aria-label') || '') + ' ' +
      (btn.getAttribute('title') || '') + ' ' +
      (btn.id || '') + ' ' +
      (btn.getAttribute('name') || '') + ' ' +
      (btn.getAttribute('data-cy') || '') + ' ' +
      (btn.getAttribute('data-testid') || '')
    ).replace(/\s+/g, ' ').trim();

    // Göz ikonu / şifre göster-gizle, kapatma, çerez, OAuth veya "şifremi unuttum" butonlarını her zaman hariç tut
    const nonSubmitRegex = /\b(show|hide|toggle|visibility|reveal|eye|göster|gizle|close|dismiss|kapat|cancel|iptal|vazgeç|cookie|çerez|forgot|unuttum|google|apple|facebook|github|discord|passkey)\b/i;
    if (nonSubmitRegex.test(labelText)) return false;

    // Açıkça submit tipindeki input veya button (ör. <button type="submit">, <input type="submit">)
    if (tag === 'INPUT' && typeAttr === 'submit') return true;
    if (tag === 'BUTTON' && typeAttr === 'submit') return true;

    // Form içindeki varsayılan <button> (type belirtilmemişse HTML standardı submit'tir, ancak boş ikon butonlarını ele)
    if (tag === 'BUTTON' && !typeAttr && btn.closest('form')) {
      const visibleLabel = ((btn.textContent || '') + (btn.getAttribute('aria-label') || '')).trim();
      if (visibleLabel.length > 0) return true;
    }

    // SPA formlarında (<form> olmadan kullanılan) açık giriş/kayıt/onay semantiği taşıyan butonlar
    const positiveSubmitRegex = /(log\s*in|sign\s*in|sign\s*up|register|create\s*account|continue|submit|next|confirm|save\s*password|change\s*password|update\s*password|reset\s*password|giriş|oturum\s*aç|kaydol|kayıt\s*ol|hesap\s*oluştur|devam|gönder|onayla|şifreyi\s*güncelle|şifreyi\s*değiştir)/i;
    return positiveSubmitRegex.test(labelText);
  }

  async function handleCandidateSubmission(target) {
    if (location.protocol !== 'https:' || _domainExcluded) return;
    if (isFuinInternalNode(target)) return;

    const creds = captureFormCredentials(target);
    if (!creds || !creds.password || creds.password.length < 2) return;
    if (isLocallyDismissed(creds.username, creds.password)) return;

    const now = Date.now();
    if (now - lastProcessedSubmitTime < 1000) return;
    lastProcessedSubmitTime = now;
    _passwordDirty = false;

    try {
      await chrome.runtime.sendMessage({
        type: 'fuin-form-submitted',
        username: creds.username,
        password: creds.password
      });
    } catch (err) {}
  }

  function showSavePrompt(candidate, result) {
    if (!candidate || !candidate.password) return;
    if (isLocallyDismissed(candidate.username, candidate.password)) return;

    if (activeSaveHost) {
      try { activeSaveHost.remove(); } catch {}
      activeSaveHost = null;
    }

    const host = document.createElement('fuin-save-prompt');
    Object.assign(host.style, {
      position: 'fixed',
      top: '16px',
      right: '16px',
      zIndex: '2147483647',
      pointerEvents: 'auto'
    });
    const shadow = host.attachShadow({ mode: 'closed' });

    const card = document.createElement('div');
    Object.assign(card.style, {
      width: '332px',
      background: '#222019',
      border: '1px solid #3d3830',
      borderRadius: '10px',
      boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#e8e2d8',
      padding: '16px',
      boxSizing: 'border-box'
    });

    const header = document.createElement('div');
    Object.assign(header.style, {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: '10px'
    });

    const logoRow = document.createElement('div');
    Object.assign(logoRow.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      fontSize: '12px',
      fontWeight: '700',
      letterSpacing: '0.8px',
      color: '#5a9a6e',
      fontFamily: 'monospace'
    });
    logoRow.appendChild(createExtSvg('hex', 13));
    const logoLabel = document.createElement('span');
    logoLabel.textContent = 'FUIN';
    logoRow.appendChild(logoLabel);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.appendChild(createExtSvg('close', 14));
    Object.assign(closeBtn.style, {
      background: 'transparent',
      border: 'none',
      color: '#a69d92',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      cursor: 'pointer',
      padding: '3px',
      borderRadius: '4px'
    });

    header.appendChild(logoRow);
    header.appendChild(closeBtn);
    card.appendChild(header);

    const isUpdate = result && result.action === 'update';
    const titleText = document.createElement('div');
    titleText.textContent = isUpdate ? 'Şifre Güncellensin mi?' : 'Hesap Kaydedilsin mi?';
    Object.assign(titleText.style, {
      fontSize: '14px',
      fontWeight: '600',
      color: '#e8e2d8',
      marginBottom: '6px'
    });
    card.appendChild(titleText);

    const rawHost = (candidate.domain || location.hostname || '').replace(/^www\./i, '');
    const cleanSite = rawHost ? (rawHost.charAt(0).toUpperCase() + rawHost.slice(1)) : 'Bu Site';

    const siteBadge = document.createElement('div');
    Object.assign(siteBadge.style, {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      background: '#1a1816',
      border: '1px solid #3d3830',
      borderRadius: '4px',
      padding: '4px 8px',
      fontSize: '11px',
      color: '#6bb382',
      fontWeight: '500',
      marginBottom: '12px'
    });
    siteBadge.appendChild(createExtSvg('globe', 12));
    const siteBadgeText = document.createElement('span');
    siteBadgeText.textContent = cleanSite;
    siteBadge.appendChild(siteBadgeText);
    card.appendChild(siteBadge);

    const fieldsBox = document.createElement('div');
    Object.assign(fieldsBox.style, {
      display: 'flex',
      flexDirection: 'column',
      gap: '8px',
      marginBottom: '14px'
    });

    // Kullanıcı Adı
    const userWrap = document.createElement('div');
    const userLabel = document.createElement('div');
    userLabel.textContent = 'Kullanıcı Adı';
    Object.assign(userLabel.style, {
      fontSize: '10px',
      fontWeight: '600',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
      color: '#a69d92',
      marginBottom: '3px'
    });
    const userInput = document.createElement('input');
    userInput.type = 'text';
    userInput.value = candidate.username || '';
    userInput.placeholder = 'Kullanıcı adı veya e-posta';
    Object.assign(userInput.style, {
      width: '100%',
      boxSizing: 'border-box',
      background: '#1a1816',
      border: '1px solid #3d3830',
      borderRadius: '5px',
      padding: '7px 10px',
      fontSize: '12px',
      color: '#e8e2d8',
      outline: 'none',
      fontFamily: 'inherit'
    });
    userInput.addEventListener('focus', () => { userInput.style.borderColor = '#5a9a6e'; });
    userInput.addEventListener('blur', () => { userInput.style.borderColor = '#3d3830'; });
    userWrap.appendChild(userLabel);
    userWrap.appendChild(userInput);
    fieldsBox.appendChild(userWrap);

    // Şifre
    const pwWrap = document.createElement('div');
    const pwLabel = document.createElement('div');
    pwLabel.textContent = 'Şifre';
    Object.assign(pwLabel.style, {
      fontSize: '10px',
      fontWeight: '600',
      textTransform: 'uppercase',
      letterSpacing: '0.5px',
      color: '#a69d92',
      marginBottom: '3px'
    });
    const pwRow = document.createElement('div');
    Object.assign(pwRow.style, {
      display: 'flex',
      alignItems: 'center',
      position: 'relative'
    });
    const pwInput = document.createElement('input');
    pwInput.type = 'password';
    pwInput.value = candidate.password || '';
    Object.assign(pwInput.style, {
      width: '100%',
      boxSizing: 'border-box',
      background: '#1a1816',
      border: '1px solid #3d3830',
      borderRadius: '5px',
      padding: '7px 32px 7px 10px',
      fontSize: '12px',
      color: '#e8e2d8',
      outline: 'none',
      fontFamily: 'monospace'
    });
    pwInput.addEventListener('focus', () => { pwInput.style.borderColor = '#5a9a6e'; });
    pwInput.addEventListener('blur', () => { pwInput.style.borderColor = '#3d3830'; });

    const eyeBtn = document.createElement('button');
    eyeBtn.type = 'button';
    eyeBtn.appendChild(createExtSvg('eye', 14));
    eyeBtn.title = 'Şifreyi göster / gizle';
    Object.assign(eyeBtn.style, {
      position: 'absolute',
      right: '7px',
      background: 'transparent',
      border: 'none',
      color: '#a69d92',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      cursor: 'pointer',
      padding: '3px'
    });
    eyeBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      const isMasked = pwInput.type === 'password';
      pwInput.type = isMasked ? 'text' : 'password';
      eyeBtn.replaceChildren(createExtSvg(isMasked ? 'eyeOff' : 'eye', 14));
      eyeBtn.style.color = isMasked ? '#6bb382' : '#a69d92';
    });

    pwRow.appendChild(pwInput);
    pwRow.appendChild(eyeBtn);
    pwWrap.appendChild(pwLabel);
    pwWrap.appendChild(pwRow);
    fieldsBox.appendChild(pwWrap);

    card.appendChild(fieldsBox);

    function dismissCurrentPrompt() {
      const curUser = userInput.value.trim();
      const curPw = pwInput.value || candidate.password;
      markLocalDismissed(curUser, curPw);
      userInput.value = '';
      pwInput.value = '';
      if (host.parentNode) host.remove();
      activeSaveHost = null;
      try {
        chrome.runtime.sendMessage({
          type: 'fuin-dismiss-save',
          username: curUser,
          password: curPw
        });
      } catch {}
    }

    closeBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      dismissCurrentPrompt();
    });

    const btnRow = document.createElement('div');
    Object.assign(btnRow.style, {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '6px'
    });

    const neverBtn = document.createElement('button');
    neverBtn.type = 'button';
    neverBtn.textContent = 'Bu Sitede Asla';
    neverBtn.title = 'Bu alan adı için bir daha şifre kaydetme önerisi gösterme';
    Object.assign(neverBtn.style, {
      background: 'transparent',
      border: 'none',
      color: '#a69d92',
      fontSize: '11px',
      fontWeight: '500',
      padding: '6px 4px',
      cursor: 'pointer',
      textDecoration: 'underline',
      textUnderlineOffset: '2px'
    });
    neverBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      _domainExcluded = true;
      markLocalDismissed(userInput.value.trim(), pwInput.value || candidate.password);
      userInput.value = '';
      pwInput.value = '';
      if (host.parentNode) host.remove();
      activeSaveHost = null;
      try { chrome.runtime.sendMessage({ type: 'fuin-exclude-domain' }); } catch {}
    });

    const rightBtns = document.createElement('div');
    Object.assign(rightBtns.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    });

    const notNowBtn = document.createElement('button');
    notNowBtn.type = 'button';
    notNowBtn.textContent = 'Şimdi Değil';
    Object.assign(notNowBtn.style, {
      background: '#2a2720',
      border: '1px solid #3d3830',
      color: '#a69d92',
      fontSize: '12px',
      fontWeight: '500',
      padding: '7px 11px',
      borderRadius: '5px',
      cursor: 'pointer'
    });
    notNowBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      dismissCurrentPrompt();
    });

    const saveBtn = document.createElement('button');
    saveBtn.type = 'button';
    saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet';
    Object.assign(saveBtn.style, {
      background: '#5a9a6e',
      border: '1px solid #5a9a6e',
      color: '#1a1816',
      fontSize: '12px',
      fontWeight: '600',
      padding: '7px 15px',
      borderRadius: '5px',
      cursor: 'pointer'
    });

    saveBtn.addEventListener('click', async (e) => {
      if (!e.isTrusted) return;
      const finalUsername = userInput.value.trim();
      const finalPassword = pwInput.value;
      if (!finalPassword) return;

      saveBtn.disabled = true;
      saveBtn.textContent = 'Kaydediliyor…';
      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'fuin-save-credential',
          domain: candidate.domain || location.hostname,
          username: finalUsername,
          password: finalPassword,
          updateEntryId: result ? result.entryId : null
        });
        if (resp && resp.ok) {
          markLocalDismissed(finalUsername, finalPassword);
          saveBtn.textContent = 'Kaydedildi! ✓';
          saveBtn.style.background = '#6bb382';
          userInput.value = '';
          pwInput.value = '';
          setTimeout(() => {
            if (host.parentNode) host.remove();
            activeSaveHost = null;
          }, 900);
        } else {
          saveBtn.textContent = (resp && resp.error === 'locked') ? 'Kasa kilitli' : 'Hata';
          setTimeout(() => { saveBtn.disabled = false; saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet'; }, 2000);
        }
      } catch {
        saveBtn.textContent = 'Bağlantı hatası';
        setTimeout(() => { saveBtn.disabled = false; saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet'; }, 2000);
      }
    });

    rightBtns.appendChild(notNowBtn);
    rightBtns.appendChild(saveBtn);
    btnRow.appendChild(neverBtn);
    btnRow.appendChild(rightBtns);
    card.appendChild(btnRow);

    shadow.appendChild(card);
    document.body.appendChild(host);
    activeSaveHost = host;

    setTimeout(() => {
      if (activeSaveHost === host && host.parentNode) {
        userInput.value = '';
        pwInput.value = '';
        host.remove();
        activeSaveHost = null;
      }
    }, 60000);
  }

  window.addEventListener('submit', (e) => {
    if (!e.isTrusted) return;
    handleCandidateSubmission(e.target);
  }, true);

  window.addEventListener('keydown', (e) => {
    if (!e.isTrusted || e.key !== 'Enter') return;
    if (isFuinInternalNode(e.target)) return;
    if (e.target && e.target.tagName === 'INPUT') {
      handleCandidateSubmission(e.target);
    }
  }, true);

  window.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    if (isFuinInternalNode(e.target)) return;
    const btn = e.target && e.target.closest
      ? e.target.closest('button, input[type="submit"], input[type="button"], [role="button"]')
      : null;
    if (btn && isLikelySubmitControl(btn)) {
      handleCandidateSubmission(btn);
    }
  }, true);

  // ── Sayfa açılışında bekleyen kaydetme bildirimi kontrolü (Redirect Sonrası) ──
  try {
    chrome.runtime.sendMessage({ type: 'fuin-get-pending-save' }, (resp) => {
      if (chrome.runtime?.lastError) return;
      if (resp && resp.hasPending && resp.candidate) {
        showSavePrompt(resp.candidate, resp.result);
      }
    });
  } catch {}

  // ── Background'dan gelen anlık kaydetme / kapatma bildirimi tetikleyicisi ──
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'fuin-trigger-save-prompt' && msg.candidate) {
      showSavePrompt(msg.candidate, msg.result);
      sendResponse?.({ ok: true });
      return;
    }
    if (msg.type === 'fuin-close-save-prompt') {
      if (activeSaveHost) {
        try { activeSaveHost.remove(); } catch {}
        activeSaveHost = null;
      }
      sendResponse?.({ ok: true });
    }
  });
})();
