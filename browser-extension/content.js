'use strict';
// ═══════════════════════════════════════════════════════════════════
// FUIN BROWSER EXTENSION — CONTENT SCRIPT
//
// Sayfadaki giriş formlarını tespit eder:
// 1. Standart formlar: input[type="password"] yanına Fuin ikonu koyar.
// 2. Bölünmüş formlar (Split Login: Google, Microsoft, Apple vb.):
//    Sayfada hiç şifre alanı yoksa, kullanıcı adı / e-posta alanını
//    tespit edip ikonu oraya ekler ve 1. adımı otomatik doldurur.
//
// Özellikler:
// - Closed Shadow DOM ile DOM izolasyonu ve zararlı script koruması
// - e.isTrusted ile sentetik tıklama ve CSRF/Clickjacking engelleme
// - TOTP / 2FA kodu sağlandığında tek tıkla otomatik panoya kopyalama
// - Klavye kısayolu (Cmd+Shift+L / Ctrl+Shift+L) desteği
// - Fuin Tasarım Sistemi renkleri (#222019, #3d3830, #5a9a6e, #6bb382)
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
    icon.title = 'Fuin ile doldur (Kısayol: Cmd+Shift+L / Ctrl+Shift+L)';
    const isHttp = location.protocol === 'http:';
    
    // Fuin Warm Dark Design System Palette
    Object.assign(icon.style, {
      position: 'absolute', width: '22px', height: '22px', lineHeight: '22px',
      textAlign: 'center', cursor: 'pointer', fontSize: '14px',
      background: '#222019', color: isHttp ? '#ff4d4f' : '#5a9a6e', borderRadius: '4px',
      border: isHttp ? '1px solid #ff4d4f' : '1px solid #3d3830',
      boxShadow: '0 2px 6px rgba(0,0,0,.35)',
      fontFamily: 'monospace', userSelect: 'none', pointerEvents: 'auto',
      transition: 'background 0.15s ease, border-color 0.15s ease, color 0.15s ease'
    });

    if (isHttp) {
      icon.title = 'Fuin: DİKKAT! Bu bağlantı güvenli değil (HTTP).';
    } else {
      icon.addEventListener('mouseenter', () => {
        icon.style.background = '#2a2720';
        icon.style.borderColor = '#5a9a6e';
        icon.style.color = '#6bb382';
      });
      icon.addEventListener('mouseleave', () => {
        icon.style.background = '#222019';
        icon.style.borderColor = '#3d3830';
        icon.style.color = '#5a9a6e';
      });
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

  async function requestAndFill(targetField, icon, shadowRoot, matchId, domain) {
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

    // TOTP Otomatik Kopyalama (Eğer kayıtta 2FA varsa)
    if (revealRes.totp) {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(revealRes.totp);
          icon.textContent = '✓';
          icon.title = 'Fuin: Şifre dolduruldu & TOTP kopyalandı!';
          setTimeout(() => {
            icon.textContent = '⬡';
            icon.title = 'Fuin ile doldur (Kısayol: Cmd+Shift+L / Ctrl+Shift+L)';
          }, 2500);
        }
      } catch {}
    }

    fillForm(targetField, revealRes);
  }

  async function handleFillClick(targetField, icon, shadowRoot) {
    if (!shadowRoot) return;
    if (location.protocol === 'http:') {
      showMenu(icon, shadowRoot, ['⚠ Güvenli olmayan bağlantı — Fuin bu sayfada şifre doldurmaz']);
      return;
    }
    const domain = location.hostname;

    const directEntryId = _pendingDirectFillEntryId;
    _pendingDirectFillEntryId = null;
    if (directEntryId) {
      await requestAndFill(targetField, icon, shadowRoot, directEntryId, domain);
      return;
    }

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
  }

  function fillForm(targetField, creds) {
    if (targetField.type === 'password') {
      const userField = findUsernameField(targetField);
      setFieldValue(userField, creds.username);
      setFieldValue(targetField, creds.password);
    } else {
      // Bölünmüş form (1. adım username)
      setFieldValue(targetField, creds.username);
      // Eğer aynı anda sayfada bir şifre alanı açılmışsa onu da doldur
      const pwField = document.querySelector('input[type="password"]');
      if (pwField && isVisibleInput(pwField)) {
        setFieldValue(pwField, creds.password);
      }
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
    const r = anchor.getBoundingClientRect();
    menu.style.top  = (window.scrollY + r.bottom + 6) + 'px';
    menu.style.left = Math.max(8, window.scrollX + r.right - 220) + 'px';

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

  function triggerFill() {
    const activeEl = document.activeElement && document.activeElement.matches && document.activeElement.matches('input') ? document.activeElement : null;
    const pwField = activeEl || document.querySelector('input[type="password"]') || findStandaloneUsernameFields()[0];
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
      const activeEl = document.activeElement && document.activeElement.matches && document.activeElement.matches('input') ? document.activeElement : null;
      const pwField = activeEl || document.querySelector('input[type="password"]') || findStandaloneUsernameFields()[0];
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
  // capture: true ile sayfa scriptlerinin event'i yutması engellenir.
  window.addEventListener('keydown', (e) => {
    const hasModifier = e.metaKey || e.ctrlKey;
    const isKeyL = e.key === 'l' || e.key === 'L' || e.code === 'KeyL';

    if (hasModifier && e.shiftKey && isKeyL) {
      e.preventDefault();
      e.stopPropagation();
      triggerFill();
    }
  }, true);

  function scan() {
    findLoginForms().forEach(injectIcon);
  }

  scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });

  // ── YENİ ŞİFRE KAYDETME / GÜNCELLEME BİLDİRİMİ (SAVE PROMPT) ────────
  let activeSaveHost = null;
  let lastProcessedSubmitTime = 0;
  let _lastTypedUsername = '';
  let _lastTypedPassword = '';

  document.addEventListener('input', (e) => {
    const el = e.target;
    if (!el || el.tagName !== 'INPUT') return;
    if (el.type === 'password') {
      if (el.value) _lastTypedPassword = el.value;
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
    const el = e.target;
    if (!el || el.tagName !== 'INPUT') return;
    if (el.type === 'password' && el.value) {
      _lastTypedPassword = el.value;
    } else if (el.value && (el.type === 'email' || el.value.includes('@') || /user|login|email/i.test(el.name || ''))) {
      _lastTypedUsername = el.value.trim();
    }
  }, true);

  function captureFormCredentials(contextEl) {
    const allPws = Array.from(document.querySelectorAll('input[type="password"]'));
    const filledPw = allPws.find(f => f.value && f.value.length > 0) || allPws.find(isVisibleInput) || allPws[0];
    
    let password = (filledPw && filledPw.value) ? filledPw.value : _lastTypedPassword;
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
      const anyEmailInput = Array.from(document.querySelectorAll('input')).find(i => i.value && (i.value.includes('@') || i.type === 'email'));
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

  async function handleCandidateSubmission(target) {
    if (location.protocol !== 'https:') return;
    const creds = captureFormCredentials(target);
    if (!creds || !creds.password || creds.password.length < 2) return;

    const now = Date.now();
    if (now - lastProcessedSubmitTime < 1000) return;
    lastProcessedSubmitTime = now;

    try {
      await chrome.runtime.sendMessage({
        type: 'fuin-form-submitted',
        username: creds.username,
        password: creds.password
      });
    } catch (err) {}
  }

  function showSavePrompt(candidate, result) {
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
      width: '320px',
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
      color: '#5a9a6e',
      fontFamily: 'monospace'
    });
    logoRow.textContent = '⬡ FUIN';

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    Object.assign(closeBtn.style, {
      background: 'transparent',
      border: 'none',
      color: '#a69d92',
      fontSize: '13px',
      cursor: 'pointer',
      padding: '2px 4px',
      lineHeight: '1'
    });
    closeBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      host.remove();
      activeSaveHost = null;
      try { chrome.runtime.sendMessage({ type: 'fuin-dismiss-save' }); } catch {}
    });

    header.appendChild(logoRow);
    header.appendChild(closeBtn);
    card.appendChild(header);

    const isUpdate = result.action === 'update';
    const titleText = document.createElement('div');
    titleText.textContent = isUpdate ? 'Şifre Güncellensin mi?' : 'Hesap Kaydedilsin mi?';
    Object.assign(titleText.style, {
      fontSize: '14px',
      fontWeight: '600',
      color: '#e8e2d8',
      marginBottom: '4px'
    });
    card.appendChild(titleText);

    const rawHost = location.hostname.replace(/^www\./i, '');
    const cleanSite = rawHost ? (rawHost.charAt(0).toUpperCase() + rawHost.slice(1)) : 'Bu Site';

    const siteBadge = document.createElement('div');
    Object.assign(siteBadge.style, {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      background: '#1a1816',
      border: '1px solid #3d3830',
      borderRadius: '4px',
      padding: '3px 8px',
      fontSize: '11px',
      color: '#6bb382',
      fontWeight: '500',
      marginBottom: '12px'
    });
    siteBadge.textContent = '🌐 ' + cleanSite;
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
    eyeBtn.textContent = '👁';
    eyeBtn.title = 'Şifreyi göster / gizle';
    Object.assign(eyeBtn.style, {
      position: 'absolute',
      right: '6px',
      background: 'transparent',
      border: 'none',
      color: '#a69d92',
      fontSize: '12px',
      cursor: 'pointer',
      padding: '2px',
      lineHeight: '1'
    });
    eyeBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      const isMasked = pwInput.type === 'password';
      pwInput.type = isMasked ? 'text' : 'password';
      eyeBtn.textContent = isMasked ? '👁‍🗨' : '👁';
      eyeBtn.style.color = isMasked ? '#6bb382' : '#a69d92';
    });

    pwRow.appendChild(pwInput);
    pwRow.appendChild(eyeBtn);
    pwWrap.appendChild(pwLabel);
    pwWrap.appendChild(pwRow);
    fieldsBox.appendChild(pwWrap);

    card.appendChild(fieldsBox);

    const btnRow = document.createElement('div');
    Object.assign(btnRow.style, {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'flex-end',
      gap: '8px'
    });

    const notNowBtn = document.createElement('button');
    notNowBtn.textContent = 'Şimdi Değil';
    Object.assign(notNowBtn.style, {
      background: '#2a2720',
      border: '1px solid #3d3830',
      color: '#a69d92',
      fontSize: '12px',
      fontWeight: '500',
      padding: '7px 12px',
      borderRadius: '5px',
      cursor: 'pointer'
    });
    notNowBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      host.remove();
      activeSaveHost = null;
      try { chrome.runtime.sendMessage({ type: 'fuin-dismiss-save' }); } catch {}
    });

    const saveBtn = document.createElement('button');
    saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet';
    Object.assign(saveBtn.style, {
      background: '#5a9a6e',
      border: '1px solid #5a9a6e',
      color: '#1a1816',
      fontSize: '12px',
      fontWeight: '600',
      padding: '7px 16px',
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
          updateEntryId: result.entryId
        });
        if (resp && resp.ok) {
          saveBtn.textContent = 'Kaydedildi! ✓';
          saveBtn.style.background = '#6bb382';
          setTimeout(() => {
            if (host.parentNode) host.remove();
            activeSaveHost = null;
          }, 1200);
        } else {
          saveBtn.textContent = 'Hata';
          setTimeout(() => { saveBtn.disabled = false; saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet'; }, 2000);
        }
      } catch {
        saveBtn.textContent = 'Bağlantı hatası';
      }
    });

    btnRow.appendChild(notNowBtn);
    btnRow.appendChild(saveBtn);
    card.appendChild(btnRow);

    shadow.appendChild(card);
    document.body.appendChild(host);
    activeSaveHost = host;

    setTimeout(() => {
      if (activeSaveHost === host && host.parentNode) {
        host.remove();
        activeSaveHost = null;
      }
    }, 25000);
  }

  window.addEventListener('submit', (e) => {
    handleCandidateSubmission(e.target);
  }, true);

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      handleCandidateSubmission(e.target);
    }
  }, true);

  window.addEventListener('click', (e) => {
    const btn = e.target && e.target.closest ? e.target.closest('button, input[type="submit"], [role="button"], a[role="button"], [class*="login"], [class*="submit"], [id*="login"], [id*="submit"]') : null;
    if (btn) {
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

  // ── Background'dan gelen anlık kaydetme bildirimi tetikleyicisi (SPA veya anlık) ──
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'fuin-trigger-save-prompt' && msg.candidate) {
      showSavePrompt(msg.candidate, msg.result);
      sendResponse?.({ ok: true });
    }
  });
})();
