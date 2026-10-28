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
    const form = pwField.closest('form') || document;
    const candidates = Array.from(form.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input[autocomplete*="user"], input:not([type])'
    )).filter(c => c !== pwField && isVisibleInput(c));

    const all = Array.from(document.querySelectorAll('input'));
    const pwIdx = all.indexOf(pwField);

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

  function captureFormCredentials(contextEl) {
    const root = (contextEl && contextEl.closest && contextEl.closest('form')) || document;
    const pwField = root.querySelector('input[type="password"]');
    if (!pwField || !pwField.value) return null;

    const userField = findUsernameField(pwField) || findStandaloneUsernameFields()[0];
    const username = userField && userField.value ? userField.value.trim() : '';
    const password = pwField.value;

    return { username, password };
  }

  async function handleCandidateSubmission(target) {
    if (location.protocol !== 'https:') return;
    const now = Date.now();
    if (now - lastProcessedSubmitTime < 1500) return; // 1.5s debounce

    const creds = captureFormCredentials(target);
    if (!creds || !creds.password || creds.password.length < 2) return;

    lastProcessedSubmitTime = now;

    let res;
    try {
      res = await chrome.runtime.sendMessage({
        type: 'fuin-check-save-candidate',
        username: creds.username,
        password: creds.password
      });
    } catch {
      return;
    }

    if (res && res.shouldPrompt) {
      showSavePrompt(creds, res);
    }
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
      width: '310px',
      background: '#222019',
      border: '1px solid #3d3830',
      borderRadius: '8px',
      boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      color: '#e8e2d8',
      padding: '14px',
      boxSizing: 'border-box'
    });

    const header = document.createElement('div');
    Object.assign(header.style, {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      marginBottom: '8px'
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
    });

    header.appendChild(logoRow);
    header.appendChild(closeBtn);
    card.appendChild(header);

    const isUpdate = result.action === 'update';
    const titleText = document.createElement('div');
    titleText.textContent = isUpdate ? 'Şifreniz Güncellensin mi?' : 'Hesap Kaydedilsin mi?';
    Object.assign(titleText.style, {
      fontSize: '13px',
      fontWeight: '600',
      color: '#e8e2d8',
      marginBottom: '4px'
    });
    card.appendChild(titleText);

    const descText = document.createElement('div');
    descText.textContent = `${location.hostname}${candidate.username ? ' (' + candidate.username + ')' : ''}`;
    Object.assign(descText.style, {
      fontSize: '11px',
      color: '#a69d92',
      marginBottom: '12px',
      overflow: 'hidden',
      textOverflow: 'ellipsis',
      whiteSpace: 'nowrap'
    });
    card.appendChild(descText);

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
      fontSize: '11px',
      fontWeight: '500',
      padding: '6px 12px',
      borderRadius: '4px',
      cursor: 'pointer'
    });
    notNowBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      host.remove();
      activeSaveHost = null;
    });

    const saveBtn = document.createElement('button');
    saveBtn.textContent = isUpdate ? 'Güncelle' : 'Kaydet';
    Object.assign(saveBtn.style, {
      background: '#5a9a6e',
      border: '1px solid #5a9a6e',
      color: '#1a1816',
      fontSize: '11px',
      fontWeight: '600',
      padding: '6px 14px',
      borderRadius: '4px',
      cursor: 'pointer'
    });

    saveBtn.addEventListener('click', async (e) => {
      if (!e.isTrusted) return;
      saveBtn.disabled = true;
      saveBtn.textContent = 'Kaydediliyor…';
      try {
        const resp = await chrome.runtime.sendMessage({
          type: 'fuin-save-credential',
          username: candidate.username,
          password: candidate.password,
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
    if (e.key === 'Enter' && e.target && e.target.tagName === 'INPUT') {
      setTimeout(() => handleCandidateSubmission(e.target), 100);
    }
  }, true);

  window.addEventListener('click', (e) => {
    if (e.target && (e.target.type === 'submit' || (e.target.matches && e.target.matches('button, input[type="submit"], [role="button"]')))) {
      setTimeout(() => handleCandidateSubmission(e.target), 100);
    }
  }, true);
})();
