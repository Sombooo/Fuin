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
  const idNameRegex = /(?:user(?:name)?|log[iİ]n|e-?ma[iİ]l|[iİ]dent[iİ]f[iİ]er|auth|account|e-?posta|kullan[ıiIİ]c[ıiIİ]|telefon|phone|member|[üÜu]ye|m[üÜu][şŞs]ter[iİ]|k[iİ]ml[iİ]k|n[iİ]ck)/i;

  function sendRuntimeMessage(payload) {
    return new Promise((resolve) => {
      let settled = false;
      const safeResolve = (val) => {
        if (!settled) {
          settled = true;
          resolve(val);
        }
      };
      try {
        const api = (typeof browser !== 'undefined' && browser.runtime && typeof browser.runtime.sendMessage === 'function')
          ? browser
          : chrome;
        if (!api || !api.runtime || typeof api.runtime.sendMessage !== 'function') {
          safeResolve(null);
          return;
        }
        const maybePromise = api.runtime.sendMessage(payload, (resp) => {
          if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.lastError) {
            safeResolve(null);
            return;
          }
          safeResolve(resp !== undefined ? resp : null);
        });
        if (maybePromise && typeof maybePromise.then === 'function') {
          maybePromise.then((res) => safeResolve(res !== undefined ? res : null))
            .catch(() => safeResolve(null));
        }
      } catch {
        safeResolve(null);
      }
    });
  }

  const MULTI_TENANT_SUFFIXES = new Set([
    'github.io', 'pages.dev', 'vercel.app', 'netlify.app', 'gitlab.io',
    'herokuapp.com', 'firebaseapp.com', 'fly.dev', 'render.com', 'onrender.com',
    'workers.dev', 'web.app', 'azurewebsites.net', 'cloudfront.net', 'railway.app',
    'up.railway.app', 'deno.dev', 'appspot.com', 'surge.sh', 'amplifyapp.com',
    'elasticbeanstalk.com', 's3.amazonaws.com', 'fastly.net', 'b-cdn.net',
    'ngrok-free.app', 'ngrok.io', 'glitch.me', 'myshopify.com',
    '000webhostapp.com', 'pipedream.net', 'pantheonsite.io',
    'wixsite.com', 'ghost.io', 'substack.com', 'azureedge.net', 'trafficmanager.net',
    'blob.core.windows.net', 'wordpress.com', 'blogspot.com', 'tumblr.com',
    'itch.io', 'notion.site', 'webflow.io', 'replit.app', 'run.app',
    'hf.space', 'trycloudflare.com', 'pythonanywhere.com'
  ]);

  const COMPOUND_CCTLD_SLDS = new Set([
    'co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'gob',
    'mil', 'biz', 'info', 'gen', 'web', 'nom', 'bel', 'pol', 'k12', 'av',
    'dr', 'bbs', 'tsk', 'kep', 'me', 'firm', 'ind'
  ]);

  function normExtHost(h) {
    let s = String(h || '').trim().toLowerCase();
    if (!s) return '';
    if (!/^https?:\/\//.test(s)) s = 'https://' + s;
    try {
      return new URL(s).hostname.replace(/^www\./, '').replace(/\.+$/, '');
    } catch {
      const raw = String(h || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0];
      if (raw.startsWith('[')) {
        const endBracket = raw.indexOf(']');
        return (endBracket !== -1 ? raw.slice(0, endBracket + 1) : raw).replace(/\.+$/, '');
      }
      if ((raw.match(/:/g) || []).length > 1) return raw.replace(/\.+$/, '');
      return raw.split(':')[0].trim().replace(/\.+$/, '');
    }
  }

  function isIpLiteralHostExt(h) {
    if (!h) return false;
    return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.includes(':') || h.startsWith('[');
  }

  function isCompoundCcTldSuffixExt(h) {
    const parts = String(h || '').split('.');
    if (parts.length !== 2) return false;
    return COMPOUND_CCTLD_SLDS.has(parts[0]) && /^[a-z]{2}$/.test(parts[1]);
  }

  function isMultiTenantHostExt(h) {
    if (!h) return false;
    if (MULTI_TENANT_SUFFIXES.has(h)) return true;
    for (const s of MULTI_TENANT_SUFFIXES) {
      if (h.endsWith('.' + s)) return true;
    }
    return false;
  }

  function getBaseSiteExt(h) {
    const clean = normExtHost(h);
    if (!clean) return '';
    if (clean === 'localhost' || isIpLiteralHostExt(clean)) return clean;
    if (isMultiTenantHostExt(clean)) return clean;
    const parts = clean.split('.');
    if (parts.length <= 2) return clean;
    const lastTwo = parts.slice(-2).join('.');
    if (isCompoundCcTldSuffixExt(lastTwo) && parts.length >= 3) return parts.slice(-3).join('.');
    return lastTwo;
  }

  function isSameSiteDomain(domA, domB) {
    const a = normExtHost(domA);
    const b = normExtHost(domB);
    if (!a || !b) return false;
    if (a === b) return true;
    if (isIpLiteralHostExt(a) || isIpLiteralHostExt(b)) return false;
    if (isMultiTenantHostExt(a) || isMultiTenantHostExt(b)) return false;
    if (isCompoundCcTldSuffixExt(a) || isCompoundCcTldSuffixExt(b)) return false;
    return getBaseSiteExt(a) === getBaseSiteExt(b);
  }

  const EXT_LOCALE = (() => {
    try {
      const lang = (
        (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getUILanguage === 'function' && chrome.i18n.getUILanguage()) ||
        (typeof navigator !== 'undefined' && navigator.language) ||
        'en'
      ).toLowerCase();
      return lang.startsWith('tr') ? 'tr' : 'en';
    } catch {
      return 'en';
    }
  })();

  const EXT_I18N = {
    tr: {
      errLocked: 'Fuin kilitli — önce masaüstü uygulamasını açın',
      errBusy: 'Fuin şu an başka bir onay bekliyor',
      errTimeout: 'Onay süresi doldu — tekrar deneyin',
      errDomainMismatch: 'Alan adı eşleşmedi',
      errNotFound: 'Kayıt bulunamadı',
      errProtocolMismatch: 'Eklenti ve Fuin sürümü uyumsuz — güncelleyin',
      errUnreachable: 'Fuin masaüstü uygulamasına ulaşılamıyor',
      errConnPrefix: 'Fuin bağlantısı başarısız',
      insecureHttp: 'Güvenli olmayan bağlantı (HTTP) — Fuin bu sayfada şifre doldurmaz',
      noMatches: 'Bu site için kayıtlı şifre yok',
      updateTitle: 'Şifre Güncellensin mi?',
      saveTitle: 'Hesap Kaydedilsin mi?',
      thisSite: 'Bu Site',
      labelUsername: 'Kullanıcı Adı',
      placeholderUsername: 'Kullanıcı adı veya e-posta',
      labelPassword: 'Şifre',
      eyeToggle: 'Şifreyi göster / gizle',
      closeTitle: 'Kapat',
      lockedNote: 'Fuin şu an kilitli. Kaydet\'e bastığınızda uygulama açılır; kilidi açıp tekrar Kaydet\'e basabilirsiniz.',
      neverSite: 'Bu Sitede Asla',
      neverSiteTitle: 'Bu alan adı için bir daha şifre kaydetme önerisi gösterme',
      notNow: 'Şimdi Değil',
      btnUpdate: 'Güncelle',
      btnSave: 'Kaydet',
      saving: 'Kaydediliyor…',
      saved: 'Kaydedildi! ✓',
      lockedOpenedNote: 'Fuin kilitli — masaüstü uygulaması açıldı. Kilidi açıp tekrar Kaydet\'e basın.',
      mismatchSaveNote: 'Sürüm uyuşmazlığı — lütfen Fuin Masaüstü ve tarayıcı eklentisini güncelleyin.',
      btnError: 'Hata',
      btnConnError: 'Bağlantı hatası'
    },
    en: {
      errLocked: 'Fuin is locked — unlock the desktop app first',
      errBusy: 'Fuin is waiting on another approval prompt',
      errTimeout: 'Approval timed out — please try again',
      errDomainMismatch: 'Domain mismatch',
      errNotFound: 'Saved entry not found',
      errProtocolMismatch: 'Extension & Fuin version mismatch — please update',
      errUnreachable: 'Could not reach Fuin desktop app',
      errConnPrefix: 'Fuin connection failed',
      insecureHttp: 'Insecure connection (HTTP) — Fuin never fills passwords over HTTP',
      noMatches: 'No saved logins for this site',
      updateTitle: 'Update Password?',
      saveTitle: 'Save Account?',
      thisSite: 'This Site',
      labelUsername: 'Username',
      placeholderUsername: 'Username or email',
      labelPassword: 'Password',
      eyeToggle: 'Show / hide password',
      closeTitle: 'Close',
      lockedNote: 'Fuin is locked. Click Save to open Fuin, unlock your vault, and save again.',
      neverSite: 'Never on this site',
      neverSiteTitle: 'Never prompt to save passwords on this domain',
      notNow: 'Not Now',
      btnUpdate: 'Update',
      btnSave: 'Save',
      saving: 'Saving…',
      saved: 'Saved! ✓',
      lockedOpenedNote: 'Fuin is locked — desktop app opened. Unlock it and press Save again.',
      mismatchSaveNote: 'Protocol version mismatch — please update Fuin Desktop and the browser extension.',
      btnError: 'Error',
      btnConnError: 'Connection error'
    }
  };

  function ct(key) {
    return (EXT_I18N[EXT_LOCALE] && EXT_I18N[EXT_LOCALE][key]) || EXT_I18N.en[key] || key;
  }

  function isVisibleInput(el) {
    if (!el || el.disabled || el.readOnly || el.hidden || el.type === 'hidden') return false;
    if (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
      try {
        const cs = window.getComputedStyle(el);
        if (cs) {
          if (cs.display === 'none' || cs.visibility === 'hidden' || cs.visibility === 'collapse') return false;
          const op = parseFloat(cs.opacity);
          if (!Number.isNaN(op) && op <= 0.05) return false;
        }
      } catch {}
    }
    const rect = typeof el.getBoundingClientRect === 'function' ? el.getBoundingClientRect() : null;
    if (!rect) return false;
    if (!(rect.width > 1 && rect.height > 1)) return false;
    if (typeof rect.right === 'number' && rect.right <= 0) return false;
    if (typeof rect.bottom === 'number' && rect.bottom <= 0) return false;
    return true;
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

    for (const c of candidates) {
      const autocomplete = (c.getAttribute('autocomplete') || '').toLowerCase();
      const name = c.getAttribute('name') || '';
      const id = c.getAttribute('id') || '';
      const placeholder = c.getAttribute('placeholder') || '';
      const ariaLabel = c.getAttribute('aria-label') || '';

      if (autocomplete.includes('username') || autocomplete.includes('email')) {
        matches.push(c);
        break; // Öncelikli eşleşme
      }
      if (idNameRegex.test(name) || idNameRegex.test(id) || idNameRegex.test(placeholder) || idNameRegex.test(ariaLabel) || c.type === 'email') {
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
    if (err === 'locked') return ct('errLocked');
    if (err === 'busy') return ct('errBusy');
    if (err === 'timeout') return ct('errTimeout');
    if (err === 'domain-mismatch') return ct('errDomainMismatch');
    if (err === 'not-found') return ct('errNotFound');
    if (err === 'protocol-mismatch') return ct('errProtocolMismatch');
    if (err === 'native-host-unreachable' || err === 'fuin-not-running') return ct('errUnreachable');
    return ct('errConnPrefix') + ' (' + err + ')';
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
      revealRes = await sendRuntimeMessage({ type: 'fuin-reveal', entryId: matchId, domain });
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
      showMenu(icon, shadowRoot, [ct('insecureHttp')]);
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
      res = await sendRuntimeMessage({ type: 'fuin-lookup', domain });
    } catch {
      res = { error: 'native-host-unreachable' };
    }

    if (!res)                                return showMenu(icon, shadowRoot, [ct('errUnreachable')]);
    if (res.error)                          return showMenu(icon, shadowRoot, [formatRevealError(res.error)]);
    if (!res.matches || !res.matches.length) return showMenu(icon, shadowRoot, [ct('noMatches')]);

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

  function findAssociatedVisiblePassword(targetField, closestForm) {
    if (targetField && targetField.type === 'password') {
      return isVisibleInput(targetField) ? targetField : null;
    }
    if (closestForm) {
      const formPws = Array.from(closestForm.querySelectorAll('input[type="password"]')).filter(isVisibleInput);
      return formPws[0] || null;
    }
    if (!targetField) return null;
    let cur = targetField.parentElement;
    for (let depth = 0; cur && depth < 5 && cur !== document.body && cur !== document.documentElement; depth++) {
      if (typeof cur.querySelectorAll === 'function') {
        const pws = Array.from(cur.querySelectorAll('input[type="password"]')).filter(isVisibleInput);
        if (pws.length > 0) return pws[0];
      }
      cur = cur.parentElement;
    }
    if (targetField.parentElement === document.body) {
      const directPws = Array.from(document.body.children || []).filter(
        el => el.tagName === 'INPUT' && el.type === 'password' && isVisibleInput(el)
      );
      if (directPws.length === 1) return directPws[0];
    }
    return null;
  }

  function fillForm(targetField, creds) {
    if (!creds) return;
    const closestForm = targetField?.closest?.('form') || null;

    // 1. Yalnızca görünür ve ilişkili tek bir kullanıcı adı alanını doldur (belge geneline püskürtme YOK)
    let targetUserField = null;
    if (targetField && targetField.type !== 'password' && isVisibleInput(targetField)) {
      targetUserField = targetField;
    } else if (targetField) {
      const candidateUser = findUsernameField(targetField);
      if (candidateUser && isVisibleInput(candidateUser)) {
        if (closestForm) {
          if (closestForm.contains(candidateUser)) targetUserField = candidateUser;
        } else {
          let sharedContainer = false;
          let cur = targetField.parentElement;
          for (let depth = 0; cur && depth < 5 && cur !== document.body && cur !== document.documentElement; depth++) {
            if (typeof cur.contains === 'function' && cur.contains(candidateUser)) {
              sharedContainer = true;
              break;
            }
            cur = cur.parentElement;
          }
          if (!sharedContainer && targetField.parentElement && candidateUser.parentElement === targetField.parentElement) {
            const meta = ((candidateUser.name || '') + ' ' + (candidateUser.id || '') + ' ' + (candidateUser.getAttribute?.('autocomplete') || '') + ' ' + (candidateUser.placeholder || '') + ' ' + (candidateUser.getAttribute?.('aria-label') || '')).toLowerCase();
            if (candidateUser.type === 'email' || idNameRegex.test(meta)) {
              sharedContainer = true;
            }
          }
          if (sharedContainer) targetUserField = candidateUser;
        }
      }
    }
    if (targetUserField && creds.username !== undefined && creds.username !== null && creds.username !== '') {
      setFieldValue(targetUserField, creds.username);
    }

    // 2. Yalnızca görünür ve ilişkili tek bir şifre alanını doldur (EXT-02: gizli input fallback'i YOK)
    const targetPwField = findAssociatedVisiblePassword(targetField, closestForm);
    if (targetPwField && isVisibleInput(targetPwField) && creds.password !== undefined && creds.password !== null) {
      setFieldValue(targetPwField, creds.password);
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

    // EXT-02: Asla gizli (görünmeyen) şifre alanlarına geri düşme
    return null;
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

  // ── YENİ ŞİFRE KAYDETME / GÜNCELLEME BİLDİRİMİ DURUM DEĞİŞKENLERİ ──────
  const _knownPasswordInputs = new WeakSet();
  const _dirtyPasswordInputs = new Set();
  let _lastTrustedActionAt = 0;
  let activeSaveHost = null;
  let _activeSaveSignature = null;
  let lastProcessedSubmitTime = 0;
  let _lastTypedUsername = '';
  let _lastTypedPassword = '';
  let _passwordDirty = false;
  let _domainExcluded = false;
  const _dismissedKeys = new Set();
  const _localDigestSeed = (() => {
    try {
      if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
        const arr = new Uint32Array(2);
        crypto.getRandomValues(arr);
        return [arr[0] || 0x9e3779b9, arr[1] || 0x85ebca6b];
      }
    } catch {}
    return [0x9e3779b9, 0x85ebca6b];
  })();

  function scan() {
    document.querySelectorAll('input[type="password"]').forEach(el => _knownPasswordInputs.add(el));
    if (activeSaveHost && !activeSaveHost.isConnected && document.body) {
      try { document.body.appendChild(activeSaveHost); } catch {}
    }
    if (activeSaveHost && activeSaveHost.isConnected) {
      enforceSaveHostStyles(activeSaveHost);
    }
    if (_passwordDirty && _dirtyPasswordInputs.size > 0 && (Date.now() - _lastTrustedActionAt < 10000)) {
      let detachedFound = false;
      for (const el of Array.from(_dirtyPasswordInputs)) {
        if (!document.documentElement.contains(el)) {
          _dirtyPasswordInputs.delete(el);
          if (el.value && el.value.length >= 2) {
            _lastTypedPassword = el.value;
          }
          detachedFound = true;
        }
      }
      if (detachedFound) {
        handleCandidateSubmission(null);
      }
    }
  }

  scan();
  new MutationObserver(scan).observe(document.documentElement, { childList: true, subtree: true });

  function makeCredKey(username, password) {
    const raw = `${String(username || '').trim().toLowerCase()}\0${String(password || '')}`;
    let h1 = _localDigestSeed[0] ^ 0xdeadbeef;
    let h2 = _localDigestSeed[1] ^ 0x41c6ce57;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0');
  }

  function markLocalDismissed(username, password) {
    if (password) {
      _dismissedKeys.add(makeCredKey(username, password));
      _dismissedKeys.add(makeCredKey('', password));
    }
    _passwordDirty = false;
    _dirtyPasswordInputs.clear();
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
        _dirtyPasswordInputs.add(el);
      } else {
        _dirtyPasswordInputs.delete(el);
        if (_dirtyPasswordInputs.size === 0) {
          _passwordDirty = false;
          _lastTypedPassword = '';
        }
      }
      const uField = findUsernameField(el);
      if (uField && uField.value && uField.value.trim()) {
        _lastTypedUsername = uField.value.trim();
      }
    } else {
      const meta = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('autocomplete') || '') + ' ' + (el.placeholder || '')).toLowerCase();
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
        _dirtyPasswordInputs.add(el);
      }
    } else if (el.value) {
      const meta = ((el.name || '') + ' ' + (el.id || '') + ' ' + (el.getAttribute('autocomplete') || '') + ' ' + (el.placeholder || '')).toLowerCase();
      if (el.type === 'email' || el.value.includes('@') || idNameRegex.test(meta)) {
        _lastTypedUsername = el.value.trim();
      }
    }
  }, true);

  function pickBestFilledPasswordInput(list) {
    if (!list || list.length === 0) return null;
    if (list.length === 1) return list[0];
    const newPwMatch = list.find(f => {
      const ac = (f.getAttribute('autocomplete') || '').toLowerCase();
      const meta = ((f.name || '') + ' ' + (f.id || '') + ' ' + (f.placeholder || '') + ' ' + (f.getAttribute('aria-label') || '')).toLowerCase();
      return ac.includes('new-password') || /(?:new[-_\s]?pass|yeni[-_\s]?sifre|yeni[-_\s]?şifre|new_pw)/i.test(meta);
    });
    if (newPwMatch) return newPwMatch;
    return list[list.length - 1];
  }

  function captureFormCredentials(contextEl) {
    // EXT-03: Yalnızca kullanıcının güvenilir klavye/input olayıyla yazdığı şifre alanlarını yakala.
    // Önceden doldurulmuş (untyped pre-filled) veya gizli şifre tuzaklarını reddet.
    if (!_passwordDirty || (_dirtyPasswordInputs.size === 0 && !_lastTypedPassword)) {
      return null;
    }

    const pwCandidates = Array.from(document.querySelectorAll('input')).filter(
      el => (el.type === 'password' || _knownPasswordInputs.has(el)) && _dirtyPasswordInputs.has(el)
    );
    const scopeForm = contextEl && contextEl.closest ? contextEl.closest('form') : null;
    const scopedPws = scopeForm ? pwCandidates.filter(f => scopeForm.contains(f)) : [];
    const pool = scopedPws.length > 0 ? scopedPws : pwCandidates;

    // Güvenlik: Gizli (görünmeyen) şifre alanları yalnızca kullanıcı gerçekten klavyeden yazdıysa (_passwordDirty) okunur
    // Çoklu şifre alanı olan (Şifre Değiştirme / Kayıt) formlarda yeni şifre alanını tercih et
    const visibleFilledList = pool.filter(f => isVisibleInput(f) && f.value && f.value.length > 0);
    const visibleFilledPw = pickBestFilledPasswordInput(visibleFilledList);
    const hiddenDirtyPw = _passwordDirty ? pickBestFilledPasswordInput(pool.filter(f => f.value && f.value.length > 0)) : null;
    const filledPw = visibleFilledPw || hiddenDirtyPw || null;

    const password = (filledPw && filledPw.value)
      ? filledPw.value
      : (_passwordDirty && _dirtyPasswordInputs.size === 0 ? _lastTypedPassword : '');
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

  function getControlLabelText(btn) {
    return (
      (btn.textContent || '') + ' ' +
      (btn.value || '') + ' ' +
      (btn.getAttribute('aria-label') || '') + ' ' +
      (btn.getAttribute('title') || '') + ' ' +
      (btn.id || '') + ' ' +
      (btn.getAttribute('name') || '') + ' ' +
      (btn.getAttribute('data-cy') || '') + ' ' +
      (btn.getAttribute('data-testid') || '')
    ).replace(/\s+/g, ' ').trim();
  }

  function isLikelySubmitControl(btn) {
    if (!btn || isFuinInternalNode(btn)) return false;
    const tag = (btn.tagName || '').toUpperCase();
    const typeAttr = (btn.getAttribute('type') || '').toLowerCase();
    if (typeAttr === 'reset' || typeAttr === 'checkbox' || typeAttr === 'radio') return false;

    const labelText = getControlLabelText(btn);

    // Göz ikonu / şifre göster-gizle, kapatma, çerez, OAuth veya "şifremi unuttum" butonlarını her zaman hariç tut
    const nonSubmitRegex = /(?:\b(?:show|hide|toggle|visibility|reveal|eye|g[öÖ]ster|g[iİ]zle|close|dismiss|kapat|cancel|cookie|forgot|unuttum|passkey)\b|(?:^|\s)(?:[iİ]ptal|vazge[çÇ]|[çÇ]erez)(?=$|\s)|(?:with|via|[iİ]le)\s+(?:google|apple|facebook|github|discord)\b|\b(?:google|apple|facebook|github|discord)\s+[iİ]le(?=$|\s))/i;
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
    const positiveSubmitRegex = /(log\s*[iİ]n|sign\s*[iİ]n|sign\s*up|register|create\s*account|continue|submit|next|confirm|save|update|verify|unlock|proceed|enter|authorize|save\s*password|change\s*password|update\s*password|reset\s*password|g[iİ]r[iİ][şŞ]|oturum\s*a[çÇ]|kaydol|kay[ıiI]t\s*ol|hesap\s*olu[şŞ]tur|hesaba\s*g[iİ]r|devam|[iİ]ler[iİ]|kaydet|g[üÜ]ncelle|tamam|do[ğĞ]rula|[üÜ]ye\s*ol|g[öÖ]nder|onayla|[şŞ]ifrey[iİ]?\s*g[üÜ]ncelle|[şŞ]ifrey[iİ]?\s*de[ğĞ][iİ][şŞ]t[iİ]r)/i;
    if (positiveSubmitRegex.test(labelText)) return true;

    // Kullanıcı şifre alanına yazdıysa ve aynı form/kapsayıcı içindeki bir butona tıkladıysa SPA form gönderimi say
    if (_passwordDirty) {
      const form = btn.closest && btn.closest('form');
      if (form && form.querySelector('input[type="password"]')) return true;
      let cur = btn.parentElement;
      for (let depth = 0; cur && depth < 5 && cur !== document.body; depth++) {
        const pws = cur.querySelectorAll ? cur.querySelectorAll('input[type="password"]') : [];
        if (pws.length > 0 && Array.from(pws).some(f => f.value && f.value.length >= 2)) {
          return true;
        }
        cur = cur.parentElement;
      }
    }

    return false;
  }

  async function handleCandidateSubmission(target) {
    if (location.protocol !== 'https:' || _domainExcluded) return;
    if (isFuinInternalNode(target)) return;

    const creds = captureFormCredentials(target);
    if (!creds || !creds.password || creds.password.length < 2) {
      // 2 adımlı (Split-Login) formlarda 1. adımda şifre alanı yoktur; kullanıcı adını 2. sayfa için sakla
      const standalone = findStandaloneUsernameFields()[0];
      const step1User = (standalone && standalone.value && standalone.value.trim())
        ? standalone.value.trim()
        : (_lastTypedUsername || '');
      if (step1User) {
        sendRuntimeMessage({
          type: 'fuin-stage-username',
          username: step1User
        });
      }
      return;
    }
    if (isLocallyDismissed(creds.username, creds.password)) return;

    const now = Date.now();
    if (now - lastProcessedSubmitTime < 1000) return;
    lastProcessedSubmitTime = now;
    _passwordDirty = false;
    _dirtyPasswordInputs.clear();

    try {
      const res = await sendRuntimeMessage({
        type: 'fuin-form-submitted',
        username: creds.username,
        password: creds.password
      });
      if (res && res.shouldPrompt && !(activeSaveHost && activeSaveHost.isConnected)) {
        showSavePrompt({
          domain: location.hostname,
          username: res.username || creds.username,
          password: creds.password,
          action: res.action || 'save',
          entryId: res.entryId || null,
          locked: !!res.locked
        }, res);
      }
    } catch (err) {}
  }

  function enforceSaveHostStyles(host) {
    if (!host || !host.style) return;
    const criticalStyles = [
      ['position', 'fixed'],
      ['top', '16px'],
      ['right', '16px'],
      ['display', 'block'],
      ['opacity', '1'],
      ['visibility', 'visible'],
      ['pointer-events', 'auto'],
      ['z-index', '2147483647'],
      ['transform', 'none'],
      ['clip-path', 'none'],
      ['filter', 'none']
    ];
    if (typeof host.style.setProperty === 'function') {
      const canInspect = typeof host.style.getPropertyValue === 'function' && typeof host.style.getPropertyPriority === 'function';
      for (const [prop, val] of criticalStyles) {
        if (!canInspect || host.style.getPropertyValue(prop) !== val || host.style.getPropertyPriority(prop) !== 'important') {
          host.style.setProperty(prop, val, 'important');
        }
      }
    } else {
      for (const [prop, val] of criticalStyles) {
        const camel = prop.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
        host.style[camel] = val;
      }
      host.style.cssText = criticalStyles.map(([p, v]) => `${p}:${v}!important`).join(';');
    }
  }

  function isSavePromptVisibleAndUnobstructed(host) {
    if (!host || !host.isConnected || host.hidden) return false;
    if (typeof window !== 'undefined' && typeof window.getComputedStyle === 'function') {
      try {
        const cs = window.getComputedStyle(host);
        if (!cs) return false;
        const op = parseFloat(cs.opacity);
        if (Number.isNaN(op) || op < 0.99) return false;
        if (cs.visibility !== 'visible') return false;
        if (cs.display === 'none') return false;
        if (cs.pointerEvents === 'none') return false;
      } catch {
        return false;
      }
    }
    return true;
  }

  function showSavePrompt(candidate, result) {
    if (!candidate || !candidate.password) return;
    if (candidate.domain && !isSameSiteDomain(location.hostname, candidate.domain)) return;
    if (isLocallyDismissed(candidate.username, candidate.password)) return;

    const sig = `${normExtHost(candidate.domain || location.hostname)}\0${candidate.username || ''}\0${candidate.password}`;
    if (activeSaveHost && activeSaveHost.isConnected && _activeSaveSignature === sig) {
      return;
    }

    if (activeSaveHost) {
      try { activeSaveHost.remove(); } catch {}
      activeSaveHost = null;
      _activeSaveSignature = null;
    }

    const host = document.createElement('fuin-save-prompt');
    enforceSaveHostStyles(host);
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
    closeBtn.title = ct('closeTitle');
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
    titleText.textContent = isUpdate ? ct('updateTitle') : ct('saveTitle');
    Object.assign(titleText.style, {
      fontSize: '14px',
      fontWeight: '600',
      color: '#e8e2d8',
      marginBottom: '6px'
    });
    card.appendChild(titleText);

    const rawHost = (candidate.domain || location.hostname || '').replace(/^www\./i, '');
    const cleanSite = rawHost ? (rawHost.charAt(0).toUpperCase() + rawHost.slice(1)) : ct('thisSite');

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
    userLabel.textContent = ct('labelUsername');
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
    userInput.placeholder = ct('placeholderUsername');
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
    pwLabel.textContent = ct('labelPassword');
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
    eyeBtn.title = ct('eyeToggle');
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
      _activeSaveSignature = null;
      sendRuntimeMessage({
        type: 'fuin-dismiss-save',
        username: curUser,
        password: curPw
      });
    }

    closeBtn.addEventListener('click', (e) => {
      if (!e.isTrusted) return;
      dismissCurrentPrompt();
    });

    const statusNote = document.createElement('div');
    Object.assign(statusNote.style, {
      display: (result && result.locked) ? 'block' : 'none',
      fontSize: '11px',
      color: '#c88040',
      background: 'rgba(200, 128, 64, 0.12)',
      border: '1px solid rgba(200, 128, 64, 0.35)',
      borderRadius: '5px',
      padding: '6px 8px',
      marginBottom: '10px',
      lineHeight: '1.4'
    });
    if (result && result.locked) {
      statusNote.textContent = ct('lockedNote');
    }
    card.appendChild(statusNote);

    const btnRow = document.createElement('div');
    Object.assign(btnRow.style, {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      gap: '6px'
    });

    const neverBtn = document.createElement('button');
    neverBtn.type = 'button';
    neverBtn.textContent = ct('neverSite');
    neverBtn.title = ct('neverSiteTitle');
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
      if (!e.isTrusted || !isSavePromptVisibleAndUnobstructed(host)) return;
      _domainExcluded = true;
      markLocalDismissed(userInput.value.trim(), pwInput.value || candidate.password);
      userInput.value = '';
      pwInput.value = '';
      if (host.parentNode) host.remove();
      activeSaveHost = null;
      _activeSaveSignature = null;
      sendRuntimeMessage({ type: 'fuin-exclude-domain' });
    });

    const rightBtns = document.createElement('div');
    Object.assign(rightBtns.style, {
      display: 'flex',
      alignItems: 'center',
      gap: '8px'
    });

    const notNowBtn = document.createElement('button');
    notNowBtn.type = 'button';
    notNowBtn.textContent = ct('notNow');
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
    saveBtn.textContent = isUpdate ? ct('btnUpdate') : ct('btnSave');
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
      if (!e.isTrusted || !isSavePromptVisibleAndUnobstructed(host)) return;
      const finalUsername = userInput.value.trim();
      const finalPassword = pwInput.value;
      if (!finalPassword) return;

      saveBtn.disabled = true;
      saveBtn.textContent = ct('saving');
      try {
        const resp = await sendRuntimeMessage({
          type: 'fuin-save-credential',
          domain: candidate.domain || location.hostname,
          username: finalUsername,
          password: finalPassword,
          updateEntryId: result ? result.entryId : null
        });
        if (resp && resp.ok) {
          markLocalDismissed(finalUsername, finalPassword);
          statusNote.style.display = 'none';
          saveBtn.textContent = ct('saved');
          saveBtn.style.background = '#6bb382';
          userInput.value = '';
          pwInput.value = '';
          setTimeout(() => {
            if (host.parentNode) host.remove();
            activeSaveHost = null;
            _activeSaveSignature = null;
          }, 900);
        } else if (resp && resp.error === 'protocol-mismatch') {
          statusNote.textContent = ct('mismatchSaveNote');
          statusNote.style.display = 'block';
          saveBtn.disabled = false;
          saveBtn.textContent = isUpdate ? ct('btnUpdate') : ct('btnSave');
        } else if (resp && (resp.error === 'locked' || resp.error === 'fuin-not-running' || resp.error === 'native-host-unreachable')) {
          sendRuntimeMessage({ type: 'fuin-open-app' });
          statusNote.textContent = ct('lockedOpenedNote');
          statusNote.style.display = 'block';
          saveBtn.disabled = false;
          saveBtn.textContent = isUpdate ? ct('btnUpdate') : ct('btnSave');
        } else {
          saveBtn.textContent = ct('btnError');
          setTimeout(() => { saveBtn.disabled = false; saveBtn.textContent = isUpdate ? ct('btnUpdate') : ct('btnSave'); }, 2000);
        }
      } catch {
        saveBtn.textContent = ct('btnConnError');
        setTimeout(() => { saveBtn.disabled = false; saveBtn.textContent = isUpdate ? ct('btnUpdate') : ct('btnSave'); }, 2000);
      }
    });

    rightBtns.appendChild(notNowBtn);
    rightBtns.appendChild(saveBtn);
    btnRow.appendChild(neverBtn);
    btnRow.appendChild(rightBtns);
    card.appendChild(btnRow);

    shadow.appendChild(card);
    document.body.appendChild(host);
    enforceSaveHostStyles(host);
    try {
      const styleGuardObserver = new MutationObserver(() => {
        if (activeSaveHost === host && host.isConnected) {
          enforceSaveHostStyles(host);
        } else {
          try { styleGuardObserver.disconnect(); } catch {}
        }
      });
      styleGuardObserver.observe(host, { attributes: true, attributeFilter: ['style', 'class', 'hidden'] });
    } catch {}
    activeSaveHost = host;
    _activeSaveSignature = sig;

    setTimeout(() => {
      if (activeSaveHost === host && host.parentNode) {
        userInput.value = '';
        pwInput.value = '';
        host.remove();
        activeSaveHost = null;
        _activeSaveSignature = null;
      }
    }, 60000);
  }

  window.addEventListener('submit', (e) => {
    if (!e.isTrusted && !(_passwordDirty && Date.now() - _lastTrustedActionAt < 5000)) return;
    handleCandidateSubmission(e.target);
  }, true);

  window.addEventListener('keydown', (e) => {
    if (!e.isTrusted) return;
    if (e.key === 'Escape') {
      _passwordDirty = false;
      _dirtyPasswordInputs.clear();
      _lastTypedPassword = '';
      return;
    }
    if (e.key !== 'Enter') return;
    if (isFuinInternalNode(e.target)) return;
    _lastTrustedActionAt = Date.now();
    if (e.target && e.target.tagName === 'INPUT') {
      handleCandidateSubmission(e.target);
    }
  }, true);

  window.addEventListener('mousedown', (e) => {
    if (!e.isTrusted) return;
    if (isFuinInternalNode(e.target)) return;
    _lastTrustedActionAt = Date.now();
    const btn = e.target && e.target.closest
      ? e.target.closest('button, input[type="submit"], input[type="button"], [role="button"]')
      : null;
    if (btn && isLikelySubmitControl(btn)) {
      handleCandidateSubmission(btn);
    }
  }, true);

  window.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    if (isFuinInternalNode(e.target)) return;
    _lastTrustedActionAt = Date.now();
    const btn = e.target && e.target.closest
      ? e.target.closest('button, input[type="submit"], input[type="button"], [role="button"]')
      : null;
    if (btn) {
      if (/(?:\b(?:close|dismiss|kapat|cancel)\b|(?:^|\s)(?:[iİ]ptal|vazge[çÇ])(?=$|\s))/i.test(getControlLabelText(btn))) {
        _passwordDirty = false;
        _dirtyPasswordInputs.clear();
        _lastTypedPassword = '';
        return;
      }
      if (isLikelySubmitControl(btn)) {
        handleCandidateSubmission(btn);
      }
    }
  }, true);

  window.addEventListener('pagehide', () => {
    if (_passwordDirty && (Date.now() - _lastTrustedActionAt < 10000)) {
      handleCandidateSubmission(null);
    }
  }, true);

  // ── Sayfa açılışında bekleyen kaydetme bildirimi kontrolü (Redirect Sonrası) ──
  async function checkPendingSaveOnLoad() {
    try {
      const resp = await sendRuntimeMessage({ type: 'fuin-get-pending-save' });
      if (resp && resp.hasPending && resp.candidate && !(activeSaveHost && activeSaveHost.isConnected)) {
        showSavePrompt(resp.candidate, resp.result);
      }
    } catch {}
  }
  checkPendingSaveOnLoad();
  setTimeout(() => {
    if (!(activeSaveHost && activeSaveHost.isConnected)) checkPendingSaveOnLoad();
  }, 450);

  // ── Background'dan gelen anlık kaydetme / kapatma bildirimi tetikleyicisi ──
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'fuin-trigger-save-prompt' && msg.candidate) {
      if (msg.candidate.domain && !isSameSiteDomain(location.hostname, msg.candidate.domain)) {
        sendResponse?.({ ok: false, reason: 'domain-mismatch' });
        return;
      }
      showSavePrompt(msg.candidate, msg.result);
      sendResponse?.({ ok: true });
      return;
    }
    if (msg.type === 'fuin-close-save-prompt') {
      if (activeSaveHost) {
        try { activeSaveHost.remove(); } catch {}
        activeSaveHost = null;
        _activeSaveSignature = null;
      }
      sendResponse?.({ ok: true });
    }
  });
})();
