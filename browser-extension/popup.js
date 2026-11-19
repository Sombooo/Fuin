'use strict';

let currentMatches = [];
let currentDomain = '';
let activeVaultTab = 'logins';
let cachedLogins = [];
let cachedCards = [];
let cachedNotes = [];
let currentPopupTab = null;
let currentPendingSave = null;
let isHttpsSupportedTab = false;

const POPUP_LOCALE = (() => {
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

const POPUP_I18N = {
  tr: {
    checking: 'Kontrol ediliyor...',
    btnUnlock: 'Kilidi Aç',
    btnFillPage: 'Bu sayfayı doldur',
    footerTagline: 'Sıfır Bulut & Çevrimdışı',
    warnInsecureHttp: 'HTTP bağlantı (Güvensiz)',
    warnHttpsOnly: 'Yalnızca HTTPS sitelerde çalışır',
    statusOffline: 'Fuin kapalı veya bağlı değil',
    statusProtocolMismatch: 'Sürüm uyuşmazlığı — Fuin güncellenmeli',
    statusLocked: 'Fuin kilitli',
    statusUnreachable: 'Masaüstü uygulamasına ulaşılamadı',
    statusNoMatches: 'Bu site için kayıt yok',
    titleUpdatePw: 'Şifreyi Güncelle',
    titleNewAccount: 'Yeni Hesap Algılandı',
    unnamed: '— (İsimsiz)',
    eyeToggleDetected: 'Algılanan şifreyi gör / gizle',
    btnSave: 'Kaydet',
    btnSaveTitle: "Fuin'e kaydet",
    toastSaved: 'Hesap Fuin kasasına kaydedildi',
    toastUnlockFirst: 'Önce Fuin kilidini açın',
    toastMismatch: 'Sürüm uyuşmazlığı — Fuin güncellenmeli',
    toastSaveFailed: 'Kaydedilemedi',
    btnDismissTitle: 'Yoksay',
    eyeTogglePw: 'Şifreyi göster / gizle',
    toastRevealFailed: 'Şifre alınamadı',
    toastConnError: 'Bağlantı hatası',
    btnFillTitle: 'Bu hesabı sayfaya doldur',
    btnCopyUserTitle: 'Kullanıcı adını kopyala',
    toastUserCopiedSec: 'Kullanıcı adı kopyalandı (30 sn)',
    toastUserCopied: 'Kullanıcı adı kopyalandı',
    btnCopyPwTitle: 'Şifreyi kopyala (30 sn sonra silinir)',
    toastPwCopiedSec: 'Şifre kopyalandı (30 sn sonra temizlenir)',
    toastPwCopied: 'Şifre kopyalandı',
    toastApprovalDenied: 'Onay reddedildi veya şifre alınamadı',
    toastErrPw: 'Hata: Şifre alınamadı',
    toastErrConn: 'Hata: Bağlantı başarısız',
    tabLogins: 'Girişler',
    tabCards: 'Kartlar',
    tabNotes: 'Notlar',
    noCardsSaved: 'Kayıtlı kart yok',
    noNotesSaved: 'Kayıtlı güvenli not yok',
    copyCardNumberTitle: 'Kart numarasını kopyala (30s)',
    copyCvvTitle: 'CVV kopyala (30s)',
    copyNoteTitle: 'Notu kopyala (30s)',
    cardNoBtn: 'No',
    cardCvvBtn: 'CVV',
    toastCardCopied: 'Kart No kopyalandı (30s)',
    toastCvvCopied: 'CVV kopyalandı (30s)',
    toastNoteCopied: 'Not kopyalandı (30s)',
    toastProtectedDesktop: 'Korumalı kayıt — Fuin masaüstünden kopyalayın',
    protectedShort: 'Korumalı'
  },
  en: {
    checking: 'Checking...',
    btnUnlock: 'Unlock',
    btnFillPage: 'Fill this page',
    footerTagline: 'Zero Cloud & Offline',
    warnInsecureHttp: 'HTTP connection (Insecure)',
    warnHttpsOnly: 'Works on HTTPS sites only',
    statusOffline: 'Fuin is closed or disconnected',
    statusProtocolMismatch: 'Version mismatch — update Fuin or extension',
    statusLocked: 'Fuin is locked',
    statusUnreachable: 'Could not reach desktop app',
    statusNoMatches: 'No saved logins for this site',
    titleUpdatePw: 'Update Password',
    titleNewAccount: 'New Account Detected',
    unnamed: '— (Unnamed)',
    eyeToggleDetected: 'Show / hide detected password',
    btnSave: 'Save',
    btnSaveTitle: 'Save to Fuin',
    toastSaved: 'Saved to Fuin vault',
    toastUnlockFirst: 'Unlock Fuin first',
    toastMismatch: 'Version mismatch — update required',
    toastSaveFailed: 'Failed to save',
    btnDismissTitle: 'Dismiss',
    eyeTogglePw: 'Show / hide password',
    toastRevealFailed: 'Could not reveal password',
    toastConnError: 'Connection error',
    btnFillTitle: 'Fill this account on page',
    btnCopyUserTitle: 'Copy username',
    toastUserCopiedSec: 'Username copied (clears in 30s)',
    toastUserCopied: 'Username copied',
    btnCopyPwTitle: 'Copy password (clears in 30s)',
    toastPwCopiedSec: 'Password copied (clears in 30s)',
    toastPwCopied: 'Password copied',
    toastApprovalDenied: 'Approval denied or password unavailable',
    toastErrPw: 'Error: Could not retrieve password',
    toastErrConn: 'Error: Connection failed',
    tabLogins: 'Logins',
    tabCards: 'Cards',
    tabNotes: 'Notes',
    noCardsSaved: 'No saved cards',
    noNotesSaved: 'No saved secure notes',
    copyCardNumberTitle: 'Copy card number (30s)',
    copyCvvTitle: 'Copy CVV (30s)',
    copyNoteTitle: 'Copy secure note (30s)',
    cardNoBtn: 'Num',
    cardCvvBtn: 'CVV',
    toastCardCopied: 'Card number copied (30s)',
    toastCvvCopied: 'CVV copied (30s)',
    toastNoteCopied: 'Note copied (30s)',
    toastProtectedDesktop: 'Protected item — copy from Fuin Desktop',
    protectedShort: 'Protected'
  }
};

function pt(key) {
  return (POPUP_I18N[POPUP_LOCALE] && POPUP_I18N[POPUP_LOCALE][key]) || POPUP_I18N.en[key] || key;
}

function formatMatchesCount(count) {
  if (POPUP_LOCALE === 'tr') return `${count} kayıt bulundu`;
  return count === 1 ? '1 match found' : `${count} matches found`;
}

function applyStaticLocalization() {
  document.documentElement.lang = POPUP_LOCALE;
  const statusEl = document.getElementById('statusText');
  if (statusEl) statusEl.textContent = pt('checking');
  const openAppBtn = document.getElementById('btnOpenApp');
  if (openAppBtn) openAppBtn.textContent = pt('btnUnlock');
  const fillBtnLabel = document.getElementById('fillBtnLabel');
  if (fillBtnLabel) fillBtnLabel.textContent = pt('btnFillPage');
  const shortcutHint = document.getElementById('shortcutHint');
  if (shortcutHint) {
    const plat = (
      (typeof navigator !== 'undefined' && (navigator.userAgentData?.platform || navigator.platform || navigator.userAgent)) ||
      ''
    ).toLowerCase();
    shortcutHint.textContent = plat.includes('mac') ? '(Cmd+Shift+L)' : '(Ctrl+Shift+L)';
  }
  const footerTagline = document.getElementById('footerTagline');
  if (footerTagline) footerTagline.textContent = pt('footerTagline');
  const extVersion = document.getElementById('extVersion');
  if (extVersion) {
    const ver = (typeof chrome !== 'undefined' && chrome.runtime?.getManifest?.()?.version) || '1.0.4';
    extVersion.textContent = 'v' + ver;
  }
}

function createPopupSvg(name, size = 14) {
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

  if (name === 'eye') {
    svg.appendChild(el('path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }));
    svg.appendChild(el('circle', { cx: '12', cy: '12', r: '3' }));
  } else if (name === 'eyeOff') {
    svg.appendChild(el('path', { d: 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24' }));
    svg.appendChild(el('line', { x1: '1', y1: '1', x2: '23', y2: '23' }));
  } else if (name === 'fill') {
    svg.appendChild(el('path', { d: 'M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4' }));
    svg.appendChild(el('polyline', { points: '10 17 15 12 10 7' }));
    svg.appendChild(el('line', { x1: '15', y1: '12', x2: '3', y2: '12' }));
  } else if (name === 'user') {
    svg.appendChild(el('path', { d: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2' }));
    svg.appendChild(el('circle', { cx: '12', cy: '7', r: '4' }));
  } else if (name === 'key') {
    svg.appendChild(el('path', { d: 'm2 21 9.6-9.6' }));
    svg.appendChild(el('path', { d: 'm7.5 15.5 2.3 2.3a1 1 0 0 1 0 1.4l-2.1 2.1a1 1 0 0 1-1.4 0L4 19' }));
    svg.appendChild(el('circle', { cx: '15.5', cy: '7.5', r: '5.5' }));
  } else if (name === 'refresh') {
    svg.appendChild(el('polyline', { points: '23 4 23 10 17 10' }));
    svg.appendChild(el('path', { d: 'M20.49 15a9 9 0 1 1-2.12-9.36L23 10' }));
  } else if (name === 'hex') {
    svg.appendChild(el('polygon', { points: '12 2 20.66 7 20.66 17 12 22 3.34 17 3.34 7 12 2' }));
  } else if (name === 'close') {
    svg.appendChild(el('line', { x1: '18', y1: '6', x2: '6', y2: '18' }));
    svg.appendChild(el('line', { x1: '6', y1: '6', x2: '18', y2: '18' }));
  } else if (name === 'check') {
    svg.appendChild(el('polyline', { points: '20 6 9 17 4 12' }));
  } else if (name === 'copy') {
    svg.appendChild(el('rect', { x: '9', y: '9', width: '13', height: '13', rx: '2', ry: '2' }));
    svg.appendChild(el('path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' }));
  } else if (name === 'lock') {
    svg.appendChild(el('rect', { x: '3', y: '11', width: '18', height: '11', rx: '2', ry: '2' }));
    svg.appendChild(el('path', { d: 'M7 11V7a5 5 0 0 1 10 0v4' }));
  }
  return svg;
}

function showToast(text) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = text;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1500);
}

async function currentTab() {
  if (typeof browser !== 'undefined' && browser.tabs && browser.tabs.query) {
    try {
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs[0]) return tabs[0];
    } catch {}
  }
  return new Promise((resolve) => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        resolve(tabs?.[0]);
      });
    } catch {
      resolve(null);
    }
  });
}

function sendTabMsg(tabId, message) {
  if (!tabId) return Promise.resolve(null);
  if (typeof browser !== 'undefined' && browser.tabs && browser.tabs.sendMessage) {
    return browser.tabs.sendMessage(tabId, message).catch(() => null);
  }
  return new Promise((resolve) => {
    try {
      chrome.tabs.sendMessage(tabId, message, (resp) => {
        if (chrome.runtime?.lastError) {}
        resolve(resp);
      });
    } catch {
      resolve(null);
    }
  });
}

function hideVaultTabs() {
  const vaultTabs = document.getElementById('vaultTabs');
  if (vaultTabs) vaultTabs.style.display = 'none';
}

function updateVaultTabLabels() {
  const tabBtnLogins = document.getElementById('tabBtnLogins');
  const tabBtnCards = document.getElementById('tabBtnCards');
  const tabBtnNotes = document.getElementById('tabBtnNotes');
  if (tabBtnLogins) {
    tabBtnLogins.textContent = `${pt('tabLogins')} (${cachedLogins.length})`;
    tabBtnLogins.classList.toggle('active', activeVaultTab === 'logins');
  }
  if (tabBtnCards) {
    tabBtnCards.textContent = `${pt('tabCards')} (${cachedCards.length})`;
    tabBtnCards.classList.toggle('active', activeVaultTab === 'cards');
  }
  if (tabBtnNotes) {
    tabBtnNotes.textContent = `${pt('tabNotes')} (${cachedNotes.length})`;
    tabBtnNotes.classList.toggle('active', activeVaultTab === 'notes');
  }
}

function showVaultTabs() {
  const vaultTabs = document.getElementById('vaultTabs');
  updateVaultTabLabels();
  if (vaultTabs) vaultTabs.style.display = 'flex';
}

function copyVaultItemField(entryId, field, btn, restoreFactory, okToastKey) {
  return async (e) => {
    if (!e.isTrusted) return;
    btn.style.opacity = '0.5';
    try {
      const secRes = await chrome.runtime.sendMessage({
        type: 'fuin-copy-secure',
        entryId,
        domain: currentDomain || '',
        field
      });
      if (secRes && secRes.ok) {
        btn.style.opacity = '1';
        btn.replaceChildren(createPopupSvg('check', 12));
        showToast(pt(okToastKey));
        setTimeout(() => btn.replaceChildren(...restoreFactory()), 1200);
        return;
      }
      if (secRes && secRes.error === 'protocol-mismatch') {
        showToast(pt('toastMismatch'));
      } else if (secRes && secRes.error === 'approval-required') {
        showToast(pt('toastProtectedDesktop'));
      } else if (secRes && secRes.error === 'locked') {
        showToast(pt('toastUnlockFirst'));
      } else {
        showToast(pt('toastErrConn'));
      }
    } catch {
      showToast(pt('toastErrConn'));
    }
    btn.style.opacity = '1';
  };
}

function renderCardItems(cards, container) {
  container.replaceChildren();
  if (!cards.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-tab-msg';
    empty.textContent = pt('noCardsSaved');
    container.appendChild(empty);
    return;
  }
  cards.forEach((c) => {
    const cardEl = document.createElement('div');
    cardEl.className = 'match-card';

    const info = document.createElement('div');
    info.className = 'match-info';

    const title = document.createElement('div');
    title.className = 'match-user';
    title.textContent = c.title || pt('unnamed');
    title.title = c.title || '';

    const sub = document.createElement('div');
    sub.className = 'match-site';
    const badge = document.createElement('span');
    badge.className = 'card-badge-pill';
    badge.textContent = c.brand || 'CARD';
    sub.appendChild(badge);
    const metaText = document.createElement('span');
    const masked = `•••• ${c.last4 || '••••'}`;
    metaText.textContent = c.cardExpiry ? `${masked} · ${c.cardExpiry}` : masked;
    sub.appendChild(metaText);

    info.appendChild(title);
    info.appendChild(sub);
    cardEl.appendChild(info);

    const actions = document.createElement('div');
    actions.className = 'match-actions';

    if (c.reprompt) {
      const lockBadge = document.createElement('button');
      lockBadge.type = 'button';
      lockBadge.className = 'action-btn text-pill';
      lockBadge.title = pt('toastProtectedDesktop');
      lockBadge.appendChild(createPopupSvg('lock', 11));
      const lbl = document.createElement('span');
      lbl.textContent = pt('protectedShort');
      lockBadge.appendChild(lbl);
      lockBadge.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        showToast(pt('toastProtectedDesktop'));
      });
      actions.appendChild(lockBadge);
    } else {
      const makeNoNodes = () => [document.createTextNode(pt('cardNoBtn'))];
      const btnCopyNo = document.createElement('button');
      btnCopyNo.type = 'button';
      btnCopyNo.className = 'action-btn text-pill';
      btnCopyNo.title = pt('copyCardNumberTitle');
      btnCopyNo.append(...makeNoNodes());
      btnCopyNo.addEventListener('click', copyVaultItemField(c.id, 'cardNumber', btnCopyNo, makeNoNodes, 'toastCardCopied'));

      const makeCvvNodes = () => [document.createTextNode(pt('cardCvvBtn'))];
      const btnCopyCvv = document.createElement('button');
      btnCopyCvv.type = 'button';
      btnCopyCvv.className = 'action-btn text-pill';
      btnCopyCvv.title = pt('copyCvvTitle');
      btnCopyCvv.append(...makeCvvNodes());
      btnCopyCvv.addEventListener('click', copyVaultItemField(c.id, 'cardCvv', btnCopyCvv, makeCvvNodes, 'toastCvvCopied'));

      actions.appendChild(btnCopyNo);
      actions.appendChild(btnCopyCvv);
    }

    cardEl.appendChild(actions);
    container.appendChild(cardEl);
  });
}

function renderNoteItems(notes, container) {
  container.replaceChildren();
  if (!notes.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-tab-msg';
    empty.textContent = pt('noNotesSaved');
    container.appendChild(empty);
    return;
  }
  notes.forEach((n) => {
    const cardEl = document.createElement('div');
    cardEl.className = 'match-card';

    const info = document.createElement('div');
    info.className = 'match-info';

    const title = document.createElement('div');
    title.className = 'match-user';
    title.textContent = n.title || pt('unnamed');
    title.title = n.title || '';

    const sub = document.createElement('div');
    sub.className = 'match-site';
    sub.textContent = n.category || pt('tabNotes');

    info.appendChild(title);
    info.appendChild(sub);
    cardEl.appendChild(info);

    const actions = document.createElement('div');
    actions.className = 'match-actions';

    if (n.reprompt) {
      const lockBadge = document.createElement('button');
      lockBadge.type = 'button';
      lockBadge.className = 'action-btn text-pill';
      lockBadge.title = pt('toastProtectedDesktop');
      lockBadge.appendChild(createPopupSvg('lock', 11));
      const lbl = document.createElement('span');
      lbl.textContent = pt('protectedShort');
      lockBadge.appendChild(lbl);
      lockBadge.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        showToast(pt('toastProtectedDesktop'));
      });
      actions.appendChild(lockBadge);
    } else {
      const makeCopyNodes = () => [createPopupSvg('copy', 13)];
      const btnCopyNote = document.createElement('button');
      btnCopyNote.type = 'button';
      btnCopyNote.className = 'action-btn';
      btnCopyNote.title = pt('copyNoteTitle');
      btnCopyNote.append(...makeCopyNodes());
      btnCopyNote.addEventListener('click', copyVaultItemField(n.id, 'secureNote', btnCopyNote, makeCopyNodes, 'toastNoteCopied'));
      actions.appendChild(btnCopyNote);
    }

    cardEl.appendChild(actions);
    container.appendChild(cardEl);
  });
}

function renderActiveTabList() {
  const fillBtn = document.getElementById('fillBtn');
  const matchesList = document.getElementById('matchesList');
  if (!matchesList) return;
  updateVaultTabLabels();

  if (activeVaultTab === 'cards') {
    if (fillBtn) fillBtn.style.display = 'none';
    matchesList.style.display = 'flex';
    renderCardItems(cachedCards, matchesList);
    return;
  }

  if (activeVaultTab === 'notes') {
    if (fillBtn) fillBtn.style.display = 'none';
    matchesList.style.display = 'flex';
    renderNoteItems(cachedNotes, matchesList);
    return;
  }

  // Logins tab
  if (fillBtn) {
    fillBtn.style.display = 'flex';
    fillBtn.disabled = !isHttpsSupportedTab || cachedLogins.length === 0;
  }
  const hasPending = Boolean(currentPendingSave && currentPendingSave.hasPending && currentPendingSave.item);
  if (cachedLogins.length > 0) {
    renderMatches(cachedLogins, matchesList, currentPopupTab);
    matchesList.style.display = 'flex';
    if (hasPending) renderPendingSaveBanner(currentPendingSave.item, matchesList);
  } else if (hasPending) {
    matchesList.replaceChildren();
    matchesList.style.display = 'flex';
    renderPendingSaveBanner(currentPendingSave.item, matchesList);
  } else {
    matchesList.style.display = 'none';
  }
}

async function checkStatus() {
  const dot = document.getElementById('dot');
  const text = document.getElementById('statusText');
  const fillBtn = document.getElementById('fillBtn');
  const domainTag = document.getElementById('domainTag');
  const openAppBtn = document.getElementById('btnOpenApp');
  const matchesList = document.getElementById('matchesList');

  const tab = await currentTab();
  currentPopupTab = tab;
  currentPendingSave = null;
  let parsedUrl = null;
  try {
    if (tab && tab.url) parsedUrl = new URL(tab.url);
  } catch {}

  if (!parsedUrl || parsedUrl.protocol !== 'https:') {
    isHttpsSupportedTab = false;
    currentDomain = '';
    cachedLogins = [];
    currentMatches = [];
    dot.className = 'dot warn';
    if (domainTag) domainTag.textContent = parsedUrl ? parsedUrl.protocol.replace(':', '') : '—';
    text.textContent = parsedUrl?.protocol === 'http:'
      ? pt('warnInsecureHttp')
      : pt('warnHttpsOnly');
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
    let itemsRes = null;
    try {
      itemsRes = await chrome.runtime.sendMessage({ type: 'fuin-list-vault-items' });
    } catch {}
    if (itemsRes && !itemsRes.error && (Array.isArray(itemsRes.cards) || Array.isArray(itemsRes.notes))) {
      cachedCards = Array.isArray(itemsRes.cards) ? itemsRes.cards : [];
      cachedNotes = Array.isArray(itemsRes.notes) ? itemsRes.notes : [];
      activeVaultTab = cachedCards.length > 0 ? 'cards' : 'notes';
      showVaultTabs();
      renderActiveTabList();
    } else {
      hideVaultTabs();
    }
    return;
  }

  isHttpsSupportedTab = true;
  const domain = parsedUrl.hostname;
  currentDomain = domain;
  if (domainTag) domainTag.textContent = domain;

  let res;
  try {
    res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
  } catch {
    res = { error: 'native-host-unreachable' };
  }

  if (!res || res.error === 'native-host-unreachable') {
    hideVaultTabs();
    dot.className = 'dot err';
    text.textContent = pt('statusOffline');
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
  } else if (res.error === 'protocol-mismatch') {
    hideVaultTabs();
    dot.className = 'dot err';
    text.textContent = pt('statusProtocolMismatch');
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
  } else if (res.error === 'locked') {
    hideVaultTabs();
    dot.className = 'dot warn';
    text.textContent = pt('statusLocked');
    fillBtn.disabled = true;
    if (openAppBtn) {
      openAppBtn.style.display = 'block';
      openAppBtn.onclick = (e) => {
        if (!e.isTrusted) return;
        chrome.runtime.sendMessage({ type: 'fuin-open-app' });
        window.close();
      };
    }
    let pendingSaveRes = null;
    try {
      pendingSaveRes = await chrome.runtime.sendMessage({ type: 'fuin-get-pending-save-popup', domain });
    } catch {}
    if (matchesList) {
      if (pendingSaveRes && pendingSaveRes.hasPending && pendingSaveRes.item) {
        matchesList.replaceChildren();
        matchesList.style.display = 'flex';
        renderPendingSaveBanner(pendingSaveRes.item, matchesList);
      } else {
        matchesList.style.display = 'none';
      }
    }
  } else if (res.error) {
    hideVaultTabs();
    dot.className = 'dot err';
    text.textContent = pt('statusUnreachable');
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
  } else {
    currentMatches = Array.isArray(res.matches) ? res.matches : [];
    cachedLogins = currentMatches;
    const count = currentMatches.length;
    dot.className = count > 0 ? 'dot ok' : 'dot warn';
    text.textContent = count > 0 ? formatMatchesCount(count) : pt('statusNoMatches');
    fillBtn.disabled = count === 0;
    if (openAppBtn) openAppBtn.style.display = 'none';

    let itemsRes = null;
    try {
      itemsRes = await chrome.runtime.sendMessage({ type: 'fuin-list-vault-items' });
    } catch {}
    cachedCards = Array.isArray(itemsRes?.cards) ? itemsRes.cards : [];
    cachedNotes = Array.isArray(itemsRes?.notes) ? itemsRes.notes : [];

    let pendingSaveRes = null;
    try {
      pendingSaveRes = await chrome.runtime.sendMessage({ type: 'fuin-get-pending-save-popup', domain });
    } catch {}
    currentPendingSave = pendingSaveRes;

    activeVaultTab = 'logins';
    showVaultTabs();
    renderActiveTabList();
  }
}

function renderPendingSaveBanner(item, container) {
  const banner = document.createElement('div');
  banner.className = 'match-card';
  banner.style.borderColor = '#5a9a6e';
  banner.style.background = 'rgba(90, 154, 110, 0.14)';
  banner.style.marginBottom = '8px';

  const info = document.createElement('div');
  info.className = 'match-info';

  const title = document.createElement('div');
  title.style.fontSize = '11px';
  title.style.fontWeight = '600';
  title.style.color = '#6bb382';
  title.style.display = 'flex';
  title.style.alignItems = 'center';
  title.style.gap = '5px';
  title.appendChild(createPopupSvg(item.action === 'update' ? 'refresh' : 'hex', 11));
  const titleLabel = document.createElement('span');
  titleLabel.textContent = item.action === 'update' ? pt('titleUpdatePw') : pt('titleNewAccount');
  title.appendChild(titleLabel);

  const user = document.createElement('div');
  user.className = 'match-user';
  user.textContent = item.username || pt('unnamed');

  const pwRow = document.createElement('div');
  pwRow.style.display = 'flex';
  pwRow.style.alignItems = 'center';
  pwRow.style.gap = '6px';
  pwRow.style.marginTop = '2px';

  const pwDots = document.createElement('span');
  pwDots.textContent = '••••••••';
  pwDots.style.fontFamily = 'monospace';
  pwDots.style.fontSize = '11px';
  pwDots.style.color = 'var(--mu)';
  pwDots.style.letterSpacing = '1px';

  const pwEye = document.createElement('button');
  pwEye.type = 'button';
  pwEye.appendChild(createPopupSvg('eye', 12));
  pwEye.title = pt('eyeToggleDetected');
  pwEye.style.background = 'transparent';
  pwEye.style.border = 'none';
  pwEye.style.color = 'var(--mu)';
  pwEye.style.display = 'flex';
  pwEye.style.alignItems = 'center';
  pwEye.style.cursor = 'pointer';
  pwEye.style.padding = '2px';

  let bannerPwShown = false;
  pwEye.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    e.stopPropagation();
    bannerPwShown = !bannerPwShown;
    pwDots.textContent = bannerPwShown ? (item.password || '—') : '••••••••';
    pwDots.style.color = bannerPwShown ? 'var(--text)' : 'var(--mu)';
    pwEye.replaceChildren(createPopupSvg(bannerPwShown ? 'eyeOff' : 'eye', 12));
    pwEye.style.color = bannerPwShown ? 'var(--ac-bright)' : 'var(--mu)';
  });

  pwRow.appendChild(pwDots);
  pwRow.appendChild(pwEye);

  info.appendChild(title);
  info.appendChild(user);
  info.appendChild(pwRow);
  banner.appendChild(info);

  const actions = document.createElement('div');
  actions.className = 'match-actions';

  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn-save-banner';
  saveBtn.textContent = pt('btnSave');
  saveBtn.title = pt('btnSaveTitle');
  saveBtn.addEventListener('click', async (e) => {
    if (!e.isTrusted) return;
    saveBtn.disabled = true;
    saveBtn.textContent = '…';
    const resp = await chrome.runtime.sendMessage({
      type: 'fuin-save-credential',
      domain: item.domain,
      username: item.username,
      password: item.password,
      updateEntryId: item.entryId,
      tabId: item.tabId
    });
    if (resp && resp.ok) {
      showToast(pt('toastSaved'));
      banner.remove();
      setTimeout(checkStatus, 500);
    } else if (resp && resp.error === 'protocol-mismatch') {
      showToast(pt('toastMismatch'));
      saveBtn.disabled = false;
      saveBtn.textContent = pt('btnSave');
    } else if (resp && (resp.error === 'locked' || resp.error === 'fuin-not-running')) {
      showToast(pt('toastUnlockFirst'));
      try { chrome.runtime.sendMessage({ type: 'fuin-open-app' }); } catch {}
      saveBtn.disabled = false;
      saveBtn.textContent = pt('btnSave');
    } else {
      showToast(pt('toastSaveFailed'));
      saveBtn.disabled = false;
      saveBtn.textContent = pt('btnSave');
    }
  });

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'btn-dismiss-banner';
  dismissBtn.appendChild(createPopupSvg('close', 12));
  dismissBtn.title = pt('btnDismissTitle');
  dismissBtn.addEventListener('click', async (e) => {
    if (!e.isTrusted) return;
    await chrome.runtime.sendMessage({
      type: 'fuin-dismiss-save',
      tabId: item.tabId,
      domain: item.domain,
      username: item.username,
      password: item.password
    });
    banner.remove();
  });

  actions.appendChild(saveBtn);
  actions.appendChild(dismissBtn);
  banner.appendChild(actions);

  container.prepend(banner);
}

function renderMatches(matches, container, tab) {
  container.replaceChildren();
  matches.forEach(m => {
    const card = document.createElement('div');
    card.className = 'match-card';

    const info = document.createElement('div');
    info.className = 'match-info';

    const user = document.createElement('div');
    user.className = 'match-user';
    user.textContent = m.username || pt('unnamed');
    user.title = m.username || '';

    const site = document.createElement('div');
    site.className = 'match-site';
    site.textContent = m.site || currentDomain;

    const pwRow = document.createElement('div');
    pwRow.className = 'match-pw-row';
    pwRow.style.display = 'flex';
    pwRow.style.alignItems = 'center';
    pwRow.style.gap = '6px';
    pwRow.style.marginTop = '4px';

    const pwDots = document.createElement('span');
    pwDots.className = 'match-pw-dots';
    pwDots.textContent = '••••••••';
    pwDots.style.fontFamily = 'monospace';
    pwDots.style.fontSize = '11px';
    pwDots.style.color = 'var(--mu)';
    pwDots.style.letterSpacing = '1px';

    const btnEye = document.createElement('button');
    btnEye.type = 'button';
    btnEye.className = 'action-btn-eye';
    btnEye.appendChild(createPopupSvg('eye', 12));
    btnEye.title = pt('eyeTogglePw');
    btnEye.style.background = 'transparent';
    btnEye.style.border = 'none';
    btnEye.style.color = 'var(--mu)';
    btnEye.style.display = 'flex';
    btnEye.style.alignItems = 'center';
    btnEye.style.cursor = 'pointer';
    btnEye.style.padding = '2px';

    let isRevealed = false;
    let revealTimer = null;
    btnEye.addEventListener('click', async (e) => {
      if (!e.isTrusted) return;
      e.stopPropagation();
      if (isRevealed) {
        isRevealed = false;
        clearTimeout(revealTimer);
        pwDots.textContent = '••••••••';
        pwDots.style.color = 'var(--mu)';
        btnEye.replaceChildren(createPopupSvg('eye', 12));
        btnEye.style.color = 'var(--mu)';
        return;
      }
      btnEye.style.opacity = '0.5';
      try {
        const rev = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: m.id, domain: currentDomain });
        btnEye.style.opacity = '1';
        if (rev && rev.password) {
          isRevealed = true;
          pwDots.textContent = rev.password;
          pwDots.style.color = 'var(--text)';
          btnEye.replaceChildren(createPopupSvg('eyeOff', 12));
          btnEye.style.color = 'var(--ac-bright)';
          clearTimeout(revealTimer);
          revealTimer = setTimeout(() => {
            isRevealed = false;
            pwDots.textContent = '••••••••';
            pwDots.style.color = 'var(--mu)';
            btnEye.replaceChildren(createPopupSvg('eye', 12));
            btnEye.style.color = 'var(--mu)';
          }, 8000);
        } else {
          showToast(rev && rev.error === 'protocol-mismatch' ? pt('toastMismatch') : pt('toastRevealFailed'));
          btnEye.replaceChildren(createPopupSvg('eye', 12));
        }
      } catch {
        btnEye.style.opacity = '1';
        showToast(pt('toastConnError'));
        btnEye.replaceChildren(createPopupSvg('eye', 12));
      }
    });

    pwRow.appendChild(pwDots);
    pwRow.appendChild(btnEye);

    info.appendChild(user);
    info.appendChild(site);
    info.appendChild(pwRow);
    card.appendChild(info);

    const actions = document.createElement('div');
    actions.className = 'match-actions';

    // Doldur butonu
    const btnFill = document.createElement('button');
    btnFill.className = 'action-btn fill-btn';
    btnFill.title = pt('btnFillTitle');
    btnFill.appendChild(createPopupSvg('fill', 14));
    btnFill.onclick = async (e) => {
      if (!e.isTrusted) return;
      if (tab?.id) {
        await sendTabMsg(tab.id, { type: 'fuin-trigger-fill', entryId: m.id });
        window.close();
      }
    };

    // Kullanıcı adı kopyala (30 sn otomatik pano temizlemeli)
    const btnCopyUser = document.createElement('button');
    btnCopyUser.className = 'action-btn';
    btnCopyUser.title = pt('btnCopyUserTitle');
    btnCopyUser.appendChild(createPopupSvg('user', 13));
    btnCopyUser.onclick = async (e) => {
      if (!e.isTrusted || !m.username) return;
      const res = await chrome.runtime.sendMessage({
        type: 'fuin-copy-secure',
        entryId: m.id,
        domain: currentDomain,
        field: 'username'
      });
      if (res && res.ok) {
        btnCopyUser.replaceChildren(createPopupSvg('check', 13));
        showToast(pt('toastUserCopiedSec'));
        setTimeout(() => btnCopyUser.replaceChildren(createPopupSvg('user', 13)), 1200);
      } else {
        await navigator.clipboard.writeText(m.username);
        showToast(pt('toastUserCopied'));
      }
    };

    // Şifre kopyala (Fuin masaüstü 30 sn güvenli pano temizlemeli)
    const btnCopyPw = document.createElement('button');
    btnCopyPw.className = 'action-btn';
    btnCopyPw.title = pt('btnCopyPwTitle');
    btnCopyPw.appendChild(createPopupSvg('key', 13));
    btnCopyPw.onclick = async (e) => {
      if (!e.isTrusted) return;
      btnCopyPw.style.opacity = '0.5';
      try {
        const secRes = await chrome.runtime.sendMessage({
          type: 'fuin-copy-secure',
          entryId: m.id,
          domain: currentDomain,
          field: 'password'
        });
        if (secRes && secRes.ok) {
          btnCopyPw.style.opacity = '1';
          btnCopyPw.replaceChildren(createPopupSvg('check', 13));
          showToast(pt('toastPwCopiedSec'));
          setTimeout(() => btnCopyPw.replaceChildren(createPopupSvg('key', 13)), 1200);
          return;
        }
        if (secRes && secRes.error === 'protocol-mismatch') {
          showToast(pt('toastMismatch'));
        } else if (secRes && secRes.error === 'approval-required') {
          const rev = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: m.id, domain: currentDomain });
          if (rev && rev.password) {
            await navigator.clipboard.writeText(rev.password);
            btnCopyPw.replaceChildren(createPopupSvg('check', 13));
            showToast(pt('toastPwCopied'));
            setTimeout(() => btnCopyPw.replaceChildren(createPopupSvg('key', 13)), 1200);
          } else {
            showToast(pt('toastApprovalDenied'));
          }
        } else {
          showToast(pt('toastErrPw'));
        }
      } catch {
        showToast(pt('toastErrConn'));
      }
      btnCopyPw.style.opacity = '1';
    };

    actions.appendChild(btnFill);
    actions.appendChild(btnCopyUser);
    actions.appendChild(btnCopyPw);
    card.appendChild(actions);

    container.appendChild(card);
  });
}

document.getElementById('tabBtnLogins')?.addEventListener('click', (e) => {
  if (!e.isTrusted) return;
  activeVaultTab = 'logins';
  renderActiveTabList();
});

document.getElementById('tabBtnCards')?.addEventListener('click', (e) => {
  if (!e.isTrusted) return;
  activeVaultTab = 'cards';
  renderActiveTabList();
});

document.getElementById('tabBtnNotes')?.addEventListener('click', (e) => {
  if (!e.isTrusted) return;
  activeVaultTab = 'notes';
  renderActiveTabList();
});

document.getElementById('fillBtn').addEventListener('click', async (e) => {
  if (!e.isTrusted) return;
  const tab = await currentTab();
  if (!tab || !tab.id) return;
  try {
    await sendTabMsg(tab.id, { type: 'fuin-trigger-fill' });
  } catch {}
  window.close();
});

applyStaticLocalization();
checkStatus();
