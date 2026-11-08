'use strict';
// ═══════════════════════════════════════════════════════════════════
// Background service worker — Fuin native messaging host ile tek
// bağlantı noktası. Content script'ler ve popup buraya mesaj gönderir,
// bu da native host'a iletip cevabı geri döndürür.
//
// Not: MV3 service worker'lar boşta kalınca kapanır; her istek için
// native messaging bağlantısını (connectNative) yeniden açmak daha
// güvenilir, bu yüzden kalıcı port yerine sendNativeMessage kullanıyoruz.
// ═══════════════════════════════════════════════════════════════════
const HOST_NAME = 'com.fuin.nativehost';
const PROTOCOL_VERSION = 1;
let hostHandshakeState = null;

async function checkHostHandshake(force = false) {
  const now = Date.now();
  if (!force && hostHandshakeState && (now - hostHandshakeState.lastChecked < 30000)) {
    return hostHandshakeState;
  }
  const res = await askFuin({
    type: 'handshake',
    clientVersion: chrome.runtime?.getManifest?.()?.version || '1.0.0',
    protocolVersion: PROTOCOL_VERSION
  });
  if (res && res.ok) {
    hostHandshakeState = {
      ok: true,
      compatible: res.compatible !== false,
      protocolVersion: res.protocolVersion || 1,
      appVersion: res.appVersion || 'unknown',
      unlocked: !!res.unlocked,
      lastChecked: now,
      error: null
    };
  } else {
    hostHandshakeState = {
      ok: false,
      compatible: res?.hostOk ? true : false,
      protocolVersion: res?.hostProtocolVersion || null,
      appVersion: null,
      unlocked: false,
      lastChecked: now,
      error: res?.error || 'unreachable'
    };
  }
  return hostHandshakeState;
}

try {
  checkHostHandshake(true).catch(() => {});
} catch {}

function askFuin(payload) {
  return new Promise((resolve) => {
    const api = typeof browser !== 'undefined' && browser.runtime?.sendNativeMessage ? browser : chrome;
    let resolved = false;
    const safeResolve = (val) => {
      if (!resolved) {
        resolved = true;
        resolve(val);
      }
    };
    try {
      const p = api.runtime.sendNativeMessage(HOST_NAME, payload, (response) => {
        if (chrome.runtime?.lastError) {
          console.error('[Fuin] Native messaging hatası:', chrome.runtime.lastError.message);
          safeResolve({ error: 'native-host-unreachable', detail: chrome.runtime.lastError.message });
          return;
        }
        safeResolve(response || { error: 'empty-response' });
      });
      if (p && typeof p.then === 'function') {
        p.then(res => safeResolve(res || { error: 'empty-response' }))
         .catch(err => safeResolve({ error: 'native-host-unreachable', detail: err?.message || String(err) }));
      }
    } catch (err) {
      safeResolve({ error: 'native-host-unreachable', detail: err?.message || String(err) });
    }
  });
}

function sendTabMessage(tabId, message) {
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

async function getActiveTab() {
  if (typeof browser !== 'undefined' && browser.tabs && browser.tabs.query) {
    try {
      const tabs = await browser.tabs.query({ active: true, lastFocusedWindow: true });
      if (tabs && tabs[0]) return tabs[0];
      const fallback = await browser.tabs.query({ active: true, currentWindow: true });
      return fallback?.[0] || null;
    } catch {
      return null;
    }
  }
  return new Promise((resolve) => {
    try {
      chrome.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
        if (tabs?.[0]) return resolve(tabs[0]);
        chrome.tabs.query({ active: true, currentWindow: true }, (fallbackTabs) => {
          resolve(fallbackTabs?.[0] || null);
        });
      });
    } catch {
      resolve(null);
    }
  });
}

let pendingReveal = null;
const pendingSaveByTab = new Map(); // tabId -> { domain, username, password, action, entryId, timestamp, locked }
const stagedUsernameByTab = new Map(); // tabId -> { domain, username, timestamp } (2 adımlı sayfa geçişli girişler için)
const dismissedFingerprints = new Map(); // key -> timestamp (session suppression for "Not Now" & just-saved)
const excludedDomainsMemory = new Set(); // normalized domains excluded via "Never for this site"
const DISMISS_TTL_MS = 60 * 60 * 1000; // 1 saat boyunca aynı şifre için tekrar sorma
const PENDING_SAVE_TTL_MS = 90 * 1000; // Yönlendirme veya kilit açma sonrası en fazla 90 saniye tut
const STAGED_USER_TTL_MS = 2 * 60 * 1000; // 2 adımlı girişte kullanıcı adını en fazla 2 dakika tut
const MAX_TRACKED_TABS = 64;
const MAX_DISMISSED_KEYS = 256;

const SESSION_DIGEST_SEED = (() => {
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
      const arr = new Uint32Array(4);
      crypto.getRandomValues(arr);
      return [arr[0] || 0x9e3779b9, arr[1] || 0x85ebca6b, arr[2] || 0xc2b2ae35, arr[3] || 0x27d4eb2f];
    }
  } catch {}
  return [0x9e3779b9, 0x85ebca6b, 0xc2b2ae35, 0x27d4eb2f];
})();

function hashDismissedKey(domain, username, password) {
  const input = `${domain}\0${String(username || '').trim().toLowerCase()}\0${String(password || '')}`;
  let h1 = SESSION_DIGEST_SEED[0] ^ 0xdeadbeef;
  let h2 = SESSION_DIGEST_SEED[1] ^ 0x41c6ce57;
  let h3 = SESSION_DIGEST_SEED[2] ^ 0x9e3779b9;
  let h4 = SESSION_DIGEST_SEED[3] ^ 0x85ebca6b;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
    h3 = Math.imul(h3 ^ (ch + i), 2246822507);
    h4 = Math.imul(h4 ^ (ch ^ i), 3266489909);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  h3 = Math.imul(h3 ^ (h3 >>> 16), 2246822507) ^ Math.imul(h4 ^ (h4 >>> 13), 3266489909);
  h4 = Math.imul(h4 ^ (h4 >>> 16), 2246822507) ^ Math.imul(h3 ^ (h3 >>> 13), 3266489909);
  return (
    (h1 >>> 0).toString(16).padStart(8, '0') +
    (h2 >>> 0).toString(16).padStart(8, '0') +
    (h3 >>> 0).toString(16).padStart(8, '0') +
    (h4 >>> 0).toString(16).padStart(8, '0')
  );
}

const MULTI_TENANT_SUFFIXES = new Set([
  'github.io', 'pages.dev', 'vercel.app', 'netlify.app', 'gitlab.io',
  'herokuapp.com', 'firebaseapp.com', 'fly.dev', 'render.com', 'onrender.com',
  'workers.dev', 'web.app', 'azurewebsites.net', 'cloudfront.net', 'railway.app',
  'up.railway.app', 'deno.dev', 'appspot.com', 'surge.sh', 'amplifyapp.com',
  'elasticbeanstalk.com', 's3.amazonaws.com', 'fastly.net', 'b-cdn.net',
  'ngrok-free.app', 'ngrok.io', 'glitch.me', 'myshopify.com',
  'wixsite.com', 'ghost.io', 'substack.com', 'azureedge.net', 'trafficmanager.net',
  'blob.core.windows.net', 'blogspot.com', 'wordpress.com'
]);

function normDomainKey(d) {
  return String(d || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split(':')[0].trim().replace(/\.$/, '');
}

function isMultiTenantHost(h) {
  for (const suffix of MULTI_TENANT_SUFFIXES) {
    if (h === suffix || h.endsWith('.' + suffix)) return true;
  }
  return false;
}

function getBaseSite(h) {
  const clean = normDomainKey(h);
  if (!clean) return '';
  if (clean === 'localhost' || /^\d{1,3}(\.\d{1,3}){3}$/.test(clean) || clean.includes(':')) return clean;
  if (isMultiTenantHost(clean)) return clean;
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const twoPartTlds = new Set([
    'com.tr', 'org.tr', 'net.tr', 'edu.tr', 'gov.tr', 'gen.tr',
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'net.nz',
    'com.br', 'net.br', 'org.br',
    'co.za', 'org.za',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
    'com.de', 'co.ca', 'com.sg', 'com.hk', 'com.mx', 'com.ar'
  ]);
  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

function isSameSiteSafe(domainA, domainB) {
  const a = normDomainKey(domainA);
  const b = normDomainKey(domainB);
  if (!a || !b) return false;
  if (a === b) return true;
  if (isMultiTenantHost(a) || isMultiTenantHost(b)) return false;
  return getBaseSite(a) === getBaseSite(b);
}

function recordDismissedCredential(domain, username, password) {
  const nd = normDomainKey(domain);
  if (!nd || !password) return;
  sweepExpiredMemory();
  while (dismissedFingerprints.size >= MAX_DISMISSED_KEYS) {
    const oldestKey = dismissedFingerprints.keys().next().value;
    if (oldestKey === undefined) break;
    dismissedFingerprints.delete(oldestKey);
  }
  const now = Date.now();
  dismissedFingerprints.set(hashDismissedKey(nd, username, password), now);
  dismissedFingerprints.set(hashDismissedKey(nd, '', password), now);
}

function isCredentialDismissed(domain, username, password) {
  const nd = normDomainKey(domain);
  if (!nd) return false;
  if (excludedDomainsMemory.has(nd)) return true;
  if (!password) return false;
  const now = Date.now();
  const k1 = hashDismissedKey(nd, username, password);
  const k2 = hashDismissedKey(nd, '', password);
  for (const k of [k1, k2]) {
    const ts = dismissedFingerprints.get(k);
    if (ts) {
      if (now - ts < DISMISS_TTL_MS) return true;
      dismissedFingerprints.delete(k);
    }
  }
  return false;
}

function clearPendingForTab(tabId, notifyClose = false) {
  if (!tabId) return;
  const existing = pendingSaveByTab.get(tabId);
  if (existing) {
    existing.password = '';
    existing.username = '';
    pendingSaveByTab.delete(tabId);
  }
  if (chrome.action?.setBadgeText) {
    try { chrome.action.setBadgeText({ text: '', tabId }); } catch {}
  }
  if (notifyClose) {
    try {
      sendTabMessage(tabId, { type: 'fuin-close-save-prompt' });
    } catch {}
  }
}

function sweepExpiredMemory() {
  const now = Date.now();
  for (const [tabId, item] of pendingSaveByTab.entries()) {
    if (now - item.timestamp > PENDING_SAVE_TTL_MS) {
      item.password = '';
      item.username = '';
      pendingSaveByTab.delete(tabId);
    }
  }
  while (pendingSaveByTab.size > MAX_TRACKED_TABS) {
    const oldestTab = pendingSaveByTab.keys().next().value;
    if (oldestTab === undefined) break;
    clearPendingForTab(oldestTab, false);
  }
  for (const [tabId, staged] of stagedUsernameByTab.entries()) {
    if (now - staged.timestamp > STAGED_USER_TTL_MS) {
      staged.username = '';
      stagedUsernameByTab.delete(tabId);
    }
  }
  while (stagedUsernameByTab.size > MAX_TRACKED_TABS) {
    const oldestTab = stagedUsernameByTab.keys().next().value;
    if (oldestTab === undefined) break;
    const oldStaged = stagedUsernameByTab.get(oldestTab);
    if (oldStaged) oldStaged.username = '';
    stagedUsernameByTab.delete(oldestTab);
  }
  for (const [key, ts] of dismissedFingerprints.entries()) {
    if (now - ts > DISMISS_TTL_MS) {
      dismissedFingerprints.delete(key);
    }
  }
}

if (typeof chrome !== 'undefined' && chrome.tabs) {
  if (chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      sweepExpiredMemory();
      if (pendingReveal && pendingReveal.tabId === tabId) {
        const urlChanged = changeInfo.url && changeInfo.url !== pendingReveal.url;
        const loadingNew = changeInfo.status === 'loading' && (!tab?.url || tab.url !== pendingReveal.url);
        if (urlChanged || loadingNew) {
          pendingReveal.cancelled = true;
          try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
          pendingReveal = null;
        }
      }

      // Güvenlik: Sekme farklı bir siteye veya HTTP'ye geçerse bekleyen şifreyi ve 1. adım kullanıcı adını anında bellekten sil (Site Isolation koruması)
      const candidateUrl = changeInfo.url || tab?.url;
      if (candidateUrl && stagedUsernameByTab.has(tabId)) {
        const staged = stagedUsernameByTab.get(tabId);
        let keepStaged = false;
        try {
          const parsed = new URL(candidateUrl);
          if (parsed.protocol === 'https:' && isSameSiteSafe(parsed.hostname, staged.domain)) {
            keepStaged = true;
          }
        } catch {}
        if (!keepStaged) {
          staged.username = '';
          stagedUsernameByTab.delete(tabId);
        }
      }
      if (candidateUrl && pendingSaveByTab.has(tabId)) {
        const pending = pendingSaveByTab.get(tabId);
        let keep = false;
        try {
          const parsed = new URL(candidateUrl);
          if (parsed.protocol === 'https:' && isSameSiteSafe(parsed.hostname, pending.domain)) {
            keep = true;
          }
        } catch {}
        if (!keep) {
          clearPendingForTab(tabId, false);
          return;
        }
      }

      // Sayfa yönlendikten / yüklendikten sonra yalnızca aynı sitedeyse bekleyen kaydetme bildirimini tetikle
      if (changeInfo.status === 'complete') {
        const pending = pendingSaveByTab.get(tabId);
        if (pending) {
          let tabMatchesOrigin = false;
          try {
            if (tab?.url) {
              const u = new URL(tab.url);
              tabMatchesOrigin = u.protocol === 'https:' && isSameSiteSafe(u.hostname, pending.domain);
            }
          } catch {}

          if (
            tabMatchesOrigin &&
            Date.now() - pending.timestamp < PENDING_SAVE_TTL_MS &&
            !isCredentialDismissed(pending.domain, pending.username, pending.password)
          ) {
            sendTabMessage(tabId, {
              type: 'fuin-trigger-save-prompt',
              candidate: pending,
              result: { action: pending.action, entryId: pending.entryId, shouldPrompt: true, locked: !!pending.locked }
            });
          } else {
            clearPendingForTab(tabId, false);
          }
        }
      }
    });
  }

  if (chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      clearPendingForTab(tabId, false);
      stagedUsernameByTab.delete(tabId);
      if (pendingReveal && pendingReveal.tabId === tabId) {
        pendingReveal.cancelled = true;
        try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
        pendingReveal = null;
      }
    });
  }
}

if (typeof chrome !== 'undefined' && chrome.commands?.onCommand) {
  chrome.commands.onCommand.addListener(async (command) => {
    if (command === 'autofill-credential') {
      const tab = await getActiveTab();
      if (tab?.id) {
        await sendTabMessage(tab.id, { type: 'fuin-trigger-fill' });
      }
    }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Güvenlik: Yalnızca Fuin uzantısının kendi ID'sinden gelen mesajları kabul et
  if (sender.id !== chrome.runtime.id) return;
  sweepExpiredMemory();

  const isInternalExtension = sender.id === chrome.runtime.id && !sender.tab;
  
  if (isInternalExtension) {
    if (msg.type === 'fuin-lookup' && msg.domain) {
      askFuin({ type: 'lookup', domain: String(msg.domain).slice(0, 253) }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-reveal' && msg.entryId && msg.domain) {
      askFuin({ type: 'reveal', entryId: String(msg.entryId).slice(0, 128), domain: String(msg.domain).slice(0, 253) }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-copy-secure' && msg.entryId && msg.domain) {
      askFuin({
        type: 'copy-secure',
        entryId: String(msg.entryId).slice(0, 128),
        domain: String(msg.domain).slice(0, 253),
        field: msg.field === 'username' ? 'username' : 'password'
      }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-open-app') {
      askFuin({ type: 'open-app' }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-handshake') {
      checkHostHandshake(!!msg.force).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-get-pending-save-popup') {
      let found = null;
      for (const [tId, p] of pendingSaveByTab.entries()) {
        if (msg.domain && isSameSiteSafe(p.domain, msg.domain)) {
          if (Date.now() - p.timestamp < PENDING_SAVE_TTL_MS && !isCredentialDismissed(p.domain, p.username, p.password)) {
            found = { ...p, tabId: tId };
            break;
          }
        }
      }
      sendResponse(found ? { hasPending: true, item: found } : { hasPending: false });
      return true;
    }
    if (msg.type === 'fuin-save-credential' && msg.password) {
      if (typeof msg.password !== 'string' || msg.password.length > 1024) return;
      const tabId = msg.tabId;
      askFuin({
        type: 'save-credential',
        domain: String(msg.domain || '').slice(0, 253),
        username: String(msg.username || '').slice(0, 512),
        password: msg.password,
        updateEntryId: msg.updateEntryId ? String(msg.updateEntryId).slice(0, 128) : undefined
      }).then((res) => {
        if (res && res.ok) {
          recordDismissedCredential(msg.domain, msg.username, msg.password);
          clearPendingForTab(tabId, true);
        }
        sendResponse(res);
      });
      return true;
    }
    if (msg.type === 'fuin-dismiss-save') {
      const tabId = msg.tabId;
      const existing = tabId ? pendingSaveByTab.get(tabId) : null;
      if (existing) {
        recordDismissedCredential(existing.domain, existing.username, existing.password);
      } else if (msg.domain && msg.password) {
        recordDismissedCredential(msg.domain, msg.username, msg.password);
      }
      clearPendingForTab(tabId, true);
      sendResponse({ ok: true });
      return true;
    }
    return;
  }

  // Content script'lerden gelen mesajlar
  if (!sender.tab?.url) return;

  // Güvenlik: Yalnızca en üst pencereden (top frame) gelen mesajları kabul et.
  // Alt iframelerden (subframe) gelen istekler domain taklidi riskine karşı engellenir.
  if (sender.frameId !== undefined && sender.frameId !== 0) return;

  let actualDomain;
  try {
    const parsedTabUrl = new URL(sender.tab.url);
    if (parsedTabUrl.protocol !== 'https:') return;
    if (sender.url) {
      const parsedSenderUrl = new URL(sender.url);
      if (parsedSenderUrl.protocol !== 'https:' || parsedSenderUrl.origin !== parsedTabUrl.origin) return;
    }
    actualDomain = parsedTabUrl.hostname;
  } catch { return; }

  if (!actualDomain || typeof actualDomain !== 'string' || actualDomain.length > 253) return;

  if (msg.type === 'fuin-lookup') {
    askFuin({ type: 'lookup', domain: actualDomain }).then(sendResponse);
    return true;
  }
  if (msg.type === 'fuin-open-app') {
    askFuin({ type: 'open-app' }).then(sendResponse);
    return true;
  }
  if (msg.type === 'fuin-stage-username' && msg.username) {
    const tabId = sender.tab?.id;
    const cleanUser = typeof msg.username === 'string' ? msg.username.trim().slice(0, 512) : '';
    if (tabId && cleanUser) {
      stagedUsernameByTab.set(tabId, {
        domain: actualDomain,
        username: cleanUser,
        timestamp: Date.now()
      });
    }
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'fuin-get-pending-save') {
    const tabId = sender.tab?.id;
    if (tabId && pendingSaveByTab.has(tabId)) {
      const p = pendingSaveByTab.get(tabId);
      if (
        isSameSiteSafe(actualDomain, p.domain) &&
        Date.now() - p.timestamp < PENDING_SAVE_TTL_MS &&
        !isCredentialDismissed(p.domain, p.username, p.password)
      ) {
        sendResponse({ hasPending: true, candidate: p, result: { action: p.action, entryId: p.entryId, shouldPrompt: true, locked: !!p.locked } });
        return true;
      } else {
        clearPendingForTab(tabId, false);
      }
    }
    sendResponse({ hasPending: false });
    return true;
  }
  if (msg.type === 'fuin-dismiss-save') {
    const tabId = sender.tab?.id;
    const existing = tabId ? pendingSaveByTab.get(tabId) : null;
    if (existing) {
      recordDismissedCredential(existing.domain, existing.username, existing.password);
    }
    if (msg.password) {
      recordDismissedCredential(actualDomain, msg.username, msg.password);
    }
    clearPendingForTab(tabId, false);
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'fuin-exclude-domain') {
    const tabId = sender.tab?.id;
    const existing = tabId ? pendingSaveByTab.get(tabId) : null;
    const targetDom = normDomainKey(existing?.domain || actualDomain);
    if (targetDom && targetDom.length <= 253) {
      excludedDomainsMemory.add(targetDom);
      askFuin({ type: 'exclude-domain', domain: targetDom }).catch(() => {});
    }
    clearPendingForTab(tabId, true);
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'fuin-form-submitted' && msg.password) {
    if (typeof msg.password !== 'string' || msg.password.length > 1024 || msg.password.length < 2) return;
    let cleanUser = typeof msg.username === 'string' ? msg.username.trim().slice(0, 512) : '';
    const tabId = sender.tab?.id;
    if (!cleanUser && tabId && stagedUsernameByTab.has(tabId)) {
      const staged = stagedUsernameByTab.get(tabId);
      if (staged && isSameSiteSafe(actualDomain, staged.domain) && (Date.now() - staged.timestamp < STAGED_USER_TTL_MS)) {
        cleanUser = staged.username;
      }
      stagedUsernameByTab.delete(tabId);
    } else if (tabId) {
      stagedUsernameByTab.delete(tabId);
    }
    if (isCredentialDismissed(actualDomain, cleanUser, msg.password)) {
      sendResponse({ shouldPrompt: false, dismissed: true });
      return true;
    }
    askFuin({
      type: 'check-save-candidate',
      domain: actualDomain,
      username: cleanUser,
      password: msg.password
    }).then((res) => {
      const isLockedState = res && (res.error === 'locked' || res.error === 'fuin-not-running' || res.error === 'native-host-unreachable');
      const shouldStage = Boolean((res && res.shouldPrompt) || isLockedState);
      if (shouldStage && !isCredentialDismissed(actualDomain, cleanUser, msg.password)) {
        const finalUser = (res && res.username) || cleanUser || '';
        const item = {
          domain: actualDomain,
          username: finalUser,
          password: msg.password,
          action: (res && res.action) || 'save',
          entryId: (res && res.entryId) || null,
          locked: Boolean(isLockedState),
          timestamp: Date.now()
        };
        const promptResult = isLockedState
          ? { shouldPrompt: true, action: 'save', entryId: null, locked: true }
          : res;
        if (tabId) {
          pendingSaveByTab.set(tabId, item);
          if (chrome.action?.setBadgeText) {
            try {
              chrome.action.setBadgeText({ text: '1', tabId });
              chrome.action.setBadgeBackgroundColor({ color: '#5a9a6e', tabId });
            } catch {}
          }
          sendTabMessage(tabId, { type: 'fuin-trigger-save-prompt', candidate: item, result: promptResult });
        }
        sendResponse(promptResult);
        return;
      }
      sendResponse(res);
    }).catch(() => {
      sendResponse({ shouldPrompt: false });
    });
    return true;
  }
  if (msg.type === 'fuin-check-save-candidate' && msg.password) {
    if (typeof msg.password !== 'string' || msg.password.length > 1024) return;
    askFuin({
      type: 'check-save-candidate',
      domain: actualDomain,
      username: typeof msg.username === 'string' ? msg.username.slice(0, 512) : '',
      password: msg.password
    }).then(sendResponse);
    return true;
  }
  if (msg.type === 'fuin-save-credential' && msg.password) {
    if (typeof msg.password !== 'string' || msg.password.length > 1024 || msg.password.length < 2) return;
    const cleanUser = typeof msg.username === 'string' ? msg.username.slice(0, 512) : '';
    const cleanUpdateId = typeof msg.updateEntryId === 'string' ? msg.updateEntryId.slice(0, 128) : undefined;
    const tabId = sender.tab?.id;
    const pendingItem = tabId ? pendingSaveByTab.get(tabId) : null;
    const saveDomain = (pendingItem && isSameSiteSafe(actualDomain, pendingItem.domain))
      ? pendingItem.domain
      : actualDomain;
    askFuin({
      type: 'save-credential',
      domain: saveDomain,
      username: cleanUser,
      password: msg.password,
      updateEntryId: cleanUpdateId
    }).then((res) => {
      if (res && res.ok) {
        recordDismissedCredential(saveDomain, cleanUser, msg.password);
        clearPendingForTab(tabId, false);
      }
      sendResponse(res);
    });
    return true;
  }
  if (msg.type === 'fuin-reveal') {
    if (!msg.entryId || typeof msg.entryId !== 'string' || msg.entryId.length > 128) {
      sendResponse({ error: 'invalid-entry-id' });
      return;
    }
    if (pendingReveal !== null) {
      sendResponse({ error: 'busy' });
      return;
    }
    // Reveal işlemi kullanıcı onayı (user gesture) doğrulaması gerektirir, 
    // bunu content.js e.isTrusted ile sağlar
    const tabId = sender.tab?.id;
    const reqUrl = sender.tab?.url;
    const currentReveal = {
      tabId,
      url: reqUrl,
      domain: actualDomain,
      sendResponse,
      cancelled: false
    };
    pendingReveal = currentReveal;

    askFuin({ type: 'reveal', entryId: msg.entryId, domain: actualDomain }).then((res) => {
      if (pendingReveal === currentReveal) {
        pendingReveal = null;
      }
      if (currentReveal.cancelled) {
        try { sendResponse({ error: 'navigation-cancelled' }); } catch {}
        return;
      }
      sendResponse(res);
    }).catch(() => {
      if (pendingReveal === currentReveal) {
        pendingReveal = null;
      }
      sendResponse({ error: 'internal-error' });
    });
    return true;
  }
});
