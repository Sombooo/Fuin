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

let pendingReveal = null;
const pendingSaveByTab = new Map(); // tabId -> { domain, username, password, action, entryId, timestamp }
const dismissedFingerprints = new Map(); // key -> timestamp (session suppression for "Not Now" & just-saved)
const excludedDomainsMemory = new Set(); // normalized domains excluded via "Never for this site"
const DISMISS_TTL_MS = 60 * 60 * 1000; // 1 saat boyunca aynı şifre için tekrar sorma
const PENDING_SAVE_TTL_MS = 60 * 1000; // Yönlendirme sonrası en fazla 60 saniye tut

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
  const now = Date.now();
  dismissedFingerprints.set(`${nd}|${String(username || '').trim().toLowerCase()}|${password}`, now);
  dismissedFingerprints.set(`${nd}||${password}`, now);
}

function isCredentialDismissed(domain, username, password) {
  const nd = normDomainKey(domain);
  if (!nd) return false;
  if (excludedDomainsMemory.has(nd)) return true;
  if (!password) return false;
  const now = Date.now();
  const k1 = `${nd}|${String(username || '').trim().toLowerCase()}|${password}`;
  const k2 = `${nd}||${password}`;
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
  if (notifyClose && chrome.tabs?.sendMessage) {
    try {
      chrome.tabs.sendMessage(tabId, { type: 'fuin-close-save-prompt' }, () => {
        if (chrome.runtime?.lastError) {}
      });
    } catch {}
  }
}

if (typeof chrome !== 'undefined' && chrome.tabs) {
  if (chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (pendingReveal && pendingReveal.tabId === tabId) {
        const urlChanged = changeInfo.url && changeInfo.url !== pendingReveal.url;
        const loadingNew = changeInfo.status === 'loading' && (!tab?.url || tab.url !== pendingReveal.url);
        if (urlChanged || loadingNew) {
          pendingReveal.cancelled = true;
          try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
          pendingReveal = null;
        }
      }

      // Güvenlik: Sekme farklı bir siteye veya HTTP'ye geçerse bekleyen şifreyi anında bellekten sil (Site Isolation koruması)
      const candidateUrl = changeInfo.url || tab?.url;
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
            chrome.tabs.sendMessage(tabId, {
              type: 'fuin-trigger-save-prompt',
              candidate: pending,
              result: { action: pending.action, entryId: pending.entryId, shouldPrompt: true }
            }, () => {
              if (chrome.runtime?.lastError) {}
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
      if (pendingReveal && pendingReveal.tabId === tabId) {
        pendingReveal.cancelled = true;
        try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
        pendingReveal = null;
      }
    });
  }
}

if (typeof chrome !== 'undefined' && chrome.commands?.onCommand) {
  chrome.commands.onCommand.addListener((command) => {
    if (command === 'autofill-credential') {
      const api = typeof browser !== 'undefined' && browser.tabs ? browser : chrome;
      api.tabs.query({ active: true, lastFocusedWindow: true }, (tabs) => {
        const tab = tabs?.[0];
        if (tab?.id) {
          api.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill' }, () => {
            if (chrome.runtime?.lastError) { /* tab might not have content script injected */ }
          });
        } else {
          api.tabs.query({ active: true, currentWindow: true }, (fallbackTabs) => {
            if (fallbackTabs?.[0]?.id) {
              api.tabs.sendMessage(fallbackTabs[0].id, { type: 'fuin-trigger-fill' }, () => {
                if (chrome.runtime?.lastError) {}
              });
            }
          });
        }
      });
    }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const isInternalExtension = sender.id === chrome.runtime.id && !sender.tab;
  
  if (isInternalExtension) {
    if (msg.type === 'fuin-lookup' && msg.domain) {
      askFuin({ type: 'lookup', domain: msg.domain }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-reveal' && msg.entryId && msg.domain) {
      askFuin({ type: 'reveal', entryId: msg.entryId, domain: msg.domain }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-copy-secure' && msg.entryId && msg.domain) {
      askFuin({
        type: 'copy-secure',
        entryId: msg.entryId,
        domain: msg.domain,
        field: msg.field === 'username' ? 'username' : 'password'
      }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-open-app') {
      askFuin({ type: 'open-app' }).then(sendResponse);
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
      const tabId = msg.tabId;
      askFuin({
        type: 'save-credential',
        domain: msg.domain,
        username: msg.username || '',
        password: msg.password,
        updateEntryId: msg.updateEntryId
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
    if (sender.url) {
      const parsedSenderUrl = new URL(sender.url);
      if (parsedSenderUrl.origin !== parsedTabUrl.origin) return;
    }
    actualDomain = parsedTabUrl.hostname;
  } catch { return; }

  if (msg.type === 'fuin-lookup') {
    askFuin({ type: 'lookup', domain: actualDomain }).then(sendResponse);
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
        sendResponse({ hasPending: true, candidate: p, result: { action: p.action, entryId: p.entryId, shouldPrompt: true } });
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
    if (targetDom) {
      excludedDomainsMemory.add(targetDom);
      askFuin({ type: 'exclude-domain', domain: targetDom }).catch(() => {});
    }
    clearPendingForTab(tabId, true);
    sendResponse({ ok: true });
    return true;
  }
  if (msg.type === 'fuin-form-submitted' && msg.password) {
    const tabId = sender.tab?.id;
    if (isCredentialDismissed(actualDomain, msg.username, msg.password)) {
      sendResponse({ shouldPrompt: false, dismissed: true });
      return true;
    }
    askFuin({
      type: 'check-save-candidate',
      domain: actualDomain,
      username: msg.username || '',
      password: msg.password
    }).then((res) => {
      if (res && res.shouldPrompt && !isCredentialDismissed(actualDomain, msg.username, msg.password)) {
        const finalUser = res.username || msg.username || '';
        const item = {
          domain: actualDomain,
          username: finalUser,
          password: msg.password,
          action: res.action || 'save',
          entryId: res.entryId || null,
          timestamp: Date.now()
        };
        if (tabId) {
          pendingSaveByTab.set(tabId, item);
          if (chrome.action?.setBadgeText) {
            try {
              chrome.action.setBadgeText({ text: '1', tabId });
              chrome.action.setBadgeBackgroundColor({ color: '#5a9a6e', tabId });
            } catch {}
          }
          chrome.tabs.sendMessage(tabId, { type: 'fuin-trigger-save-prompt', candidate: item, result: res }, () => {
            if (chrome.runtime?.lastError) {}
          });
        }
      }
      sendResponse(res);
    }).catch(() => {
      sendResponse({ shouldPrompt: false });
    });
    return true;
  }
  if (msg.type === 'fuin-check-save-candidate' && msg.password) {
    askFuin({
      type: 'check-save-candidate',
      domain: actualDomain,
      username: msg.username || '',
      password: msg.password
    }).then(sendResponse);
    return true;
  }
  if (msg.type === 'fuin-save-credential' && msg.password) {
    const tabId = sender.tab?.id;
    const pendingItem = tabId ? pendingSaveByTab.get(tabId) : null;
    const saveDomain = (pendingItem && isSameSiteSafe(actualDomain, pendingItem.domain))
      ? pendingItem.domain
      : actualDomain;
    askFuin({
      type: 'save-credential',
      domain: saveDomain,
      username: msg.username || '',
      password: msg.password,
      updateEntryId: msg.updateEntryId
    }).then((res) => {
      if (res && res.ok) {
        recordDismissedCredential(saveDomain, msg.username, msg.password);
        clearPendingForTab(tabId, false);
      }
      sendResponse(res);
    });
    return true;
  }
  if (msg.type === 'fuin-reveal') {
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
