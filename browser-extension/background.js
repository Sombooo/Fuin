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

function normDomainKey(d) {
  return String(d || '').toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].split(':')[0].trim();
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
  pendingSaveByTab.delete(tabId);
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

      // Sayfa yönlendikten / yüklendikten sonra bekleyen kaydetme bildirimi varsa sekmede tetikle
      if (changeInfo.status === 'complete') {
        const pending = pendingSaveByTab.get(tabId);
        if (pending) {
          if (Date.now() - pending.timestamp < 120000 && !isCredentialDismissed(pending.domain, pending.username, pending.password)) {
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
      pendingSaveByTab.delete(tabId);
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
    if (msg.type === 'fuin-open-app') {
      askFuin({ type: 'open-app' }).then(sendResponse);
      return true;
    }
    if (msg.type === 'fuin-get-pending-save-popup') {
      let found = null;
      for (const [tId, p] of pendingSaveByTab.entries()) {
        if (msg.domain && (p.domain === msg.domain || p.domain.endsWith('.' + msg.domain) || msg.domain.endsWith('.' + p.domain))) {
          if (Date.now() - p.timestamp < 120000 && !isCredentialDismissed(p.domain, p.username, p.password)) {
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
      if (Date.now() - p.timestamp < 120000 && !isCredentialDismissed(p.domain, p.username, p.password)) {
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
    const saveDomain = pendingItem?.domain || actualDomain;
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
