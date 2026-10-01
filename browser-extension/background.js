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
    chrome.runtime.sendNativeMessage(HOST_NAME, payload, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[Fuin] Native messaging hatası:', chrome.runtime.lastError.message);
        resolve({ error: 'native-host-unreachable', detail: chrome.runtime.lastError.message });
        return;
      }
      resolve(response || { error: 'empty-response' });
    });
  });
}

let pendingReveal = null;

if (typeof chrome !== 'undefined' && chrome.tabs) {
  if (chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (pendingReveal && pendingReveal.tabId === tabId) {
        const urlChanged = changeInfo.url && changeInfo.url !== pendingReveal.url;
        const loadingNew = changeInfo.status === 'loading' && tab?.url && tab.url !== pendingReveal.url;
        if (urlChanged || loadingNew) {
          pendingReveal.cancelled = true;
          try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
          pendingReveal = null;
        }
      }
    });
  }

  if (chrome.tabs.onRemoved) {
    chrome.tabs.onRemoved.addListener((tabId) => {
      if (pendingReveal && pendingReveal.tabId === tabId) {
        pendingReveal.cancelled = true;
        try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
        pendingReveal = null;
      }
    });
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const isInternalExtension = sender.id === chrome.runtime.id && !sender.tab;
  
  if (isInternalExtension) {
    if (msg.type === 'fuin-lookup' && msg.domain) {
      askFuin({ type: 'lookup', domain: msg.domain }).then(sendResponse);
      return true;
    }
    return;
  }

  // Content script'lerden gelen mesajlar
  if (!sender.tab?.url) return;
  let actualDomain;
  try { actualDomain = new URL(sender.tab.url).hostname; } catch { return; }

  if (msg.type === 'fuin-lookup') {
    askFuin({ type: 'lookup', domain: actualDomain }).then(sendResponse);
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
