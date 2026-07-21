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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Güvenlik: Yalnızca content script'lerden gelen mesajları kabul et
  if (!sender.tab?.url) return;
  // Domain'i sender.tab.url'den türet — content script'in bildirdiği domain'e güvenme
  let actualDomain;
  try { actualDomain = new URL(sender.tab.url).hostname; } catch { return; }

  if (msg.type === 'fuin-lookup') {
    askFuin({ type: 'lookup', domain: actualDomain }).then(sendResponse);
    return true; // async cevap
  }
  if (msg.type === 'fuin-reveal') {
    askFuin({ type: 'reveal', entryId: msg.entryId, domain: actualDomain }).then(sendResponse);
    return true;
  }
});
