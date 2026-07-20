'use strict';

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function checkStatus() {
  const tab = await currentTab();
  let domain = '—';
  try { domain = new URL(tab.url).hostname; } catch {}

  const res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
  console.log('[Fuin] popup lookup cevabı:', res);
  const dot = document.getElementById('dot');
  const text = document.getElementById('statusText');

  if (res.error === 'native-host-unreachable') {
    dot.className = 'dot err'; text.textContent = 'Fuin çalışmıyor: ' + (res.detail || '');
  } else if (res.error === 'locked') {
    dot.className = 'dot err'; text.textContent = 'Fuin kilitli';
  } else if (res.error) {
    dot.className = 'dot err'; text.textContent = 'Bağlanılamadı';
  } else {
    dot.className = 'dot ok';
    text.textContent = res.matches.length ? `${res.matches.length} kayıt bulundu` : 'Bu site için kayıt yok';
  }
}

document.getElementById('fillBtn').addEventListener('click', async () => {
  const tab = await currentTab();
  chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill' });
  window.close();
});

checkStatus();
