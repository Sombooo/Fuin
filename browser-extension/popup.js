'use strict';

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function checkStatus() {
  const dot = document.getElementById('dot');
  const text = document.getElementById('statusText');
  const fillBtn = document.getElementById('fillBtn');
  const domainTag = document.getElementById('domainTag');

  const tab = await currentTab();
  let parsedUrl = null;
  try {
    if (tab && tab.url) parsedUrl = new URL(tab.url);
  } catch {}

  if (!parsedUrl || parsedUrl.protocol !== 'https:') {
    dot.className = 'dot warn';
    if (domainTag) domainTag.textContent = parsedUrl ? parsedUrl.protocol.replace(':', '') : '—';
    text.textContent = parsedUrl?.protocol === 'http:'
      ? 'HTTP bağlantı (Güvensiz)'
      : 'Yalnızca HTTPS sitelerde çalışır';
    fillBtn.disabled = true;
    return;
  }

  const domain = parsedUrl.hostname;
  if (domainTag) domainTag.textContent = domain;

  let res;
  try {
    res = await chrome.runtime.sendMessage({ type: 'fuin-lookup', domain });
  } catch {
    res = { error: 'native-host-unreachable' };
  }

  if (!res || res.error === 'native-host-unreachable') {
    dot.className = 'dot err';
    text.textContent = 'Fuin çalışmıyor veya bağlı değil';
    fillBtn.disabled = true;
  } else if (res.error === 'locked') {
    dot.className = 'dot warn';
    text.textContent = 'Fuin kilitli — önce kilidi açın';
    fillBtn.disabled = true;
  } else if (res.error) {
    dot.className = 'dot err';
    text.textContent = 'Masaüstü uygulamasına ulaşılamadı';
    fillBtn.disabled = true;
  } else {
    const count = Array.isArray(res.matches) ? res.matches.length : 0;
    dot.className = count > 0 ? 'dot ok' : 'dot warn';
    text.textContent = count > 0 ? `${count} eşleşen kayıt bulundu` : 'Bu site için kayıt yok';
    fillBtn.disabled = count === 0;
  }
}

document.getElementById('fillBtn').addEventListener('click', async () => {
  const tab = await currentTab();
  if (!tab || !tab.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill' });
  } catch {
    // Sayfa yeni yüklendiyse veya content script henüz aktif değilse sessizce geç
  }
  window.close();
});

checkStatus();
