'use strict';

let currentMatches = [];
let currentDomain = '';

function showToast(text) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = text;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 1500);
}

async function currentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function checkStatus() {
  const dot = document.getElementById('dot');
  const text = document.getElementById('statusText');
  const fillBtn = document.getElementById('fillBtn');
  const domainTag = document.getElementById('domainTag');
  const openAppBtn = document.getElementById('btnOpenApp');
  const matchesList = document.getElementById('matchesList');

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
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
    return;
  }

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
    dot.className = 'dot err';
    text.textContent = 'Fuin kapalı veya bağlı değil';
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
  } else if (res.error === 'locked') {
    dot.className = 'dot warn';
    text.textContent = 'Fuin kilitli';
    fillBtn.disabled = true;
    if (openAppBtn) {
      openAppBtn.style.display = 'block';
      openAppBtn.onclick = () => {
        chrome.runtime.sendMessage({ type: 'fuin-open-app' });
        window.close();
      };
    }
    if (matchesList) matchesList.style.display = 'none';
  } else if (res.error) {
    dot.className = 'dot err';
    text.textContent = 'Masaüstü uygulamasına ulaşılamadı';
    fillBtn.disabled = true;
    if (openAppBtn) openAppBtn.style.display = 'none';
    if (matchesList) matchesList.style.display = 'none';
  } else {
    currentMatches = Array.isArray(res.matches) ? res.matches : [];
    const count = currentMatches.length;
    dot.className = count > 0 ? 'dot ok' : 'dot warn';
    text.textContent = count > 0 ? `${count} kayıt bulundu` : 'Bu site için kayıt yok';
    fillBtn.disabled = count === 0;
    if (openAppBtn) openAppBtn.style.display = 'none';

    if (count > 0 && matchesList) {
      renderMatches(currentMatches, matchesList, tab);
      matchesList.style.display = 'flex';
    } else if (matchesList) {
      matchesList.style.display = 'none';
    }
  }
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
    user.textContent = m.username || '— (İsimsiz)';
    user.title = m.username || '';

    const site = document.createElement('div');
    site.className = 'match-site';
    site.textContent = m.site || currentDomain;

    info.appendChild(user);
    info.appendChild(site);
    card.appendChild(info);

    const actions = document.createElement('div');
    actions.className = 'match-actions';

    // Doldur butonu
    const btnFill = document.createElement('button');
    btnFill.className = 'action-btn fill-btn';
    btnFill.title = 'Bu hesabı sayfaya doldur';
    btnFill.textContent = '🪄';
    btnFill.onclick = async () => {
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill', entryId: m.id });
        window.close();
      }
    };

    // Kullanıcı adı kopyala
    const btnCopyUser = document.createElement('button');
    btnCopyUser.className = 'action-btn';
    btnCopyUser.title = 'Kullanıcı adını kopyala';
    btnCopyUser.textContent = '👤';
    btnCopyUser.onclick = async () => {
      if (m.username) {
        await navigator.clipboard.writeText(m.username);
        showToast('Kullanıcı adı kopyalandı! ✓');
      }
    };

    // Şifre kopyala
    const btnCopyPw = document.createElement('button');
    btnCopyPw.className = 'action-btn';
    btnCopyPw.title = 'Şifreyi kopyala';
    btnCopyPw.textContent = '🔑';
    btnCopyPw.onclick = async () => {
      btnCopyPw.textContent = '…';
      try {
        const rev = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: m.id, domain: currentDomain });
        if (rev && rev.password) {
          await navigator.clipboard.writeText(rev.password);
          showToast('Şifre kopyalandı! ✓');
        } else {
          showToast('Hata: Şifre alınamadı');
        }
      } catch {
        showToast('Hata: Bağlantı başarısız');
      }
      btnCopyPw.textContent = '🔑';
    };

    actions.appendChild(btnFill);
    actions.appendChild(btnCopyUser);
    actions.appendChild(btnCopyPw);
    card.appendChild(actions);

    container.appendChild(card);
  });
}

document.getElementById('fillBtn').addEventListener('click', async () => {
  const tab = await currentTab();
  if (!tab || !tab.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill' });
  } catch {}
  window.close();
});

checkStatus();
