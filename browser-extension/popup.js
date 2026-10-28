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

    let pendingSaveRes = null;
    try {
      pendingSaveRes = await chrome.runtime.sendMessage({ type: 'fuin-get-pending-save-popup', domain });
    } catch {}

    if (count > 0 && matchesList) {
      renderMatches(currentMatches, matchesList, tab);
      matchesList.style.display = 'flex';
      if (pendingSaveRes && pendingSaveRes.hasPending && pendingSaveRes.item) {
        renderPendingSaveBanner(pendingSaveRes.item, matchesList);
      }
    } else if (matchesList) {
      if (pendingSaveRes && pendingSaveRes.hasPending && pendingSaveRes.item) {
        matchesList.replaceChildren();
        matchesList.style.display = 'flex';
        renderPendingSaveBanner(pendingSaveRes.item, matchesList);
      } else {
        matchesList.style.display = 'none';
      }
    }
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
  title.textContent = item.action === 'update' ? '🔄 Şifreyi Güncelle' : '⬡ Yeni Hesap Algılandı';

  const user = document.createElement('div');
  user.className = 'match-user';
  user.textContent = item.username || '— (İsimsiz)';

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
  pwEye.textContent = '👁';
  pwEye.title = 'Algılanan şifreyi gör / gizle';
  pwEye.style.background = 'transparent';
  pwEye.style.border = 'none';
  pwEye.style.color = 'var(--mu)';
  pwEye.style.fontSize = '11px';
  pwEye.style.cursor = 'pointer';
  pwEye.style.padding = '0';
  pwEye.style.lineHeight = '1';

  let bannerPwShown = false;
  pwEye.addEventListener('click', (e) => {
    e.stopPropagation();
    bannerPwShown = !bannerPwShown;
    pwDots.textContent = bannerPwShown ? (item.password || '—') : '••••••••';
    pwDots.style.color = bannerPwShown ? 'var(--text)' : 'var(--mu)';
    pwEye.textContent = bannerPwShown ? '👁‍🗨' : '👁';
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
  saveBtn.className = 'btn-fill-card';
  saveBtn.textContent = 'Kaydet';
  saveBtn.title = "Fuin'e kaydet";
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
      showToast('Hesap Fuin kasanıza kaydedildi! ✓');
      banner.remove();
      setTimeout(checkStatus, 500);
    }
  });

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'btn-copy-card';
  dismissBtn.textContent = '✕';
  dismissBtn.title = 'Yoksay';
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
    user.textContent = m.username || '— (İsimsiz)';
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
    btnEye.textContent = '👁';
    btnEye.title = 'Şifreyi göster / gizle';
    btnEye.style.background = 'transparent';
    btnEye.style.border = 'none';
    btnEye.style.color = 'var(--mu)';
    btnEye.style.fontSize = '11px';
    btnEye.style.cursor = 'pointer';
    btnEye.style.padding = '0';
    btnEye.style.lineHeight = '1';

    let isRevealed = false;
    let revealTimer = null;
    btnEye.addEventListener('click', async (e) => {
      e.stopPropagation();
      if (isRevealed) {
        isRevealed = false;
        clearTimeout(revealTimer);
        pwDots.textContent = '••••••••';
        pwDots.style.color = 'var(--mu)';
        btnEye.textContent = '👁';
        return;
      }
      btnEye.textContent = '…';
      try {
        const rev = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: m.id, domain: currentDomain });
        if (rev && rev.password) {
          isRevealed = true;
          pwDots.textContent = rev.password;
          pwDots.style.color = 'var(--text)';
          btnEye.textContent = '👁‍🗨';
          clearTimeout(revealTimer);
          revealTimer = setTimeout(() => {
            isRevealed = false;
            pwDots.textContent = '••••••••';
            pwDots.style.color = 'var(--mu)';
            btnEye.textContent = '👁';
          }, 8000);
        } else {
          showToast('Şifre alınamadı');
          btnEye.textContent = '👁';
        }
      } catch {
        showToast('Bağlantı hatası');
        btnEye.textContent = '👁';
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
