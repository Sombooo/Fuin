'use strict';

let currentMatches = [];
let currentDomain = '';

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
      openAppBtn.onclick = (e) => {
        if (!e.isTrusted) return;
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
  title.style.display = 'flex';
  title.style.alignItems = 'center';
  title.style.gap = '5px';
  title.appendChild(createPopupSvg(item.action === 'update' ? 'refresh' : 'hex', 11));
  const titleLabel = document.createElement('span');
  titleLabel.textContent = item.action === 'update' ? 'Şifreyi Güncelle' : 'Yeni Hesap Algılandı';
  title.appendChild(titleLabel);

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
  pwEye.appendChild(createPopupSvg('eye', 12));
  pwEye.title = 'Algılanan şifreyi gör / gizle';
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
      showToast('Hesap Fuin kasasına kaydedildi');
      banner.remove();
      setTimeout(checkStatus, 500);
    }
  });

  const dismissBtn = document.createElement('button');
  dismissBtn.className = 'btn-dismiss-banner';
  dismissBtn.appendChild(createPopupSvg('close', 12));
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
    btnEye.appendChild(createPopupSvg('eye', 12));
    btnEye.title = 'Şifreyi göster / gizle';
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
          showToast('Şifre alınamadı');
          btnEye.replaceChildren(createPopupSvg('eye', 12));
        }
      } catch {
        btnEye.style.opacity = '1';
        showToast('Bağlantı hatası');
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
    btnFill.title = 'Bu hesabı sayfaya doldur';
    btnFill.appendChild(createPopupSvg('fill', 14));
    btnFill.onclick = async (e) => {
      if (!e.isTrusted) return;
      if (tab?.id) {
        await chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill', entryId: m.id });
        window.close();
      }
    };

    // Kullanıcı adı kopyala (30 sn otomatik pano temizlemeli)
    const btnCopyUser = document.createElement('button');
    btnCopyUser.className = 'action-btn';
    btnCopyUser.title = 'Kullanıcı adını kopyala';
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
        showToast('Kullanıcı adı kopyalandı (30 sn)');
        setTimeout(() => btnCopyUser.replaceChildren(createPopupSvg('user', 13)), 1200);
      } else {
        await navigator.clipboard.writeText(m.username);
        showToast('Kullanıcı adı kopyalandı');
      }
    };

    // Şifre kopyala (Fuin masaüstü 30 sn güvenli pano temizlemeli)
    const btnCopyPw = document.createElement('button');
    btnCopyPw.className = 'action-btn';
    btnCopyPw.title = 'Şifreyi kopyala (30 sn sonra silinir)';
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
          showToast('Şifre kopyalandı (30 sn sonra temizlenir)');
          setTimeout(() => btnCopyPw.replaceChildren(createPopupSvg('key', 13)), 1200);
          return;
        }
        if (secRes && secRes.error === 'approval-required') {
          const rev = await chrome.runtime.sendMessage({ type: 'fuin-reveal', entryId: m.id, domain: currentDomain });
          if (rev && rev.password) {
            await navigator.clipboard.writeText(rev.password);
            btnCopyPw.replaceChildren(createPopupSvg('check', 13));
            showToast('Şifre kopyalandı');
            setTimeout(() => btnCopyPw.replaceChildren(createPopupSvg('key', 13)), 1200);
          } else {
            showToast('Onay reddedildi veya şifre alınamadı');
          }
        } else {
          showToast('Hata: Şifre alınamadı');
        }
      } catch {
        showToast('Hata: Bağlantı başarısız');
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

document.getElementById('fillBtn').addEventListener('click', async (e) => {
  if (!e.isTrusted) return;
  const tab = await currentTab();
  if (!tab || !tab.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: 'fuin-trigger-fill' });
  } catch {}
  window.close();
});

checkStatus();
