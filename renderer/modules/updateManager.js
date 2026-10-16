// ═══════════════════════════════════════════════════════════════════
// FUIN UPDATE MANAGER
// renderer/modules/updateManager.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  function normalizeVersion(v) {
    return String(v || '').trim().replace(/^v/i, '');
  }

  function isNewerVersion(latest, current) {
    const l = normalizeVersion(latest);
    const c = normalizeVersion(current);
    if (!l || !c || l === c) return false;

    const [lCore, lPre] = l.split('-');
    const [cCore, cPre] = c.split('-');

    const lParts = lCore.split('.').map(x => parseInt(x, 10) || 0);
    const cParts = cCore.split('.').map(x => parseInt(x, 10) || 0);

    for (let i = 0; i < 3; i++) {
      const lp = lParts[i] || 0;
      const cp = cParts[i] || 0;
      if (lp > cp) return true;
      if (lp < cp) return false;
    }

    // Same core version. A release without prerelease is newer than one with (e.g. 1.0.0 > 1.0.0-beta.1)
    if (!lPre && cPre) return true;
    if (lPre && !cPre) return false;

    // Both have prereleases: compare pre parts (e.g. beta.2 > beta.1)
    if (lPre && cPre) {
      const lPreParts = lPre.split('.');
      const cPreParts = cPre.split('.');
      for (let i = 0; i < Math.max(lPreParts.length, cPreParts.length); i++) {
        const lp = lPreParts[i];
        const cp = cPreParts[i];
        if (lp === undefined) return false;
        if (cp === undefined) return true;
        const ln = parseInt(lp, 10);
        const cn = parseInt(cp, 10);
        if (!isNaN(ln) && !isNaN(cn)) {
          if (ln > cn) return true;
          if (ln < cn) return false;
        } else if (lp > cp) return true;
        else if (lp < cp) return false;
      }
    }

    return false;
  }

  async function getLocalAppVersion() {
    try {
      const v = await window.kekkai?.getAppVersion?.();
      if (v) return v;
    } catch {}
    return '1.0.0-beta.3';
  }

  async function silentCheckForUpdates() {
    try {
      const res = await fetch('https://api.github.com/repos/Sombooo/Fuin/releases', { cache: 'no-store' });
      if (!res.ok) return;
      const releases = await res.json();
      if (!Array.isArray(releases) || releases.length === 0) return;
      const latestRelease = releases.find(r => !r.draft) || releases[0];
      const latestVersion = latestRelease?.tag_name;
      const currentVersion = await getLocalAppVersion();
      if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
        const badge = document.getElementById('navUpdateBadge');
        if (badge) badge.style.display = 'block';
      }
    } catch (e) {
      // Sessiz hata (internet yok veya firewall engelledi)
    }
  }

  async function checkForUpdates(t = (k) => k) {
    const btn = document.getElementById('updateBtn');
    const msg = document.getElementById('updateMsg');
    const subEl = document.getElementById('sysUpdateCheckSub');
    if (!btn || !msg) return;
    btn.disabled = true;
    btn.textContent = '...';
    msg.textContent = '';
    
    try {
      const currentVersion = await getLocalAppVersion();
      if (subEl) {
        subEl.textContent = `${t('sysUpdateCheckSub') || "Fuin'in yeni bir sürümü olup olmadığını GitHub üzerinden kontrol edin."} (Mevcut: v${normalizeVersion(currentVersion)})`;
      }

      const res = await fetch('https://api.github.com/repos/Sombooo/Fuin/releases', { cache: 'no-store' });
      if (!res.ok) throw new Error('API error (' + res.status + ')');
      const releases = await res.json();
      if (!Array.isArray(releases) || releases.length === 0) {
        msg.textContent = 'Henüz yayınlanmış bir sürüm bulunamadı.';
        return;
      }

      const latestRelease = releases.find(r => !r.draft) || releases[0];
      const latestVersion = latestRelease?.tag_name;
      
      if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
        msg.textContent = '';
        const vSpan = document.createElement('span');
        vSpan.style.color = 'var(--green)';
        vSpan.textContent = `Yeni sürüm mevcut: ${latestVersion}`;
        msg.appendChild(vSpan);
        // Güvenlik: URL'yi doğrula — sadece github.com domaininden kabul et
        if (latestRelease.html_url && latestRelease.html_url.startsWith('https://github.com/')) {
          const link = document.createElement('a');
          link.href = '#';
          link.textContent = 'İndir';
          link.style.cssText = 'color:var(--text);text-decoration:underline;margin-left:8px;cursor:pointer';
          link.addEventListener('click', (ev) => { ev.preventDefault(); window.kekkai?.openUrl(latestRelease.html_url); });
          msg.appendChild(link);
        }
      } else {
        msg.textContent = `En güncel sürümü kullanıyorsunuz (v${normalizeVersion(currentVersion)}).`;
      }
    } catch (err) {
      msg.textContent = 'Kontrol edilemedi. İnternet bağlantısını kontrol edin veya depo adresini ayarlayın.';
    } finally {
      btn.disabled = false;
      btn.textContent = t('sysUpdateCheckBtn') || 'Güncellemeleri Denetle';
    }
  }

  window.FuinUpdateManager = {
    normalizeVersion,
    isNewerVersion,
    getLocalAppVersion,
    silentCheckForUpdates,
    checkForUpdates,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinUpdateManager;
  }
})(typeof window !== 'undefined' ? window : globalThis);
