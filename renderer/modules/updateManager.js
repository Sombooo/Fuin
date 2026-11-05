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
    return '1.0.0-beta.8';
  }

  const GITHUB_RELEASES_URL = 'https://api.github.com/repos/Sombooo/Fuin/releases';
  const UPDATE_FETCH_TIMEOUT_MS = 8000;

  function isTrustedFuinReleaseUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    try {
      const parsed = new URL(rawUrl.trim());
      return (
        parsed.protocol === 'https:' &&
        parsed.hostname === 'github.com' &&
        parsed.pathname.startsWith('/Sombooo/Fuin/')
      );
    } catch {
      return false;
    }
  }

  function isTrustedFuinDownloadUrl(rawUrl) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) return false;
    try {
      const parsed = new URL(rawUrl.trim());
      return (
        parsed.protocol === 'https:' &&
        parsed.hostname === 'github.com' &&
        parsed.pathname.startsWith('/Sombooo/Fuin/releases/download/')
      );
    } catch {
      return false;
    }
  }

  function findPlatformAsset(release) {
    if (!release || !Array.isArray(release.assets)) return null;
    const platform = window.kekkai?.platform || 'darwin';
    let matchers = [];
    if (platform === 'darwin') {
      matchers = [
        a => typeof a.name === 'string' && a.name.toLowerCase().endsWith('.dmg'),
        a => typeof a.name === 'string' && (a.name.toLowerCase().endsWith('-mac.zip') || a.name.toLowerCase().endsWith('.zip'))
      ];
    } else if (platform === 'win32') {
      matchers = [
        a => typeof a.name === 'string' && a.name.toLowerCase().endsWith('.exe')
      ];
    } else {
      matchers = [
        a => typeof a.name === 'string' && a.name.toLowerCase().endsWith('.appimage'),
        a => typeof a.name === 'string' && a.name.toLowerCase().endsWith('.deb')
      ];
    }

    for (const matcher of matchers) {
      const found = release.assets.find(matcher);
      if (found && isTrustedFuinDownloadUrl(found.browser_download_url)) {
        return found;
      }
    }
    return null;
  }

  function isAutoUpdateCheckEnabled() {
    try {
      return typeof localStorage !== 'undefined' && localStorage.getItem('fuin-auto-update-check') !== 'false';
    } catch {
      return true;
    }
  }

  async function fetchReleasesWithTimeout() {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timer = controller ? setTimeout(() => {
      try { controller.abort(); } catch {}
    }, UPDATE_FETCH_TIMEOUT_MS) : null;
    try {
      const res = await fetch(GITHUB_RELEASES_URL, {
        cache: 'no-store',
        redirect: 'error',
        headers: { Accept: 'application/vnd.github+json' },
        signal: controller ? controller.signal : undefined
      });
      if (!res.ok) throw new Error('API error (' + res.status + ')');
      if (res.url && !res.url.startsWith('https://api.github.com/')) {
        throw new Error('Untrusted API response origin');
      }
      return await res.json();
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async function silentCheckForUpdates() {
    if (!isAutoUpdateCheckEnabled()) return;
    try {
      const releases = await fetchReleasesWithTimeout();
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
        const curLabel = t('sysUpdateCurrent', { v: normalizeVersion(currentVersion) }) || `(v${normalizeVersion(currentVersion)})`;
        subEl.textContent = `${t('sysUpdateCheckSub') || "Fuin'in yeni bir sürümü olup olmadığını GitHub üzerinden kontrol edin."} ${curLabel}`;
      }

      const releases = await fetchReleasesWithTimeout();
      if (!Array.isArray(releases) || releases.length === 0) {
        msg.textContent = t('sysUpdateNoReleases') || 'Henüz yayınlanmış bir sürüm bulunamadı.';
        return;
      }

      const latestRelease = releases.find(r => !r.draft) || releases[0];
      const latestVersion = latestRelease?.tag_name;
      
      if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
        msg.textContent = '';
        const vSpan = document.createElement('span');
        vSpan.style.color = 'var(--green)';
        vSpan.style.fontWeight = '600';
        vSpan.textContent = t('sysUpdateNewAvailable', { v: latestVersion }) || `Yeni sürüm mevcut: ${latestVersion}`;
        msg.appendChild(vSpan);

        const asset = findPlatformAsset(latestRelease);
        if (asset && window.kekkai?.downloadUpdate) {
          const dlBtn = document.createElement('button');
          dlBtn.className = 'btn-io pri';
          dlBtn.style.cssText = 'margin-left:10px;padding:4px 10px;font-size:11px;cursor:pointer;';
          dlBtn.textContent = t('sysUpdateDownloadBtn') || 'Uygulama İçinden İndir & Güncelle';

          const progressWrap = document.createElement('div');
          progressWrap.style.cssText = 'display:none;margin-top:8px;width:100%;max-width:320px;';
          progressWrap.innerHTML = `
            <div style="font-size:11px;color:var(--mu);margin-bottom:4px;" class="dl-status-text">${t('sysUpdateDownloading') || 'İndiriliyor'}...</div>
            <div class="update-progress-wrap"><div class="update-progress-bar" style="width:0%;"></div></div>
          `;

          let unregProgress = null;
          dlBtn.addEventListener('click', async () => {
            dlBtn.disabled = true;
            progressWrap.style.display = 'block';
            const statusText = progressWrap.querySelector('.dl-status-text');
            const pBar = progressWrap.querySelector('.update-progress-bar');

            if (window.kekkai?.onUpdateDownloadProgress) {
              unregProgress = window.kekkai.onUpdateDownloadProgress(({ percent, received, total }) => {
                pBar.style.width = Math.min(100, Math.max(0, percent)) + '%';
                const recMB = (received / 1048576).toFixed(1);
                const totMB = total > 0 ? (total / 1048576).toFixed(1) : '?';
                const isEn = typeof document !== 'undefined' && document.documentElement && document.documentElement.lang === 'en';
                const pctStr = isEn ? `${percent}%` : `%${percent}`;
                statusText.textContent = `${t('sysUpdateDownloading') || 'İndiriliyor'}: ${pctStr} (${recMB} MB / ${totMB} MB)`;
              });
            }

            try {
              const res = await window.kekkai.downloadUpdate({
                url: asset.browser_download_url,
                filename: asset.name
              });
              if (res && res.filePath) {
                statusText.textContent = t('sysUpdateDownloaded') || 'İndirme tamamlandı! Yükleyici hazır.';
                pBar.style.width = '100%';
                dlBtn.className = 'btn-io pri';
                dlBtn.textContent = t('sysUpdateInstallBtn') || 'Kurulumu Başlat';
                dlBtn.disabled = false;
                dlBtn.onclick = async () => {
                  await window.kekkai?.installUpdate?.({ filePath: res.filePath });
                };
              }
            } catch (err) {
              statusText.textContent = `${t('sysUpdateFailed') || 'İndirme başarısız oldu'}: ${err.message || 'Error'}`;
              dlBtn.disabled = false;
            } finally {
              if (unregProgress) unregProgress();
            }
          });

          msg.appendChild(dlBtn);
          msg.appendChild(progressWrap);
        }

        // Güvenlik: URL'yi doğrula — yalnızca resmi Sombooo/Fuin GitHub deposunu kabul et
        if (isTrustedFuinReleaseUrl(latestRelease.html_url)) {
          const safeHref = new URL(latestRelease.html_url.trim()).href;
          const link = document.createElement('a');
          link.href = '#';
          link.textContent = t('sysUpdateViewRelease') || 'GitHub Sürüm Notları';
          link.style.cssText = 'color:var(--mu);text-decoration:underline;margin-left:8px;font-size:11px;cursor:pointer;';
          link.addEventListener('click', (ev) => { ev.preventDefault(); window.kekkai?.openUrl(safeHref); });
          msg.appendChild(link);
        }
      } else {
        msg.textContent = t('sysUpdateLatest', { v: normalizeVersion(currentVersion) }) || `En güncel sürümü kullanıyorsunuz (v${normalizeVersion(currentVersion)}).`;
      }
    } catch (err) {
      msg.textContent = t('sysUpdateCheckFailed') || 'Kontrol edilemedi. İnternet bağlantısını kontrol edin veya depo adresini ayarlayın.';
    } finally {
      btn.disabled = false;
      btn.textContent = t('sysUpdateBtn') || 'Şimdi Denetle';
    }
  }

  window.FuinUpdateManager = {
    normalizeVersion,
    isNewerVersion,
    getLocalAppVersion,
    silentCheckForUpdates,
    checkForUpdates,
    isAutoUpdateCheckEnabled,
    findPlatformAsset,
    isTrustedFuinDownloadUrl,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinUpdateManager;
  }
})(typeof window !== 'undefined' ? window : globalThis);
