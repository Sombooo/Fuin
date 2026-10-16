// ═══════════════════════════════════════════════════════════════════
// FUIN LAN SYNC & PAIRING UI CONTROLLER
// renderer/modules/lanSyncController.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  function updateSyncModeUI(t) {
    const pairedCard = document.getElementById('pairedDevicesCard');
    if (pairedCard) {
      pairedCard.style.display = '';
    }

    const navSyncIcon = document.getElementById('navSyncIcon');
    const navSyncText = document.getElementById('navSyncText');
    if (navSyncIcon && navSyncText) {
      navSyncIcon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;display:inline-block;"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>`;
      navSyncText.textContent = (typeof t === 'function' && t('navSync')) || 'Eşitle';
      navSyncText.setAttribute('data-i18n', 'navSync');
    }
  }

  async function renderPairedDevicesList({ api, t, esc, onRevoke }) {
    if (!api || !api.getPairedDevices) return;
    const listEl = document.getElementById('pairedDevicesList');
    if (!listEl) return;

    const devices = await api.getPairedDevices();
    if (!devices || devices.length === 0) {
      listEl.innerHTML = `
        <div class="paired-empty-card">
          <svg class="paired-empty-icon" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
            <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
            <line x1="12" y1="18" x2="12.01" y2="18"/>
          </svg>
          <div class="paired-empty-title" data-i18n="noPairedDevices">${t('noPairedDevices') || 'Henüz eşleşmiş mobil cihaz yok.'}</div>
          <div class="paired-empty-desc" data-i18n="noPairedDevicesSub">${t('noPairedDevicesSub') || 'Yukarıdaki "Telefon Eşle" butonuna tıklayarak Fuin Mobile ile eşleştirin.'}</div>
        </div>
      `;
      return;
    }

    listEl.innerHTML = devices.map(d => `
      <div class="device-card">
        <div class="device-left">
          <div class="device-icon-wrap">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <rect x="5" y="2" width="14" height="20" rx="2" ry="2"/>
              <line x1="12" y1="18" x2="12.01" y2="18"/>
            </svg>
          </div>
          <div class="device-info">
            <div class="device-title-row">
              <span class="device-name">${esc(d.deviceName || (t('deviceMobileDefault') || 'Mobil Cihaz'))}</span>
              <span class="device-status-badge">
                <span class="badge-dot"></span>
                <span data-i18n="deviceStatusReady">${t('deviceStatusReady') || 'Eşleşti / Hazır'}</span>
              </span>
            </div>
            <div class="device-meta">
              <span>ID: ${esc(d.deviceId)}</span>
              ${d.keyPreview ? `<span class="device-meta-sep">·</span><span class="device-key-pill">${esc(d.keyPreview)}</span>` : ''}
              <span class="device-meta-sep">·</span>
              <span>${t('deviceLastSync') || 'Son eşitleme'}: ${d.lastSyncAt ? new Date(d.lastSyncAt).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'tr-TR') : (t('deviceNeverSynced') || 'Henüz eşitlenmedi')}</span>
            </div>
          </div>
        </div>
        <button class="btn-unlink-device" data-device-id="${esc(d.deviceId)}" title="${t('btnRevokePair') || 'Eşleşmeyi Kaldır'}">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="3 6 5 6 21 6"/>
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
          </svg>
          <span data-i18n="btnRevokePair">${t('btnRevokePair') || 'Eşleşmeyi Kaldır'}</span>
        </button>
      </div>
    `).join('');

    listEl.querySelectorAll('.btn-unlink-device').forEach(btn => {
      btn.addEventListener('click', () => {
        const devId = btn.getAttribute('data-device-id');
        if (devId && typeof onRevoke === 'function') onRevoke(devId);
      });
    });
  }

  function renderPairingQRToCanvas(qrString) {
    const canvas = document.getElementById('pairQrCanvas');
    if (!canvas || typeof QRCode === 'undefined') return;
    const ctx = canvas.getContext('2d');
    const div = document.createElement('div');
    div.style.display = 'none';
    document.body.appendChild(div);

    try {
      new QRCode(div, {
        text: qrString,
        width: 240,
        height: 240,
        colorDark: '#2a2520',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.L,
      });
      const qrCanvasEl = div.querySelector('canvas');
      if (qrCanvasEl) {
        ctx.clearRect(0, 0, 240, 240);
        ctx.drawImage(qrCanvasEl, 0, 0, 240, 240);
      }
    } finally {
      div.remove();
    }
  }

  window.FuinLanSyncUI = {
    updateSyncModeUI,
    renderPairedDevicesList,
    renderPairingQRToCanvas,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinLanSyncUI;
  }
})(typeof window !== 'undefined' ? window : globalThis);
