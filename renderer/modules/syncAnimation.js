// ═══════════════════════════════════════════════════════════════════
// FUIN SYNC QR CANVAS & ANIMATION CONTROLLER
// renderer/modules/syncAnimation.js
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  function renderSyncChunkToCanvas(chunk) {
    if (!chunk || !chunk.qrString) return;
    const qrText = chunk.qrString;
    const canvas = document.getElementById('qrCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    const div = document.createElement('div');
    div.style.display = 'none';
    document.body.appendChild(div);

    try {
      if (typeof QRCode !== 'undefined') {
        new QRCode(div, {
          text:         qrText,
          width:        260,
          height:       260,
          colorDark:    '#2a2520',
          colorLight:   '#ffffff',
          correctLevel: QRCode.CorrectLevel.M,
        });
        const qrCanvasEl = div.querySelector('canvas');
        if (qrCanvasEl) {
          ctx.clearRect(0, 0, 260, 260);
          ctx.drawImage(qrCanvasEl, 0, 0, 260, 260);
        }
      }
    } catch (e) {
      ctx.fillStyle = '#f5f0e8';
      ctx.fillRect(0, 0, 260, 260);
      ctx.fillStyle = '#a0342a';
      ctx.font = '12px monospace';
      ctx.fillText('Chunk çok büyük', 20, 130);
    } finally {
      if (div.parentNode) {
        div.parentNode.removeChild(div);
      }
    }
  }

  function renderSyncFrame({ chunk, syncFps, t }) {
    if (!chunk) return;
    renderSyncChunkToCanvas(chunk);
    const stChunk = document.getElementById('stChunk');
    if (stChunk) stChunk.textContent = `${chunk.index} / ${chunk.total}`;
    const stStatus = document.getElementById('stStatus');
    if (stStatus) {
      stStatus.textContent = t('syncTransferring');
      stStatus.style.color = 'var(--green)';
    }
    const stFps = document.getElementById('stFps');
    if (stFps) stFps.textContent = `${syncFps} FPS`;
    const transferIdVal = document.getElementById('transferIdVal');
    if (transferIdVal) transferIdVal.textContent = chunk.sessionId || '';
    const chunkBar = document.getElementById('chunkBar');
    if (chunkBar) chunkBar.style.width = (chunk.index / chunk.total * 100) + '%';
  }

  function updatePauseUI({ syncPaused, t }) {
    const btn = document.getElementById('pauseBtn');
    const stStatus = document.getElementById('stStatus');
    if (!btn) return;
    if (syncPaused) {
      btn.textContent = t('syncResume');
      btn.classList.remove('pause');
      if (stStatus) {
        stStatus.textContent = t('syncPaused');
        stStatus.style.color = 'var(--amber)';
      }
    } else {
      btn.textContent = t('syncPause');
      btn.classList.add('pause');
    }
  }

  function updateFpsUI(newFps, btn) {
    ['btnFps3', 'btnFps6', 'btnFps10'].forEach(id => {
      document.getElementById(id)?.classList.remove('active');
    });
    if (btn) btn.classList.add('active');
    const stFps = document.getElementById('stFps');
    if (stFps) stFps.textContent = `${newFps} FPS`;
  }

  function resetSyncModalDOM(t) {
    document.getElementById('syncOverlay')?.classList.remove('open');
    document.getElementById('expiredOverlay')?.classList.remove('show');
    const prep = document.getElementById('preparingOverlay');
    if (prep) prep.style.display = 'flex';
    const spin = document.querySelector('.qr-preparing .spin');
    if (spin) spin.style.display = 'block';
    const prepText = document.getElementById('preparingText');
    if (prepText) {
      prepText.textContent = t('syncPreparing') || 'PAKET HAZIRLANIYOR...';
      prepText.style.color = '';
    }
  }

  window.FuinSyncAnimation = {
    renderSyncChunkToCanvas,
    renderSyncFrame,
    updatePauseUI,
    updateFpsUI,
    resetSyncModalDOM,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinSyncAnimation;
  }
})(typeof window !== 'undefined' ? window : globalThis);
