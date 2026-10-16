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

  window.FuinSyncAnimation = {
    renderSyncChunkToCanvas,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinSyncAnimation;
  }
})(typeof window !== 'undefined' ? window : globalThis);
