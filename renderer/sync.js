'use strict';

const api = window.kekkai;

// ── STATE ─────────────────────────────────────────────────────────
let chunks       = [];
let currentIdx   = 0;
let fps          = 6;
let paused       = false;
let animHandle   = null;
let lastFrameTime= 0;
let encryptedB64 = null; // yeniden build için sakla

// ── API EVENTS ────────────────────────────────────────────────────
api.onSyncChunksReady(payload => {
  chunks = payload.chunks;
  encryptedB64 = payload.encryptedB64; // "yeniden başlat" için sakla — taze transferId/IV üretmek üzere
  startAnimation();
});

api.onSyncError(msg => {
  document.getElementById('preparingText').textContent = t('syncErrorPrefix') + msg;
});

api.onSyncKeyExpired(() => {
  stopAnimation();
  document.getElementById('expiredOverlay').classList.add('show');
  document.getElementById('stStatus').textContent = t('syncTimedOut');
  document.getElementById('stStatus').style.color = 'var(--red)';
});

// ── QR RENDERER ───────────────────────────────────────────────────
const canvas = document.getElementById('qrCanvas');
const ctx    = canvas.getContext('2d');

function renderChunkToCanvas(chunk) {
  const json = JSON.stringify(chunk);

  // qrcode.js → offscreen div → canvas'a çiz
  const div = document.createElement('div');
  div.style.display = 'none';
  document.body.appendChild(div);

  try {
    new QRCode(div, {
      text:           json,
      width:          260,
      height:         260,
      colorDark:      '#2a2520',
      colorLight:     '#ffffff',
      correctLevel:   QRCode.CorrectLevel.M, // Level M
    });

    // qrcode.js canvas'ı div'e ekler
    const qrCanvasEl = div.querySelector('canvas');
    if (qrCanvasEl) {
      ctx.clearRect(0, 0, 260, 260);
      ctx.drawImage(qrCanvasEl, 0, 0, 260, 260);
    }
  } catch(e) {
    // QR chunk çok büyükse uyar
    ctx.fillStyle = '#f5f0e8';
    ctx.fillRect(0,0,260,260);
    ctx.fillStyle = '#a0342a';
    ctx.font = '12px monospace';
    ctx.fillText('Chunk çok büyük', 20, 130);
  } finally {
    document.body.removeChild(div);
  }
}

// ── ANİMASYON ────────────────────────────────────────────────────
// requestAnimationFrame + zaman kontrolü: main thread donmaz
function animate(timestamp) {
  if (paused || !chunks.length) { animHandle = requestAnimationFrame(animate); return; }

  const interval = 1000 / fps;
  if (timestamp - lastFrameTime >= interval) {
    lastFrameTime = timestamp;
    renderFrame();
  }
  animHandle = requestAnimationFrame(animate);
}

function renderFrame() {
  const chunk = chunks[currentIdx];
  renderChunkToCanvas(chunk);

  // UI güncelle
  document.getElementById('stChunk').textContent  = `${chunk.index} / ${chunk.total}`;
  document.getElementById('stStatus').textContent = t('syncTransferring');
  document.getElementById('stStatus').style.color = 'var(--green)';
  document.getElementById('stFps').textContent    = `${fps} FPS`;
  document.getElementById('transferIdVal').textContent = chunk.transferId;
  document.getElementById('chunkBar').style.width = (chunk.index / chunk.total * 100) + '%';

  currentIdx = (currentIdx + 1) % chunks.length;
}

function startAnimation() {
  document.getElementById('preparingOverlay').style.display = 'none';
  currentIdx = 0; lastFrameTime = 0;
  if (animHandle) cancelAnimationFrame(animHandle);
  animHandle = requestAnimationFrame(animate);
}

function stopAnimation() {
  if (animHandle) { cancelAnimationFrame(animHandle); animHandle = null; }
}

// ── KONTROLLER ───────────────────────────────────────────────────
function togglePause() {
  paused = !paused;
  const btn = document.getElementById('pauseBtn');
  if (paused) {
    btn.textContent = t('syncResume');
    btn.classList.remove('pause');
    document.getElementById('stStatus').textContent = t('syncPaused');
    document.getElementById('stStatus').style.color = 'var(--amber)';
  } else {
    btn.textContent = t('syncPause');
    btn.classList.add('pause');
  }
}

function setFps(newFps, btn) {
  fps = newFps;
  document.querySelectorAll('.speed-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('stFps').textContent = `${fps} FPS`;
}

async function resetTransfer() {
  if (paused) togglePause();
  if (!encryptedB64) { currentIdx = 0; lastFrameTime = 0; return; }
  // Taze transferId + IV + tag ile yeni paket üret (eskisini tekrar yayınlamak yerine)
  stopAnimation();
  document.getElementById('preparingOverlay').style.display = 'flex';
  document.getElementById('preparingText').textContent = t('syncPreparingRebuild');
  try {
    const fresh = await api.rebuildChunks(encryptedB64);
    chunks = fresh;
    startAnimation();
  } catch (e) {
    document.getElementById('preparingText').textContent = t('syncErrorPrefix') + e.message;
  }
}

async function closeSyncWindow() {
  stopAnimation();
  await api.clearSyncKey();
  api.closeSyncWindow();
}

// ── BADGE ─────────────────────────────────────────────────────────
async function initBadge() {
  const info = await api.cryptoInfo();
  const badge = document.getElementById('syncBadge');
  badge.textContent = info.argon2 ? 'Argon2id · SyncKey' : 'PBKDF2 · SyncKey';
  badge.style.color  = info.argon2 ? 'var(--green)' : 'var(--amber)';
}
initBadge();
setLanguage(localStorage.getItem('fuin-lang') || 'tr');

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btnCloseSync')?.addEventListener('click', closeSyncWindow);
  document.getElementById('btnFps3')?.addEventListener('click', function() { setFps(3, this); });
  document.getElementById('btnFps6')?.addEventListener('click', function() { setFps(6, this); });
  document.getElementById('btnFps10')?.addEventListener('click', function() { setFps(10, this); });
  document.getElementById('pauseBtn')?.addEventListener('click', togglePause);
  document.getElementById('btnResetTransfer')?.addEventListener('click', resetTransfer);
});
