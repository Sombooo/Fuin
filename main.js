'use strict';

const { app, BrowserWindow, ipcMain, dialog, clipboard, powerMonitor, shell, Tray, Menu, nativeImage, systemPreferences, safeStorage } = require('electron');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');
const syncV2 = require('./sync-v2.js'); // Phase 4 orchestration
const syncLan = require('./sync-lan.js'); // Hybrid LAN Sync

if (app.isPackaged) {
  console.log = () => {};
  console.error = () => {};
  console.warn = () => {};
}

let argon2, zxcvbn;
try { argon2 = require('argon2'); } catch { argon2 = null; }
try { zxcvbn = require('zxcvbn'); } catch { zxcvbn = null; }

// --- FAZ 3: Hardware & RAM Security ---
let machineId = null;
try {
  const { machineIdSync } = require('node-machine-id');
  machineId = machineIdSync();
} catch {
  const idFile = path.join(app.getPath('userData'), 'fuin.machine-id');
  if (fs.existsSync(idFile)) {
    machineId = fs.readFileSync(idFile, 'utf8').trim();
  } else {
    machineId = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(idFile, machineId, { mode: 0o600 });
  }
}

let sodium = null;
try { sodium = require('sodium-native'); } catch { sodium = null; }

function secureBuffer(buf) {
  if (sodium && buf && Buffer.isBuffer(buf)) {
    try { sodium.sodium_mlock(buf); } catch (e) { /* ignore */ }
  }
}
function unsecureBuffer(buf) {
  if (sodium && buf && Buffer.isBuffer(buf)) {
    try { sodium.sodium_munlock(buf); } catch (e) { /* ignore */ }
  }
}
// --------------------------------------

const DATA_FILE        = path.join(app.getPath('userData'), 'fuin.enc');
const RECOVERY_FILE    = path.join(app.getPath('userData'), 'fuin.recovery');
const MASTER_ENC_FILE  = path.join(app.getPath('userData'), 'fuin.master.enc');
const RECOVERY_STATUS_FILE = path.join(app.getPath('userData'), 'fuin.recovery-status');

let mainWindow;
let tray = null;
let isQuitting = false;

// ── Pencereler ────────────────────────────────────────────────────
function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1100, height: 750, minWidth: 860, minHeight: 600,
    frame: false, backgroundColor: '#f5f0e8',
    webPreferences: {
      nodeIntegration: false, contextIsolation: true, sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  // Ekran koruması: Casus yazılımlara ve ekran kaydına karşı koruma (Siyah ekran verir).
  const DEV_ALLOW_SCREENSHOTS = false;
  if (app.isPackaged && !DEV_ALLOW_SCREENSHOTS) {
    mainWindow.setContentProtection(true);
  } else {
    mainWindow.setContentProtection(false);
  }
  mainWindow.webContents?.on?.('will-navigate', (e) => e.preventDefault());
  mainWindow.webContents?.setWindowOpenHandler?.(() => ({ action: 'deny' }));
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  
  mainWindow.on('minimize', () => {
    if (powerMonitorManager.getIdleLockSeconds() > 0) {
      triggerForceLock('minimized');
    }
  });

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      triggerForceLock('closed');
      mainWindow.hide();
    }
  });
  
  mainWindow.on('closed', () => { mainWindow = null; });
}



app.whenReady().then(() => {
  const { session } = require('electron');
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src https://api.github.com https://api.pwnedpasswords.com;"]
      }
    });
  });
  createWindow();
  createTray();
  app.on('activate', () => {
    if (!mainWindow) createWindow();
    else mainWindow.show();
  });
  powerMonitorManager.initPowerMonitor({
    getIsUnlocked: () => isUnlocked,
    onForceLock: (reason) => triggerForceLock(reason),
    onWarning: (remaining) => mainWindow?.webContents?.send('auto-lock-warning', remaining),
    onWarningCancel: () => mainWindow?.webContents?.send('auto-lock-warning-cancel')
  });
  startExtensionBridge();
  autoInstallNativeMessagingHosts();

  // Cleanup any orphaned recovery transactions from crashes (Task R1)
  cleanupOrphanRecoveryTransactions(app.getPath('userData'));

  // ── Phase 4: Initialize Sync V2 orchestration ─────────────────────────────
  syncV2.initGenerationManager(app.getPath('userData'));
  syncV2.onSessionExpiry(() => {
    mainWindow?.webContents.send('sync-key-expired');
  });

  // ── Hybrid LAN Sync initialization ────────────────────────────────────────
  initLanSync(app.getPath('userData'));
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin' && isQuitting) app.quit(); });
app.on('before-quit', () => {
  isQuitting = true;
  stopExtensionBridge();
  if (_ephemeralLanServer) {
    try { _ephemeralLanServer.stop('quitting'); } catch {}
  }
  if (clipboardTimer) {
    try { clipboard.writeText(''); } catch {}
  }
});

const trayManager = require('./main/trayManager');
const powerMonitorManager = require('./main/powerMonitor');

function createTray() {
  tray = trayManager.initTray({
    Menu,
    Tray,
    nativeImage,
    baseDir: __dirname,
    getMainWindow: () => mainWindow,
    onLock: () => triggerForceLock('tray'),
    onQuit: () => {
      isQuitting = true;
      app.quit();
    }
  });
}

let isUnlocked = false;

// ── ADV-01: Authoritative Vault Snapshot Binding ─────────────────────────────
// Cryptographic binding tracking the active authoritative vault snapshot.
// Plaintext entries are NEVER stored long-lived in main process.
// Only a 32-byte canonical CBOR SHA-256 digest + metadata is maintained.
let _authoritativeVaultSession = null;

function setAuthoritativeVaultSession(entries, dataCiphertext) {
  if (!Array.isArray(entries) || entries.length === 0) {
    _authoritativeVaultSession = null;
    return;
  }
  const binding = syncV2.computeSnapshotHash(entries);
  let dataFileHash = null;
  try {
    if (dataCiphertext) {
      dataFileHash = crypto.createHash('sha256').update(String(dataCiphertext)).digest('hex');
    } else if (fs.existsSync(DATA_FILE)) {
      dataFileHash = crypto.createHash('sha256').update(fs.readFileSync(DATA_FILE)).digest('hex');
    }
  } catch {}

  _authoritativeVaultSession = {
    binding,
    entryCount: entries.length,
    dataFileHash,
    timestamp: Date.now(),
    unlocked: true,
  };
}

function clearAuthoritativeVaultSession() {
  _authoritativeVaultSession = null;
}

function triggerForceLock(reason) {
  powerMonitorManager.stopIdleWatcher();
  isUnlocked = false;
  clearAuthoritativeVaultSession();
  if (_ephemeralLanServer) {
    try { _ephemeralLanServer.stop('vault-locked'); } catch {}
  }
  mainWindow?.webContents?.send('force-lock', reason);
}

// Renderer, unlock()/lock() olduğunda bu state'i main process'e bildirir
ipcMain.handle('set-unlock-state', (_, unlocked) => {
  isUnlocked = !!unlocked;
  if (!isUnlocked) {
    clearAuthoritativeVaultSession();
    if (_ephemeralLanServer) {
      try { _ephemeralLanServer.stop('vault-locked'); } catch {}
    }
  }
  if (isUnlocked) powerMonitorManager.startIdleWatcher(); else powerMonitorManager.stopIdleWatcher();
  return true;
});

ipcMain.handle('set-idle-lock', (_, seconds) => {
  powerMonitorManager.setIdleLockSeconds(seconds);
});

// ===================================================================
// ATOMIC WRITE HELPER (FIX-05)
// ===================================================================
function writeAtomicSync(targetPath, data, options = {}) {
  const mode = options.mode || 0o600;
  const encoding = options.encoding || 'utf8';
  const dir = path.dirname(targetPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const rand = crypto.randomBytes(6).toString('hex');
  const tempPath = path.join(dir, `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.${rand}.tmp`);

  let fd;
  try {
    fd = fs.openSync(tempPath, 'w', mode);
    if (process.platform !== 'win32') {
      try { fs.fchmodSync(fd, mode); } catch {}
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding);
    let offset = 0;
    while (offset < buf.length) {
      offset += fs.writeSync(fd, buf, offset, buf.length - offset);
    }
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }

  try {
    fs.renameSync(tempPath, targetPath);
  } catch (renameErr) {
    if (process.platform === 'win32' && (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY' || renameErr.code === 'EACCES')) {
      let succeeded = false;
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          const start = Date.now();
          while (Date.now() - start < attempt * 10) { /* spin-wait */ }
          fs.renameSync(tempPath, targetPath);
          succeeded = true;
          break;
        } catch {}
      }
      if (!succeeded) {
        try { fs.unlinkSync(tempPath); } catch {}
        throw renameErr;
      }
    } else {
      try { fs.unlinkSync(tempPath); } catch {}
      throw renameErr;
    }
  }
}

// ===================================================================
// ATOMIC RECOVERY PAIR PERSISTENCE (TASK R1)
// ===================================================================

function validateRecoveryPayload(val, name) {
  if (val === undefined || val === null) {
    throw new Error(`Invalid recovery payload: ${name} is required`);
  }
  if (typeof val !== 'string' && !Buffer.isBuffer(val)) {
    throw new Error(`Invalid recovery payload: ${name} must be a string or Buffer`);
  }
  if (typeof val === 'string' && val.trim().length === 0) {
    throw new Error(`Invalid recovery payload: ${name} cannot be empty`);
  }
  if (Buffer.isBuffer(val) && val.length === 0) {
    throw new Error(`Invalid recovery payload: ${name} cannot be an empty buffer`);
  }
}

function writeAndFsyncSync(filePath, data, mode = 0o600) {
  let fd;
  try {
    fd = fs.openSync(filePath, 'w', mode);
    if (process.platform !== 'win32') {
      try { fs.fchmodSync(fd, mode); } catch {}
    }
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
    let offset = 0;
    while (offset < buf.length) {
      offset += fs.writeSync(fd, buf, offset, buf.length - offset);
    }
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }
}

function safeRenameSync(sourcePath, targetPath) {
  try {
    fs.renameSync(sourcePath, targetPath);
  } catch (renameErr) {
    if (process.platform === 'win32' && (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY' || renameErr.code === 'EACCES')) {
      let succeeded = false;
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          const start = Date.now();
          while (Date.now() - start < attempt * 10) { /* spin-wait */ }
          fs.renameSync(sourcePath, targetPath);
          succeeded = true;
          break;
        } catch {}
      }
      if (!succeeded) throw renameErr;
    } else {
      throw renameErr;
    }
  }
}

function cleanupOrphanRecoveryTransactions(userDataDir) {
  if (!userDataDir || !fs.existsSync(userDataDir)) return;
  try {
    const files = fs.readdirSync(userDataDir);
    const recoveryFile = path.join(userDataDir, 'fuin.recovery');

    // Process orphan rollback files
    const rollbackFiles = files.filter(f => f.startsWith('.fuin.recovery.') && f.endsWith('.rollback'));
    for (const rf of rollbackFiles) {
      const rollbackPath = path.join(userDataDir, rf);
      const txId = rf.slice('.fuin.recovery.'.length, -'.rollback'.length);
      const commitMarkerPath = path.join(userDataDir, `.fuin.recovery.${txId}.commit`);

      if (fs.existsSync(commitMarkerPath)) {
        // Window 5 crash: Stage 2 succeeded and was committed!
        // Complete forward: discard rollback file and commit marker
        try { fs.unlinkSync(rollbackPath); } catch {}
        try { fs.unlinkSync(commitMarkerPath); } catch {}
      } else {
        // Window 3 or 4 crash: Stage 2 failed or was not reached
        // Roll back: restore original recovery file
        try {
          safeRenameSync(rollbackPath, recoveryFile);
        } catch {
          try { fs.unlinkSync(rollbackPath); } catch {}
        }
      }
    }

    // Clean up any dangling commit markers that have no rollback file
    const commitFiles = files.filter(f => f.startsWith('.fuin.recovery.') && f.endsWith('.commit'));
    for (const cf of commitFiles) {
      try { fs.unlinkSync(path.join(userDataDir, cf)); } catch {}
    }

    // Clean up stale temporary files older than 60 seconds
    const now = Date.now();
    const staleTmpFiles = files.filter(f => (f.startsWith('.fuin.recovery.') || f.startsWith('.fuin.master.enc.')) && f.endsWith('.tmp'));
    for (const tf of staleTmpFiles) {
      const tmpPath = path.join(userDataDir, tf);
      try {
        const stat = fs.statSync(tmpPath);
        if (now - stat.mtimeMs > 60000) {
          fs.unlinkSync(tmpPath);
        }
      } catch {}
    }
  } catch (e) {
    console.error('Cleanup orphan recovery error:', e);
  }
}

function saveRecoveryPairSync(arg1, arg2, arg3, arg4) {
  let userDataDir, recoveryData, masterEncData, hooks;
  if (arguments.length >= 3 && typeof arg1 === 'string' && (path.isAbsolute(arg1) || arg1.includes(path.sep) || fs.existsSync(arg1))) {
    userDataDir = arg1;
    recoveryData = arg2;
    masterEncData = arg3;
    hooks = arg4 || {};
  } else {
    userDataDir = (typeof app !== 'undefined' && app.getPath) ? app.getPath('userData') : null;
    recoveryData = arg1;
    masterEncData = arg2;
    hooks = arg3 || {};
  }

  validateRecoveryPayload(recoveryData, 'recoveryData');
  validateRecoveryPayload(masterEncData, 'masterEncData');

  if (!userDataDir) {
    throw new Error('userData directory is not configured');
  }

  if (!fs.existsSync(userDataDir)) {
    fs.mkdirSync(userDataDir, { recursive: true, mode: 0o700 });
  }

  const targetRecovery = path.join(userDataDir, 'fuin.recovery');
  const targetMasterEnc = path.join(userDataDir, 'fuin.master.enc');
  const targetStatus = path.join(userDataDir, 'fuin.recovery-status');

  const txId = `${process.pid}.${Date.now()}.${crypto.randomBytes(16).toString('hex')}`;
  const tempRecovery = path.join(userDataDir, `.${path.basename(targetRecovery)}.${txId}.tmp`);
  const tempMasterEnc = path.join(userDataDir, `.${path.basename(targetMasterEnc)}.${txId}.tmp`);
  const rollbackRecovery = path.join(userDataDir, `.${path.basename(targetRecovery)}.${txId}.rollback`);
  const commitMarker = path.join(userDataDir, `.${path.basename(targetRecovery)}.${txId}.commit`);

  const originalRecoveryExists = fs.existsSync(targetRecovery);
  let originalRecoveryData = null;
  if (originalRecoveryExists) {
    try { originalRecoveryData = fs.readFileSync(targetRecovery); } catch {}
  }

  let recoveryPublished = false;
  let masterEncPublished = false;

  try {
    // 1. Write and fsync temporary files with mode 0o600
    writeAndFsyncSync(tempRecovery, recoveryData, 0o600);
    if (hooks && hooks.failAfterRecoveryTempWrite) {
      throw new Error('SIMULATED_FAIL_AFTER_RECOVERY_TEMP_WRITE');
    }

    writeAndFsyncSync(tempMasterEnc, masterEncData, 0o600);
    if (hooks && hooks.failAfterMasterTempWrite) {
      throw new Error('SIMULATED_FAIL_AFTER_MASTER_TEMP_WRITE');
    }

    // 2. Stage rollback copy if targetRecovery already exists
    if (originalRecoveryExists) {
      fs.copyFileSync(targetRecovery, rollbackRecovery);
      if (process.platform !== 'win32') {
        try { fs.chmodSync(rollbackRecovery, 0o600); } catch {}
      }
    }

    // 3. Atomically publish recovery file
    if (hooks && hooks.failBeforeRecoveryRename) {
      throw new Error('SIMULATED_FAIL_BEFORE_RECOVERY_RENAME');
    }
    safeRenameSync(tempRecovery, targetRecovery);
    recoveryPublished = true;

    // 4. Atomically publish master.enc file
    if (hooks && hooks.failBeforeMasterRename) {
      throw new Error('SIMULATED_FAIL_BEFORE_MASTER_RENAME');
    }
    safeRenameSync(tempMasterEnc, targetMasterEnc);
    masterEncPublished = true;

    // 4.5 Commit marker: signals transaction completed forward (Window 5 fix)
    writeAndFsyncSync(commitMarker, JSON.stringify({ committedAt: Date.now(), txId }), 0o600);
    if (hooks && hooks.failAfterCommitMarker) {
      throw new Error('SIMULATED_FAIL_AFTER_COMMIT_MARKER');
    }

    // 5. Cleanup rollback staging
    if (fs.existsSync(rollbackRecovery)) {
      try { fs.unlinkSync(rollbackRecovery); } catch {}
    }

    // 5.5 Cleanup commit marker
    if (fs.existsSync(commitMarker)) {
      try { fs.unlinkSync(commitMarker); } catch {}
    }

    // 6. Update recovery status coherently
    if (typeof app !== 'undefined' && app.getPath && userDataDir === app.getPath('userData')) {
      setRecoveryLegacyBound(false);
      backupFile(targetRecovery);
      backupFile(targetMasterEnc);
    } else {
      const statusData = JSON.stringify({ version: 1, legacyBound: false, updatedAt: Date.now() });
      const tempStatus = path.join(userDataDir, `.${path.basename(targetStatus)}.${txId}.tmp`);
      writeAndFsyncSync(tempStatus, statusData, 0o600);
      safeRenameSync(tempStatus, targetStatus);
    }

    return true;
  } catch (err) {
    // Clean up temporary files
    try { if (fs.existsSync(tempRecovery)) fs.unlinkSync(tempRecovery); } catch {}
    try { if (fs.existsSync(tempMasterEnc)) fs.unlinkSync(tempMasterEnc); } catch {}

    // Rollback logic: if recovery was published but master.enc failed
    if (recoveryPublished && !masterEncPublished) {
      try {
        if (originalRecoveryExists && fs.existsSync(rollbackRecovery)) {
          safeRenameSync(rollbackRecovery, targetRecovery);
        } else if (originalRecoveryExists && originalRecoveryData !== null) {
          writeAndFsyncSync(targetRecovery, originalRecoveryData, 0o600);
        } else {
          try { if (fs.existsSync(targetRecovery)) fs.unlinkSync(targetRecovery); } catch {}
        }
      } catch (rollbackErr) {
        console.error('[saveRecoveryPairSync] CRITICAL: Rollback failed:', rollbackErr);
      }
    }

    // Always clean up rollback file if it still exists (unless simulating Window 5 crash)
    if (!hooks || !hooks.failAfterCommitMarker) {
      try { if (fs.existsSync(rollbackRecovery)) fs.unlinkSync(rollbackRecovery); } catch {}
      try { if (fs.existsSync(commitMarker)) fs.unlinkSync(commitMarker); } catch {}
    }

    throw err;
  }
}

// FAZ 3 — TOUCH ID & SAFE STORAGE
ipcMain.handle('check-touchid-available', () => {
  if (process.platform !== 'darwin') return false;
  if (!safeStorage.isEncryptionAvailable()) return false;
  try {
    if (!systemPreferences.canPromptTouchID()) return false;
    const p = path.join(app.getPath('userData'), 'fuin.touchid.enc');
    return fs.existsSync(p);
  } catch (e) {
    return false;
  }
});

ipcMain.handle('touchid-unlock', async () => {
  if (process.platform !== 'darwin') return null;
  try {
    // 1. Önce biyometrik doğrula — başarısızsa anahtar asla okunmaz
    await systemPreferences.promptTouchID('Fuin kasanızı açmak için Touch ID kullanın');
    
    // 2. Sadece biyometrik başarılıysa anahtarı oku
    const p = path.join(app.getPath('userData'), 'fuin.touchid.enc');
    if (!fs.existsSync(p)) return null;
    const buf = fs.readFileSync(p);
    return safeStorage.decryptString(buf);
  } catch (e) {
    return null; // biyometrik reddedildi veya hata
  }
});

ipcMain.handle('save-touchid-key', (_, key) => {
  try {
    const buf = safeStorage.encryptString(key);
    const p = path.join(app.getPath('userData'), 'fuin.touchid.enc');
    writeAtomicSync(p, buf, { mode: 0o600 });
    return true;
  } catch (e) {
    return false;
  }
});

ipcMain.handle('clear-touchid-key', () => {
  try {
    const p = path.join(app.getPath('userData'), 'fuin.touchid.enc');
    if (fs.existsSync(p)) fs.unlinkSync(p);
    return true;
  } catch (e) {
    return false;
  }
});

ipcMain.on('win-minimize', () => mainWindow?.minimize());
ipcMain.on('win-maximize', () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow?.maximize());
ipcMain.on('win-close',    () => mainWindow?.close());
ipcMain.on('sync-win-close', () => syncV2.cancelSyncSession());

// ═══════════════════════════════════════════════════════════════════
// CRYPTO CORE
// ═══════════════════════════════════════════════════════════════════

// vaultKey ve syncKey FARKLI salt'larla türetilir.
// İki salt: biri vault dosyasına gömülü (encryptData'dan gelir),
// diğeri syncSalt — her sync oturumu için ayrı üretilir.
// Böylece vaultKey ↔ syncKey arasında hiçbir matematiksel ilişki kalmaz.

async function deriveVaultKey(passwordStr, vaultSalt, bindHardware = false) {
  if (typeof passwordStr !== 'string' || passwordStr.length > 1024) throw new Error('Invalid password length');
  const pwBuf = Buffer.from(passwordStr, 'utf8');
  secureBuffer(pwBuf);
  
  let actualSalt = vaultSalt;
  if (bindHardware && machineId) {
    actualSalt = Buffer.concat([vaultSalt, Buffer.from(machineId, 'utf8')]);
  }

  let key;

  if (!argon2) {
    unsecureBuffer(pwBuf);
    pwBuf.fill(0);
    throw new Error('CRITICAL: Argon2 native module is unavailable; refusing insecure KDF downgrade.');
  }

  try {
    const raw = await argon2.hash(pwBuf, {
      type: argon2.argon2id, salt: actualSalt,
      memoryCost: 131072, timeCost: 4, parallelism: 1,
      hashLength: 32, raw: true,
    });
    key = Buffer.from(raw);
    secureBuffer(key);
    raw.fill(0);
  } catch (err) {
    unsecureBuffer(pwBuf);
    pwBuf.fill(0);
    throw new Error(`Argon2id key derivation failed: ${err.message}`);
  }

  unsecureBuffer(pwBuf);
  pwBuf.fill(0);
  return key; // caller'ın fill(0) ve unsecureBuffer sorumluluğu
}

// AES-256-GCM şifreleme — vaultKey ile
async function encryptData(plaintext, passwordStr) {
  if (plaintext && plaintext.type === 'fuin/vault' && Array.isArray(plaintext.entries)) {
    setAuthoritativeVaultSession(plaintext.entries, null);
  }
  const vaultSalt = crypto.randomBytes(32);
  const iv        = crypto.randomBytes(12);
  const vaultKey  = await deriveVaultKey(passwordStr, vaultSalt, false);

  const jsonBuf = Buffer.from(JSON.stringify(plaintext), 'utf8');
  secureBuffer(jsonBuf);
  
  const cipher  = crypto.createCipheriv('aes-256-gcm', vaultKey, iv);
  const enc1    = cipher.update(jsonBuf);
  const enc2    = cipher.final();
  const tag     = cipher.getAuthTag();

  unsecureBuffer(vaultKey);
  vaultKey.fill(0);
  unsecureBuffer(jsonBuf);
  jsonBuf.fill(0);

  return Buffer.concat([vaultSalt, iv, tag, enc1, enc2]).toString('base64');
}

// Güvenlik: Brute-force rate limiting — başarısız denemelerden sonra üstel gecikme
function loadLockoutState() {
  const p = path.join(app.getPath('userData'), 'fuin.lockout');
  if (!fs.existsSync(p)) return { count: 0, until: 0 };
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    if (!raw.data || !raw.hmac) return { count: 0, until: 0 }; // If corrupted or old format, just reset. Penalizing here causes legitimate users to be locked out if they update from old version!
    const hmac = crypto.createHmac('sha256', machineId || 'fallback').update(raw.data).digest('hex');
    const hmacBuf = Buffer.from(hmac, 'utf8');
    const rawHmacBuf = Buffer.from(String(raw.hmac), 'utf8');
    if (hmacBuf.length !== rawHmacBuf.length || !crypto.timingSafeEqual(hmacBuf, rawHmacBuf)) return { count: 0, until: 0 };
    const data = JSON.parse(raw.data);
    return { count: data.count || 0, until: data.until || 0 };
  } catch { return { count: 0, until: 0 }; }
}

function saveLockoutState(count, until) {
  try {
    const p = path.join(app.getPath('userData'), 'fuin.lockout');
    const dataStr = JSON.stringify({ count, until });
    const hmac = crypto.createHmac('sha256', machineId || 'fallback').update(dataStr).digest('hex');
    writeAtomicSync(p, JSON.stringify({ data: dataStr, hmac }), { encoding: 'utf8', mode: 0o600 });
  } catch {}
}

// ADV-03: Recovery material migration status tracking
function getRecoveryStatus() {
  const exists = fs.existsSync(RECOVERY_FILE);
  if (!exists) {
    return { exists: false, legacyBound: false };
  }
  if (!fs.existsSync(RECOVERY_STATUS_FILE)) {
    return { exists: true, legacyBound: false, statusUnknown: true };
  }
  try {
    const raw = JSON.parse(fs.readFileSync(RECOVERY_STATUS_FILE, 'utf8'));
    return { exists: true, legacyBound: !!raw.legacyBound, updatedAt: raw.updatedAt || null };
  } catch {
    return { exists: true, legacyBound: false };
  }
}

function setRecoveryLegacyBound(bound) {
  try {
    const data = JSON.stringify({ version: 1, legacyBound: !!bound, updatedAt: Date.now() });
    writeAtomicSync(RECOVERY_STATUS_FILE, data, { encoding: 'utf8', mode: 0o600 });
  } catch (err) {
    console.error('Failed to save recovery status:', err);
  }
}

// AES-256-GCM şifre çözme — vaultKey ile
async function decryptData(b64Str, passwordStr) {
  // Brute-force koruması: üstel geri çekilme
  const lockout = loadLockoutState();
  const now = Date.now();
  if (now < lockout.until) {
    const waitSec = Math.ceil((lockout.until - now) / 1000);
    throw new Error(`Too many attempts. Wait ${waitSec}s`);
  }

  const buf       = Buffer.from(b64Str, 'base64');
  const vaultSalt = buf.slice(0, 32);
  const iv        = buf.slice(32, 44);
  const tag       = buf.slice(44, 60);
  const data      = buf.slice(60);
  
  let vaultKey;
  
  // FIX-04 Pass 1: Try portable standard key first (no machineId)
  try {
    vaultKey = await deriveVaultKey(passwordStr, vaultSalt, false);
    const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey, iv);
    decipher.setAuthTag(tag);
    let dec1 = decipher.update(data);
    let dec2 = decipher.final();
    
    unsecureBuffer(vaultKey);
    vaultKey.fill(0);
    
    secureBuffer(dec1); secureBuffer(dec2);
    const jsonStr = Buffer.concat([dec1, dec2]).toString('utf8');
    unsecureBuffer(dec1); unsecureBuffer(dec2);
    dec1.fill(0); dec2.fill(0);
    
    saveLockoutState(0, 0); // başarılı — sayacı sıfırla
    const parsedVault = JSON.parse(jsonStr);
    if (parsedVault && parsedVault.type === 'fuin/vault' && Array.isArray(parsedVault.entries)) {
      setAuthoritativeVaultSession(parsedVault.entries, b64Str);
    }
    return parsedVault;
  } catch (e) {
    if (vaultKey) { unsecureBuffer(vaultKey); vaultKey.fill(0); }
    
    // FIX-04 Pass 2: Backward compatibility for existing hardware-bound vaults
    if (machineId) {
      try {
        vaultKey = await deriveVaultKey(passwordStr, vaultSalt, true);
        const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey, iv);
        decipher.setAuthTag(tag);
        let dec1 = decipher.update(data);
        let dec2 = decipher.final();
        
        unsecureBuffer(vaultKey);
        vaultKey.fill(0);
        
        secureBuffer(dec1); secureBuffer(dec2);
        const jsonStr = Buffer.concat([dec1, dec2]).toString('utf8');
        unsecureBuffer(dec1); unsecureBuffer(dec2);
        dec1.fill(0); dec2.fill(0);
        
        saveLockoutState(0, 0);
        console.log('[decryptData] Decrypted with legacy hardware-bound key (ready for portable re-encryption)');

        // ADV-03: If recovery material exists, record that it remains bound to legacy hardware
        if (fs.existsSync(RECOVERY_FILE) || fs.existsSync(MASTER_ENC_FILE)) {
          setRecoveryLegacyBound(true);
        }

        const parsedVault = JSON.parse(jsonStr);
        if (parsedVault && parsedVault.type === 'fuin/vault' && Array.isArray(parsedVault.entries)) {
          setAuthoritativeVaultSession(parsedVault.entries, b64Str);
        }
        return parsedVault;
      } catch (e2) {
        if (vaultKey) { unsecureBuffer(vaultKey); vaultKey.fill(0); }
      }
    }
    
    lockout.count++;
    const delay = Math.min(1000 * Math.pow(2, lockout.count), 300000); // max 5 dk
    saveLockoutState(lockout.count, Date.now() + delay);
    throw new Error('Decryption failed');
  }
}

function safeCompare(a, b) {
  const key = crypto.randomBytes(32);
  const h1 = crypto.createHmac('sha256', key).update(String(a)).digest();
  const h2 = crypto.createHmac('sha256', key).update(String(b)).digest();
  return crypto.timingSafeEqual(h1, h2);
}

ipcMain.on('open-url', (e, url) => {
  // Güvenlik: URL'yi doğrula — yalnızca https:// ve http:// kabul et
  try {
    const parsed = new URL(url);
    if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
      shell.openExternal(parsed.href);
    }
  } catch { /* geçersiz URL — yoksay */ }
});

// ── IPC: Temel crypto ─────────────────────────────────────────────
ipcMain.handle('encrypt',      async (_, { data, password }) => encryptData(data, password));
ipcMain.handle('decrypt',      async (_, { b64, password })  => decryptData(b64, password));
ipcMain.handle('safe-compare', (_,    { a, b })              => safeCompare(a, b));

ipcMain.handle('zxcvbn', (_, password) => {
  if (!zxcvbn) return null;
  const r = zxcvbn(password);
  return {
    score: r.score,
    crackTime: r.crack_times_display.offline_slow_hashing_1e4_per_second,
    warning: r.feedback?.warning || '',
    suggestions: r.feedback?.suggestions || [],
  };
});

ipcMain.handle('crypto-info', () => ({
  argon2:      !!argon2,
  zxcvbn:      !!zxcvbn,
  dualKey:     true,
  separateSalts: true,
  // Vault KDF (portable-first, legacy fallback)
  vaultKdf:    argon2 ? 'Argon2id (128MB, 4 iter, portable-first)' : 'PBKDF2-SHA512 (310k iter)',
  kdf:         argon2 ? 'Argon2id (128MB, 4 iter, portable-first)' : 'PBKDF2-SHA512 (310k iter)',
  // Sync V2 KDF — Argon2id ONLY, PBKDF2 fallback yok
  syncKdf:     argon2 ? 'Argon2id V2 (64MB, t=3, p=4) — XChaCha20-Poly1305' : null,
  syncV2Ready: !!argon2, // Argon2 yoksa Sync V2 başlatılamaz
  argon2Warning: !argon2, // Renderer'da uyarı göstermek için
}));

ipcMain.handle('get-app-version', () => app.getVersion());

// ── IPC: Sync V2 session ──────────────────────────────────────────
//
// 'open-sync-window': V2 entry point.
//
// Caller contract (from renderer/app.js openSyncWindow):
//   password     = Vault Password (used to decrypt vault via decryptData)
//   syncPassword = Sync Password (feeds deriveSyncKey — MUST be separate)
//   entries      = plaintext vault entries already decrypted in renderer
//
// SECURITY NOTE:
//   The renderer already decrypts the vault and passes plaintext entries.
//   This is consistent with the existing architecture where the renderer
//   calls api.openSyncWindow(master, jsonStr) with already-plaintext data.
//   Phase 4 keeps this boundary unchanged: renderer passes entries,
//   main.js runs the V2 crypto pipeline.
//
//   Vault Password (password) is NOT passed to deriveSyncKey().
//   Only syncPassword feeds the Sync Key derivation (INV-01).
//
ipcMain.handle('open-sync-window', async (event, { syncPassword, entries }) => {
  const sendToWindow = (channel, data) => {
    try { event?.sender?.send(channel, data); } catch {}
    try {
      if (mainWindow?.webContents && mainWindow.webContents !== event?.sender) {
        mainWindow.webContents.send(channel, data);
      }
    } catch {}
  };

  if (!isUnlocked || !_authoritativeVaultSession || !_authoritativeVaultSession.unlocked || !_authoritativeVaultSession.binding) {
    sendToWindow('sync-error', 'SYNC_V2: Vault is locked or no authoritative vault session active');
    return false;
  }
  let effectivePassword = syncPassword;
  if (!effectivePassword || effectivePassword === '__PAIRED_DEVICE__' || effectivePassword === 'paired') {
    try {
      const pm = getPairingManager();
      if (pm && Array.isArray(pm.pairedDevices) && pm.pairedDevices.length > 0 && pm.pairedDevices[0].pairKeyHex) {
        effectivePassword = pm.pairedDevices[0].pairKeyHex;
      }
    } catch {}
  }
  if (!effectivePassword || typeof effectivePassword !== 'string' || effectivePassword.trim().length === 0) {
    sendToWindow('sync-error', 'SYNC_V2: syncPassword is required and must be non-empty');
    return false;
  }
  if (!entries) {
    sendToWindow('sync-error', 'SYNC_V2: entries array is required');
    return false;
  }

  // ADV-01: Invariant Enforcement via Cryptographic Binding
  try {
    const entryArray = typeof entries === 'string' ? JSON.parse(entries) : entries;
    if (!Array.isArray(entryArray) || entryArray.length === 0) {
      throw new Error('SYNC_V2: entries must be a non-empty array representing full vault');
    }

    // Check 1: Entry count must strictly match authoritative session count
    if (entryArray.length !== _authoritativeVaultSession.entryCount) {
      throw new Error(`SYNC_V2: Entry count mismatch — received ${entryArray.length}, authoritative vault contains ${_authoritativeVaultSession.entryCount}`);
    }

    // Check 2: Verify disk state consistency if hash is recorded
    if (_authoritativeVaultSession.dataFileHash && fs.existsSync(DATA_FILE)) {
      try {
        const currentDiskHash = crypto.createHash('sha256').update(fs.readFileSync(DATA_FILE)).digest('hex');
        if (!safeCompare(currentDiskHash, _authoritativeVaultSession.dataFileHash)) {
          throw new Error('SYNC_V2: Authoritative vault file on disk does not match active session state');
        }
      } catch (diskErr) {
        throw new Error(`SYNC_V2: Failed to verify disk state: ${diskErr.message}`);
      }
    }

    // Check 3: Cryptographic snapshot binding verification (SHA-256 of Canonical CBOR)
    const candidateBinding = syncV2.computeSnapshotHash(entryArray);
    if (!candidateBinding || candidateBinding.length !== 32) {
      throw new Error('SYNC_V2: Failed to compute candidate snapshot hash');
    }

    if (!crypto.timingSafeEqual(candidateBinding, _authoritativeVaultSession.binding)) {
      throw new Error('SYNC_V2: Integrity violation — submitted entries do not match authoritative vault snapshot');
    }

    const result = await syncV2.buildV2QRChunks(entryArray, effectivePassword);
    sendToWindow('sync-chunks-ready', {
      // Send V2 QR strings. The renderer renders each string directly as QR.
      chunks: result.qrChunks.map((qr, i) => ({
        // V2 QR string in protocol format: FUIN|2|...|index/total|crc|base45
        qrString:   qr,
        index:      i + 1,
        total:      result.total,
        sessionId:  result.sessionIdHex,
        v2:         true,
      })),
      sessionIdHex: result.sessionIdHex,
      generation:   result.generation,
      total:        result.total,
      // encryptedB64 is null for V2 — not used
      encryptedB64: null,
    });
    return true;
  } catch (e) {
    console.error('[open-sync-window] Error:', e.stack || e.message);
    sendToWindow('sync-error', e.message);
    return false;
  }
});

ipcMain.handle('clear-sync-key', () => {
  syncV2.cancelSyncSession();
  return true;
});

// ── IPC: LAN Sync & Pairing (Hybrid Sync R1, R2, R4) ───────────────
let _pairingManager = null;
let _ephemeralLanServer = null;
let _activeLanEntries = null;

function initLanSync(userDataPath) {
  if (_pairingManager) return;
  _pairingManager = new syncLan.PairingManager(userDataPath);
  _ephemeralLanServer = new syncLan.EphemeralServer({
    pairingManager: _pairingManager,
    getVaultEntries: () => _activeLanEntries || [],
    applyMergedEntries: (mergedEntries, stats) => {
      if (mainWindow?.webContents) {
        mainWindow.webContents.send('lan-sync-applied', { entries: mergedEntries, stats });
      }
    },
    onDevicePaired: (device) => {
      if (mainWindow?.webContents) {
        mainWindow.webContents.send('lan-device-paired', device);
      }
    }
  });

  _ephemeralLanServer.onClosed((reason) => {
    if (Array.isArray(_activeLanEntries)) {
      _activeLanEntries.length = 0;
    }
    _activeLanEntries = null;
    if (mainWindow?.webContents) {
      mainWindow.webContents.send('lan-sync-closed', { reason });
    }
  });
}

function getPairingManager() {
  if (!_pairingManager) {
    initLanSync(app.getPath('userData'));
  }
  return _pairingManager;
}

function getEphemeralLanServer() {
  if (!_ephemeralLanServer) {
    initLanSync(app.getPath('userData'));
  }
  return _ephemeralLanServer;
}

function getSavedSyncMode() {
  try {
    const p = path.join(app.getPath('userData'), 'fuin.sync-mode');
    if (fs.existsSync(p)) {
      const mode = fs.readFileSync(p, 'utf8').trim();
      if (mode === 'airgap' || mode === 'lan') return mode;
    }
  } catch {}
  return 'lan'; // Default (R4)
}

ipcMain.handle('lan-get-sync-mode', () => getSavedSyncMode());

ipcMain.handle('lan-set-sync-mode', (_, mode) => {
  const targetMode = mode === 'airgap' ? 'airgap' : 'lan';
  try {
    const p = path.join(app.getPath('userData'), 'fuin.sync-mode');
    writeAtomicSync(p, targetMode, { mode: 0o600 });
  } catch {}
  if (targetMode === 'airgap' && _ephemeralLanServer) {
    _ephemeralLanServer.stop('mode-switched-to-airgap');
  }
  return targetMode;
});

ipcMain.handle('lan-generate-pairing-qr', (_, opts) => {
  if (!isUnlocked) {
    throw new Error('SYNC_LAN: Vault is locked');
  }
  const mode = getSavedSyncMode();
  if (mode === 'airgap') {
    throw new Error('SYNC_LAN: Air-Gap mode is active; network transport disabled');
  }
  const pm = getPairingManager();
  const server = getEphemeralLanServer();
  const effectiveOpts = Object.assign({}, opts);
  if (!effectiveOpts.port && server && server.isListening() && server.getPort()) {
    effectiveOpts.port = server.getPort();
  }
  return pm.generatePairingData(effectiveOpts);
});

ipcMain.handle('lan-get-paired-devices', () => {
  const pm = getPairingManager();
  return pm.getPairedDevices();
});

ipcMain.handle('lan-revoke-paired-device', (_, deviceId) => {
  const pm = getPairingManager();
  return pm.removePairedDevice(deviceId);
});

ipcMain.handle('lan-start-sync', async (event, { entries }) => {
  if (!isUnlocked) {
    throw new Error('SYNC_LAN: Vault is locked');
  }
  const mode = getSavedSyncMode();
  if (mode === 'airgap') {
    throw new Error('SYNC_LAN: Air-Gap mode is active; network transport disabled');
  }

  const server = getEphemeralLanServer();
  _activeLanEntries = Array.isArray(entries) ? entries : [];

  const res = await server.start();
  return {
    port: res.port,
    addresses: res.addresses,
    timeoutSec: 120
  };
});

ipcMain.handle('lan-stop-sync', async () => {
  if (_ephemeralLanServer) {
    await _ephemeralLanServer.stop('user-cancelled');
  }
  return true;
});

ipcMain.handle('lan-status', () => {
  if (!_ephemeralLanServer) return { active: false, remainingSec: 0 };
  return _ephemeralLanServer.getStatus();
});

// ── IPC: Pano ─────────────────────────────────────────────────────
let clipboardTimer = null;
ipcMain.handle('copy-secure', (_, text) => {
  clipboard.writeText(text);
  if (clipboardTimer) clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(() => {
    try { clipboard.writeText(''); } catch {}
    clipboardTimer = null;
    mainWindow?.webContents.send('clipboard-cleared');
  }, 30000);
  return true;
});
ipcMain.handle('cancel-clipboard-clear', () => {
  if (clipboardTimer) { clearTimeout(clipboardTimer); clipboardTimer = null; }
});

function backupFile(sourcePath) {
  if (!fs.existsSync(sourcePath)) return;
  try {
    const backupDir = path.join(app.getPath('userData'), 'backups');
    if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { mode: 0o700 });
    
    const ext = path.extname(sourcePath);
    const base = path.basename(sourcePath, ext);
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(backupDir, `${base}${ext}.${timestamp}.bak`);
    
    fs.copyFileSync(sourcePath, backupPath);
    
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith(base + ext + '.') && f.endsWith('.bak'))
      .map(f => ({ name: f, time: fs.statSync(path.join(backupDir, f)).mtime.getTime() }))
      .sort((a, b) => b.time - a.time);
      
    if (files.length > 10) {
      for (let i = 10; i < files.length; i++) {
        fs.unlinkSync(path.join(backupDir, files[i].name));
      }
    }
  } catch (e) {
    console.error('Backup error:', e);
  }
}

// ── IPC: Veri dosyası ─────────────────────────────────────────────
ipcMain.handle('load-data', () => {
  if (!fs.existsSync(DATA_FILE)) return null;
  const stat = fs.statSync(DATA_FILE);
  if (stat.size === 0) {
    console.warn('[load-data] DATA_FILE is 0 bytes. Attempting recovery from latest backup...');
    const backupDir = path.join(app.getPath('userData'), 'backups');
    if (fs.existsSync(backupDir)) {
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('fuin.enc.') && f.endsWith('.bak'))
        .map(f => ({ name: f, path: path.join(backupDir, f), stat: fs.statSync(path.join(backupDir, f)) }))
        .filter(f => f.stat.size > 0)
        .sort((a, b) => b.stat.mtime.getTime() - a.stat.mtime.getTime());
      if (files.length > 0) {
        console.warn(`[load-data] Recovered from backup: ${files[0].name}`);
        const recovered = fs.readFileSync(files[0].path, 'utf8');
        writeAtomicSync(DATA_FILE, recovered, { mode: 0o600 });
        return recovered;
      }
    }
  }
  return fs.readFileSync(DATA_FILE, 'utf8');
});
ipcMain.handle('save-data', (_, enc) => { 
  backupFile(DATA_FILE);
  writeAtomicSync(DATA_FILE, enc, { encoding: 'utf8', mode: 0o600 }); 
  if (_authoritativeVaultSession) {
    try {
      _authoritativeVaultSession.dataFileHash = crypto.createHash('sha256').update(String(enc)).digest('hex');
    } catch {}
  }
  return true; 
});
ipcMain.handle('data-exists', () => fs.existsSync(DATA_FILE));

// ── IPC: Recovery ─────────────────────────────────────────────────
ipcMain.handle('save-recovery-pair', (_, payload, maybeMasterEnc) => {
  let recoveryData, masterEncData;
  if (payload && typeof payload === 'object' && !Buffer.isBuffer(payload)) {
    recoveryData = payload.recovery || payload.recoveryData;
    masterEncData = payload.masterEnc || payload.masterEncData;
  } else {
    recoveryData = payload;
    masterEncData = maybeMasterEnc;
  }
  return saveRecoveryPairSync(recoveryData, masterEncData);
});
// DEPRECATED (IPC-IPC-01): Standalone recovery/master handlers are deprecated and removed
// from preload.js to prevent split-write desynchronization. Retained strictly for test harness compatibility.
ipcMain.handle('save-recovery', (_, d) => { 
  writeAtomicSync(RECOVERY_FILE, d, { encoding: 'utf8', mode: 0o600 }); 
  setRecoveryLegacyBound(false);
  return true; 
});
ipcMain.handle('load-recovery', () => fs.existsSync(RECOVERY_FILE) ? fs.readFileSync(RECOVERY_FILE, 'utf8') : null);
ipcMain.handle('recovery-exists', () => fs.existsSync(RECOVERY_FILE));
ipcMain.handle('get-recovery-status', () => getRecoveryStatus());

// DEPRECATED (IPC-IPC-01): Standalone master.enc writer is deprecated and removed
// from preload.js to prevent split-write desynchronization. Retained strictly for test harness compatibility.
// master.enc — şifre değiştirmek için vault'u yeniden şifrelemede kullanılır
// localStorage yerine bu dosya kullanılır; renderer erişemez, yalnızca IPC üzerinden
ipcMain.handle('save-master-enc', (_, d) => { 
  backupFile(MASTER_ENC_FILE);
  writeAtomicSync(MASTER_ENC_FILE, d, { encoding: 'utf8', mode: 0o600 }); 
  return true; 
});
ipcMain.handle('load-master-enc', () => {
  if (!fs.existsSync(MASTER_ENC_FILE)) return null;
  const stat = fs.statSync(MASTER_ENC_FILE);
  if (stat.size === 0) {
    console.warn('[load-master-enc] MASTER_ENC_FILE is 0 bytes. Attempting recovery from latest backup...');
    const backupDir = path.join(app.getPath('userData'), 'backups');
    if (fs.existsSync(backupDir)) {
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('fuin.master.enc.') && f.endsWith('.bak'))
        .map(f => ({ name: f, path: path.join(backupDir, f), stat: fs.statSync(path.join(backupDir, f)) }))
        .filter(f => f.stat.size > 0)
        .sort((a, b) => b.stat.mtime.getTime() - a.stat.mtime.getTime());
      if (files.length > 0) {
        console.warn(`[load-master-enc] Recovered from backup: ${files[0].name}`);
        const recovered = fs.readFileSync(files[0].path, 'utf8');
        writeAtomicSync(MASTER_ENC_FILE, recovered, { mode: 0o600 });
        return recovered;
      }
    }
  }
  return fs.readFileSync(MASTER_ENC_FILE, 'utf8');
});

// ── IPC: Tam sıfırlama ────────────────────────────────────────────
ipcMain.handle('full-reset', () => {
  syncV2.cancelSyncSession();
  clearAuthoritativeVaultSession();
  if (_ephemeralLanServer) {
    try { _ephemeralLanServer.stop('full-reset'); } catch {}
  }
  if (_pairingManager && typeof _pairingManager.clearAll === 'function') {
    try { _pairingManager.clearAll(); } catch {}
  }
  const userDataDir = app.getPath('userData');
  try { if (fs.existsSync(DATA_FILE))       fs.unlinkSync(DATA_FILE);       } catch {}
  try { if (fs.existsSync(RECOVERY_FILE))   fs.unlinkSync(RECOVERY_FILE);   } catch {}
  try { if (fs.existsSync(MASTER_ENC_FILE)) fs.unlinkSync(MASTER_ENC_FILE); } catch {}
  try { if (fs.existsSync(RECOVERY_STATUS_FILE)) fs.unlinkSync(RECOVERY_STATUS_FILE); } catch {}
  try {
    const touchIdFile = path.join(userDataDir, 'fuin.touchid.enc');
    if (fs.existsSync(touchIdFile)) fs.unlinkSync(touchIdFile);
  } catch {}
  try {
    const lockoutFile = path.join(userDataDir, 'fuin.lockout');
    if (fs.existsSync(lockoutFile)) fs.unlinkSync(lockoutFile);
  } catch {}
  try {
    const backupDir = path.join(userDataDir, 'backups');
    if (fs.existsSync(backupDir)) fs.rmSync(backupDir, { recursive: true, force: true });
  } catch {}
  return true;
});

// ── IPC: Yedek Klasörü ─────────────────────────────────────────────
ipcMain.handle('open-backup-folder', async () => {
  const backupDir = path.join(app.getPath('userData'), 'backups');
  if (!fs.existsSync(backupDir)) fs.mkdirSync(backupDir, { recursive: true });
  await shell.openPath(backupDir);
  return true;
});

// ── IPC: Dosya dialogları ─────────────────────────────────────────
ipcMain.handle('export-file', async (_, { content, defaultName, filters }) => {
  const { filePath } = await dialog.showSaveDialog(mainWindow, { defaultPath: defaultName, filters });
  if (filePath) { fs.writeFileSync(filePath, content, 'utf8'); return true; }
  return false;
});
ipcMain.handle('import-file', async (_, { filters }) => {
  const { filePaths } = await dialog.showOpenDialog(mainWindow, { filters, properties: ['openFile'] });
  if (filePaths?.[0]) return fs.readFileSync(filePaths[0], 'utf8');
  return null;
});

// ═══════════════════════════════════════════════════════════════════
// TARAYICI EKLENTİSİ KÖPRÜSÜ
// Mimari: Eklenti (background.js) ⇄ Native Messaging Host (ayrı process,
// stdin/stdout) ⇄ [bu yerel socket] ⇄ main.js ⇄ (IPC) ⇄ renderer.
//
// main.js şifre çözülmüş vault verisini TUTMAZ — sadece köprü görevi
// görür. Gerçek arama/ifşa işlemi renderer'daki `entries` (bellekte,
// sadece kilit açıkken var olan) üzerinde yapılır. Böylece mimari
// prensip korunur: decrypted veri her zaman tek yerde (renderer RAM'i).
//
// Güvenlik notu (bilinçli sınırlama — v1):
// - Socket sadece localhost'ta (unix socket / named pipe), ağa açık değil.
// - Basit paylaşılan token ile eşleşme yapılır (fuin.ext-token dosyası).
//   Bu, "hangi process bağlanıyor" garantisi vermez — aynı kullanıcı
//   hesabındaki başka bir process de token dosyasını okuyup bağlanabilir.
//   Güçlü izolasyon için ileride OS keyring / code-signing doğrulaması
//   eklenmeli. Şimdilik "rastgele internet sitesi bu sokete bağlanamaz"
//   seviyesinde bir koruma sağlıyor, "aynı makinedeki kötü niyetli
//   process" tehdidine karşı tam koruma DEĞİL.
// - `reveal` (gerçek şifreyi açığa çıkarma) her zaman kullanıcıya
//   renderer'da bir onay modalı gösterir — sessizce asla şifre sızdırılmaz.
// ═══════════════════════════════════════════════════════════════════
// FAZ 4 — BROWSER EXTENSION BRIDGE & NATIVE MESSAGING
// Delegated to main/extensionBridge.js
// ═══════════════════════════════════════════════════════════════════
const extensionBridge = require('./main/extensionBridge');

const PUBLISHED_CHROME_EXTENSION_ID = process.env.FUIN_CHROME_EXTENSION_ID || '';
const EXTRA_CHROME_ORIGINS = process.env.FUIN_CHROME_ORIGINS
  ? process.env.FUIN_CHROME_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : [];

const KNOWN_EXTENSION_IDS = {
  chromeOrigins: [
    ...(PUBLISHED_CHROME_EXTENSION_ID ? [`chrome-extension://${PUBLISHED_CHROME_EXTENSION_ID}/`] : []),
    ...EXTRA_CHROME_ORIGINS,
  ],
  firefoxIds: ['fuin-app@sombo.dev', 'fuin@sombo.dev'],
};

function writeNativeHostManifest(targetPath, key, values) {
  return extensionBridge.writeNativeHostManifest(targetPath, key, values, app);
}

function registerWindowsRegistryKey(subKey, manifestPath) {
  return extensionBridge.registerWindowsRegistryKey(subKey, manifestPath);
}

function autoInstallNativeMessagingHosts() {
  return extensionBridge.autoInstallNativeMessagingHosts(app, KNOWN_EXTENSION_IDS);
}

function startExtensionBridge() {
  return extensionBridge.startExtensionBridge({
    app,
    getMainWindow: () => mainWindow,
    getIsUnlocked: () => isUnlocked,
  });
}

function stopExtensionBridge() {
  return extensionBridge.stopExtensionBridge();
}

ipcMain.handle('ext-response', (_, { requestId, payload }) => {
  return extensionBridge.handleExtResponse(requestId, payload);
});

ipcMain.handle('get-ext-token-masked', () => {
  return extensionBridge.getMaskedToken(app);
});

ipcMain.handle('ext-bridge-status', () => {
  return extensionBridge.getExtBridgeStatus(app);
});


if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    validateRecoveryPayload,
    writeAndFsyncSync,
    safeRenameSync,
    cleanupOrphanRecoveryTransactions,
    saveRecoveryPairSync,
    KNOWN_EXTENSION_IDS,
    autoInstallNativeMessagingHosts,
    writeNativeHostManifest,
    registerWindowsRegistryKey,
    initLanSync,
    getPairingManager,
    getEphemeralLanServer,
    getSavedSyncMode
  };
}
