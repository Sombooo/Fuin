'use strict';

const { app, BrowserWindow, ipcMain, dialog, clipboard, powerMonitor, shell, Tray, Menu, nativeImage } = require('electron');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

let argon2, zxcvbn;
try { argon2 = require('argon2'); } catch { argon2 = null; }
try { zxcvbn = require('zxcvbn'); } catch { zxcvbn = null; }

const DATA_FILE        = path.join(app.getPath('userData'), 'fuin.enc');
const RECOVERY_FILE    = path.join(app.getPath('userData'), 'fuin.recovery');
const MASTER_ENC_FILE  = path.join(app.getPath('userData'), 'fuin.master.enc');

let mainWindow, syncWindow;
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
  mainWindow.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  
  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow.webContents.send('force-lock');
      mainWindow.hide();
    }
  });
  
  mainWindow.on('closed', () => { mainWindow = null; });
}

function createSyncWindow() {
  if (syncWindow) { syncWindow.focus(); return; }
  syncWindow = new BrowserWindow({
    width: 520, height: 680, resizable: false,
    frame: false, backgroundColor: '#f5f0e8',
    parent: mainWindow, modal: false,
    webPreferences: {
      nodeIntegration: false, contextIsolation: true, sandbox: true,
      preload: path.join(__dirname, 'preload.js'),
    },
  });
  syncWindow.loadFile(path.join(__dirname, 'renderer', 'sync.html'));
  syncWindow.on('closed', () => {
    syncWindow = null;
    // Pencere kapanınca sync key RAM'den temizlenir (activeSyncKey aşağıda)
    clearActiveSyncKey();
  });
}

app.whenReady().then(() => {
  createWindow();
  createTray();
  app.on('activate', () => {
    if (!mainWindow) createWindow();
    else mainWindow.show();
  });
  startPowerMonitorWatchers();
  startExtensionBridge();
  autoInstallNativeMessagingHosts();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin' && isQuitting) app.quit(); });
app.on('before-quit', () => {
  isQuitting = true;
  stopExtensionBridge();
  if (clipboardTimer) {
    try { clipboard.writeText(''); } catch {}
  }
});

function createTray() {
  if (tray) return;
  const iconPath = path.join(__dirname, 'assets', 'icon.png');
  let icon = nativeImage.createFromPath(iconPath);
  if (process.platform === 'darwin') {
    icon = icon.resize({ width: 16, height: 16 });
  }
  tray = new Tray(icon);
  tray.setToolTip('Fuin');
  
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Göster', click: () => { if (mainWindow) mainWindow.show(); } },
    { label: 'Kilitle', click: () => { if (mainWindow) mainWindow.webContents.send('force-lock'); } },
    { type: 'separator' },
    { label: 'Çıkış', click: () => { isQuitting = true; app.quit(); } }
  ]);
  
  if (process.platform === 'darwin') {
    tray.on('right-click', () => { tray.popUpContextMenu(contextMenu); });
  } else {
    tray.setContextMenu(contextMenu);
  }
  
  tray.on('click', () => {
    if (mainWindow) {
      if (mainWindow.isVisible()) mainWindow.hide();
      else mainWindow.show();
    }
  });
}
// ═══════════════════════════════════════════════════════════════════
// FAZ 2 — AUTO-LOCK
// Vault kilidi açıkken sistem genelinde boşta kalma süresi izlenir
// (powerMonitor.getSystemIdleTime — pencere odakta olmasa bile çalışır).
// Süre dolmadan IDLE_WARNING_SECONDS kala renderer'a uyarı gönderilir.
// Sistem uykuya geçtiğinde veya ekran kilitlendiğinde uyarı beklemeden
// anında kilitlenir.
// ═══════════════════════════════════════════════════════════════════
const IDLE_LOCK_SECONDS    = 5 * 60; // 5 dakika hareketsizlik → kilit
const IDLE_WARNING_SECONDS = 30;     // kilitlenmeden 30sn önce uyar

let isUnlocked      = false;
let idlePollTimer   = null;
let warningActive   = false;

function startIdleWatcher() {
  if (idlePollTimer) return;
  idlePollTimer = setInterval(() => {
    if (!isUnlocked || !mainWindow) return;
    const idleSec   = powerMonitor.getSystemIdleTime();
    const remaining = IDLE_LOCK_SECONDS - idleSec;

    if (remaining <= 0) {
      triggerForceLock('idle');
    } else if (remaining <= IDLE_WARNING_SECONDS) {
      warningActive = true;
      mainWindow.webContents.send('auto-lock-warning', Math.ceil(remaining));
    } else if (warningActive) {
      warningActive = false;
      mainWindow.webContents.send('auto-lock-warning-cancel');
    }
  }, 1000);
}

function stopIdleWatcher() {
  if (idlePollTimer) { clearInterval(idlePollTimer); idlePollTimer = null; }
  warningActive = false;
}

function triggerForceLock(reason) {
  stopIdleWatcher();
  isUnlocked = false;
  mainWindow?.webContents.send('force-lock', reason);
}

function startPowerMonitorWatchers() {
  // Ekran kilitlendiğinde (Windows/macOS) anında kilitle
  powerMonitor.on('lock-screen', () => { if (isUnlocked) triggerForceLock('lock-screen'); });
  // Sistem uykuya/beklemeye geçtiğinde anında kilitle
  powerMonitor.on('suspend',     () => { if (isUnlocked) triggerForceLock('suspend'); });
}

// Renderer, unlock()/lock() olduğunda bu state'i main process'e bildirir
ipcMain.handle('set-unlock-state', (_, unlocked) => {
  isUnlocked = !!unlocked;
  if (isUnlocked) startIdleWatcher(); else stopIdleWatcher();
  return true;
});

ipcMain.on('win-minimize', () => mainWindow?.minimize());
ipcMain.on('win-maximize', () => mainWindow?.isMaximized() ? mainWindow.unmaximize() : mainWindow?.maximize());
ipcMain.on('win-close',    () => mainWindow?.close());
ipcMain.on('sync-win-close', () => syncWindow?.close());

// ═══════════════════════════════════════════════════════════════════
// CRYPTO CORE
// ═══════════════════════════════════════════════════════════════════

// vaultKey ve syncKey FARKLI salt'larla türetilir.
// İki salt: biri vault dosyasına gömülü (encryptData'dan gelir),
// diğeri syncSalt — her sync oturumu için ayrı üretilir.
// Böylece vaultKey ↔ syncKey arasında hiçbir matematiksel ilişki kalmaz.

async function deriveVaultKey(passwordStr, vaultSalt) {
  const pwBuf = Buffer.from(passwordStr, 'utf8');
  let key;

  if (argon2) {
    try {
      const raw = await argon2.hash(pwBuf, {
        type: argon2.argon2id, salt: vaultSalt,
        memoryCost: 65536, timeCost: 3, parallelism: 1,
        hashLength: 32, raw: true,
      });
      key = Buffer.from(raw);
      raw.fill(0);
    } catch { key = null; }
  }

  if (!key) {
    key = await new Promise((res, rej) =>
      crypto.pbkdf2(pwBuf, vaultSalt, 200000, 32, 'sha512', (e, k) => e ? rej(e) : res(k))
    );
  }

  pwBuf.fill(0);
  return key; // caller'ın fill(0) sorumluluğu
}

async function deriveSyncKey(passwordStr, syncSalt) {
  const pwBuf = Buffer.from(passwordStr, 'utf8');
  // syncSalt'a "SYNC" domain separator ekle — vaultKey ile çakışmayı önler
  const domainSalt = Buffer.concat([syncSalt, Buffer.from('FUIN_SYNC_V1', 'utf8')]);
  let key;

  if (argon2) {
    // Argon2 salt 16-64 byte arası; domainSalt 46 byte — uygun
    try {
      const raw = await argon2.hash(pwBuf, {
        type: argon2.argon2id, salt: domainSalt,
        memoryCost: 65536, timeCost: 3, parallelism: 1,
        hashLength: 32, raw: true,
      });
      key = Buffer.from(raw);
      raw.fill(0);
    } catch { key = null; }
  }

  if (!key) {
    key = await new Promise((res, rej) =>
      crypto.pbkdf2(pwBuf, domainSalt, 200000, 32, 'sha512', (e, k) => e ? rej(e) : res(k))
    );
  }

  pwBuf.fill(0);
  domainSalt.fill(0);
  return key;
}

// AES-256-GCM şifreleme — vaultKey ile
async function encryptData(plaintext, passwordStr) {
  const vaultSalt = crypto.randomBytes(32);
  const iv        = crypto.randomBytes(12);
  const vaultKey  = await deriveVaultKey(passwordStr, vaultSalt);

  const jsonBuf = Buffer.from(JSON.stringify(plaintext), 'utf8');
  const cipher  = crypto.createCipheriv('aes-256-gcm', vaultKey, iv);
  const enc1    = cipher.update(jsonBuf);
  const enc2    = cipher.final();
  const tag     = cipher.getAuthTag();

  vaultKey.fill(0);
  jsonBuf.fill(0);

  return Buffer.concat([vaultSalt, iv, tag, enc1, enc2]).toString('base64');
}

// Güvenlik: Brute-force rate limiting — başarısız denemelerden sonra üstel gecikme
let decryptFailCount = 0;
let decryptLockUntil = 0;

// AES-256-GCM şifre çözme — vaultKey ile
async function decryptData(b64Str, passwordStr) {
  // Brute-force koruması: üstel geri çekilme
  const now = Date.now();
  if (now < decryptLockUntil) {
    const waitSec = Math.ceil((decryptLockUntil - now) / 1000);
    throw new Error(`Too many attempts. Wait ${waitSec}s`);
  }

  const buf       = Buffer.from(b64Str, 'base64');
  const vaultSalt = buf.slice(0, 32);
  const iv        = buf.slice(32, 44);
  const tag       = buf.slice(44, 60);
  const data      = buf.slice(60);
  const vaultKey  = await deriveVaultKey(passwordStr, vaultSalt);

  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey, iv);
    decipher.setAuthTag(tag);
    const dec1 = decipher.update(data);
    const dec2 = decipher.final();
    vaultKey.fill(0);
    const jsonStr = Buffer.concat([dec1, dec2]).toString('utf8');
    dec1.fill(0); dec2.fill(0);
    decryptFailCount = 0; decryptLockUntil = 0; // başarılı — sayacı sıfırla
    return JSON.parse(jsonStr);
  } catch {
    vaultKey.fill(0);
    decryptFailCount++;
    decryptLockUntil = Date.now() + Math.min(1000 * Math.pow(2, decryptFailCount), 30000);
    throw new Error('Decryption failed');
  }
}

function safeCompare(a, b) {
  const aBuf = Buffer.from(String(a), 'utf8');
  const bBuf = Buffer.from(String(b), 'utf8');
  // Güvenlik: Uzunluk farkı varsa doğrudan false dön (truncation önleme)
  if (aBuf.length !== bBuf.length) { aBuf.fill(0); bBuf.fill(0); return false; }
  const result = crypto.timingSafeEqual(aBuf, bBuf);
  aBuf.fill(0); bBuf.fill(0);
  return result;
}

// ═══════════════════════════════════════════════════════════════════
// SYNC KEY YÖNETİMİ
// syncKey sadece sync penceresi açıkken RAM'de tutulur.
// Pencere kapanınca veya işlem bitince Buffer.fill(0) ile yok edilir.
// ═══════════════════════════════════════════════════════════════════
let activeSyncKey    = null; // Buffer | null
let activeSyncSalt   = null;
let activeSyncTimer  = null;

function clearActiveSyncKey() {
  if (activeSyncKey)  { activeSyncKey.fill(0);  activeSyncKey  = null; }
  if (activeSyncSalt) { activeSyncSalt.fill(0); activeSyncSalt = null; }
  if (activeSyncTimer){ clearTimeout(activeSyncTimer); activeSyncTimer = null; }
}

// Sync oturumu başlat: syncKey türet ve RAM'e al
async function initSyncSession(passwordStr) {
  clearActiveSyncKey(); // önceki oturumu temizle
  activeSyncSalt = crypto.randomBytes(32);
  activeSyncKey  = await deriveSyncKey(passwordStr, activeSyncSalt);

  // Güvenlik: 5 dakika sonra otomatik temizle
  activeSyncTimer = setTimeout(() => {
    clearActiveSyncKey();
    syncWindow?.webContents.send('sync-key-expired');
  }, 5 * 60 * 1000);

  return activeSyncSalt.toString('hex'); // salt'ı UI'ya gönder (debug/bilgi)
}

// ═══════════════════════════════════════════════════════════════════
// QR CHUNKING
// Vault, activeSyncKey ile paketlenir ve chunk'lara bölünür.
// Her chunk: { fuin, transferId, index, total, data }
// ═══════════════════════════════════════════════════════════════════
async function buildQRChunks(encryptedB64, chunkSize = 400) {
  if (!activeSyncKey) throw new Error('Sync session not initialized');

  const rawBuf     = Buffer.from(encryptedB64, 'utf8');
  const tIv        = crypto.randomBytes(12);
  const transferId = crypto.randomBytes(8).toString('hex').toUpperCase();

  // activeSyncKey kullan — vaultKey'den tamamen bağımsız
  const cipher = crypto.createCipheriv('aes-256-gcm', activeSyncKey, tIv);
  const enc1   = cipher.update(rawBuf);
  const enc2   = cipher.final();
  const tag    = cipher.getAuthTag();

  // Transfer paketi: [syncSalt32][iv12][tag16][ciphertext]
  const packet    = Buffer.concat([activeSyncSalt, tIv, tag, enc1, enc2]);
  const b64Packet = packet.toString('base64');

  // Chunk'lara böl
  const chunks = [];
  for (let i = 0; i < b64Packet.length; i += chunkSize) {
    chunks.push(b64Packet.slice(i, i + chunkSize));
  }

  return chunks.map((data, index) => ({
    fuin: true, transferId,
    index: index + 1, total: chunks.length, data,
  }));
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
  argon2: !!argon2, zxcvbn: !!zxcvbn, dualKey: true, separateSalts: true,
  kdf: argon2 ? 'Argon2id (64MB, 3 iter)' : 'PBKDF2-SHA512 (200k iter)',
  argon2Warning: !argon2, // Renderer'da uyarı göstermek için
}));

// ── IPC: Sync session ─────────────────────────────────────────────
ipcMain.handle('open-sync-window', async (_, { password, encryptedB64 }) => {
  await initSyncSession(password);
  createSyncWindow();
  // Pencere yüklenince chunk'ları hazırla
  syncWindow.webContents.once('did-finish-load', async () => {
    try {
      const chunks = await buildQRChunks(encryptedB64);
      syncWindow?.webContents.send('sync-chunks-ready', { chunks, encryptedB64 });
    } catch (e) {
      syncWindow?.webContents.send('sync-error', e.message);
    }
  });
  return true;
});

ipcMain.handle('rebuild-chunks', async (_, { encryptedB64, chunkSize }) => {
  const chunks = await buildQRChunks(encryptedB64, chunkSize || 400);
  return chunks;
});

ipcMain.handle('clear-sync-key', () => {
  clearActiveSyncKey();
  return true;
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
    const backupPath = path.join(backupDir, `${base}.${timestamp}${ext}.bak`);
    
    fs.copyFileSync(sourcePath, backupPath);
    
    const files = fs.readdirSync(backupDir)
      .filter(f => f.startsWith(base + '.') && f.endsWith('.bak'))
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
ipcMain.handle('load-data',   ()        => fs.existsSync(DATA_FILE) ? fs.readFileSync(DATA_FILE, 'utf8') : null);
ipcMain.handle('save-data',   (_, enc)  => { 
  backupFile(DATA_FILE);
  fs.writeFileSync(DATA_FILE, enc, { encoding: 'utf8', mode: 0o600 }); 
  return true; 
});
ipcMain.handle('data-exists', ()        => fs.existsSync(DATA_FILE));

// ── IPC: Recovery ─────────────────────────────────────────────────
ipcMain.handle('save-recovery',   (_, d) => { fs.writeFileSync(RECOVERY_FILE, d, { encoding: 'utf8', mode: 0o600 }); return true; });
ipcMain.handle('load-recovery',   ()     => fs.existsSync(RECOVERY_FILE) ? fs.readFileSync(RECOVERY_FILE, 'utf8') : null);
ipcMain.handle('recovery-exists', ()     => fs.existsSync(RECOVERY_FILE));

// master.enc — şifre değiştirmek için vault'u yeniden şifrelemede kullanılır
// localStorage yerine bu dosya kullanılır; renderer erişemez, yalnızca IPC üzerinden
ipcMain.handle('save-master-enc', (_, d) => { 
  backupFile(MASTER_ENC_FILE);
  fs.writeFileSync(MASTER_ENC_FILE, d, { encoding: 'utf8', mode: 0o600 }); 
  return true; 
});
ipcMain.handle('load-master-enc', ()     => fs.existsSync(MASTER_ENC_FILE) ? fs.readFileSync(MASTER_ENC_FILE, 'utf8') : null);

// ── IPC: Tam sıfırlama ────────────────────────────────────────────
ipcMain.handle('full-reset', () => {
  clearActiveSyncKey();
  try { if (fs.existsSync(DATA_FILE))       fs.unlinkSync(DATA_FILE);       } catch {}
  try { if (fs.existsSync(RECOVERY_FILE))   fs.unlinkSync(RECOVERY_FILE);   } catch {}
  try { if (fs.existsSync(MASTER_ENC_FILE)) fs.unlinkSync(MASTER_ENC_FILE); } catch {}
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
const net = require('net');

const EXT_TOKEN_FILE = path.join(app.getPath('userData'), 'fuin.ext-token');
const EXT_SOCKET_PATH = process.platform === 'win32'
  ? '\\\\.\\pipe\\fuin-ext-bridge'
  : path.join(app.getPath('userData'), 'fuin-ext.sock');

const NATIVE_HOST_NAME = 'com.fuin.nativehost';

// Chrome Web Store / Firefox AMO'ya yayınlandıktan sonra buraya gerçek,
// kalıcı mağaza ID'lerini ekle. Firefox tarafı zaten sabit (manifest.json'da
// browser_specific_settings.gecko.id ile pinlenmiş), Chrome/Edge/Brave
// mağaza ID'si yayınlanınca netleşir. Geliştirme sırasında eklenen ID'ler
// (paketlenmemiş yükleme) kalıcı değildir, her yükleyişte değişebilir —
// bu yüzden yayına çıkmadan önce bu listeyi güncel tutmak gerekir.
const KNOWN_EXTENSION_IDS = {
  chromeOrigins: [
    // 'chrome-extension://GERÇEK_MAĞAZA_ID/', // yayınlanınca eklenecek
  ],
  firefoxIds: ['fuin@sombo.dev'],
};

function getNativeHostJsPath() {
  // Paketlenmiş uygulamada extraResources ile kopyalanan host.js (asar
  // dışında, gerçek bir dosya olarak — tarayıcı işlemleri asar sanal
  // dosya sistemine erişemez, gerçek bir yol gerekir). Geliştirme
  // modunda (npm start) doğrudan proje içindeki native-host/host.js.
  return app.isPackaged
    ? path.join(process.resourcesPath, 'native-host', 'host.js')
    : path.join(__dirname, 'native-host', 'host.js');
}

// Sistemde Node.js kurulu olmasına hiç bağımlı değiliz: Electron'un
// kendi binary'si, ELECTRON_RUN_AS_NODE=1 ortam değişkeniyle çalıştırılırsa
// sıradan bir Node.js yorumlayıcısı gibi davranır. Böylece native host'u
// çalıştırmak için ayrı bir binary derlemeye (pkg/nexe) veya kullanıcının
// PATH'inde node bulunmasına gerek kalmıyor.
function ensureNativeHostWrapper() {
  const hostJs = getNativeHostJsPath();
  const wrapperDir = app.getPath('userData');
  const electronPath = process.execPath;

  if (process.platform === 'win32') {
    const batPath = path.join(wrapperDir, 'fuin-host.bat');
    fs.writeFileSync(batPath, `@echo off\r\nset ELECTRON_RUN_AS_NODE=1\r\n"${electronPath}" "${hostJs}" %*\r\n`);
    return batPath;
  }
  const shPath = path.join(wrapperDir, 'fuin-host.sh');
  fs.writeFileSync(shPath, `#!/bin/sh\nexport ELECTRON_RUN_AS_NODE=1\nexec "${electronPath}" "${hostJs}" "$@"\n`);
  fs.chmodSync(shPath, 0o700);
  return shPath;
}

function writeNativeHostManifest(targetPath, key, values) {
  try {
    const manifest = {
      name: NATIVE_HOST_NAME,
      description: 'Fuin Şifre Yöneticisi — Native Messaging Köprüsü',
      path: ensureNativeHostWrapper(),
      type: 'stdio',
      [key]: values,
    };
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    fs.writeFileSync(targetPath, JSON.stringify(manifest, null, 2));
    return true;
  } catch (e) {
    console.error('[native-host-install] yazılamadı:', targetPath, e.message);
    return false;
  }
}

// Fuin her açıldığında sessizce çalışır — ucuz bir dosya yazma işlemi
// olduğu için kilit gerekmez, uygulama taşınsa/güncellense bile kayıt
// kendi kendine güncel kalır (self-healing).
function autoInstallNativeMessagingHosts() {
  const home = app.getPath('home');
  const results = [];

  if (KNOWN_EXTENSION_IDS.chromeOrigins.length) {
    const chromeTargets = process.platform === 'darwin' ? [
      path.join(home, 'Library/Application Support/Google/Chrome/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, 'Library/Application Support/Microsoft Edge/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
    ] : process.platform === 'linux' ? [
      path.join(home, '.config/google-chrome/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, '.config/microsoft-edge/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, '.config/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
    ] : []; // Windows: registry gerekiyor, installer (NSIS) tarafında ayrıca ele alınmalı
    for (const t of chromeTargets) results.push(writeNativeHostManifest(t, 'allowed_origins', KNOWN_EXTENSION_IDS.chromeOrigins));
  }

  if (KNOWN_EXTENSION_IDS.firefoxIds.length) {
    const firefoxTargets = process.platform === 'darwin' ? [
      path.join(home, 'Library/Application Support/zen/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, 'Library/Application Support/Mozilla/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
    ] : process.platform === 'linux' ? [
      path.join(home, '.zen/native-messaging-hosts', `${NATIVE_HOST_NAME}.json`),
      path.join(home, '.mozilla/native-messaging-hosts', `${NATIVE_HOST_NAME}.json`),
    ] : [];
    for (const t of firefoxTargets) results.push(writeNativeHostManifest(t, 'allowed_extensions', KNOWN_EXTENSION_IDS.firefoxIds));
  }

  console.log(`[native-host-install] ${results.filter(Boolean).length}/${results.length} manifest yazıldı`);
}

function getOrCreateExtToken() {
  if (fs.existsSync(EXT_TOKEN_FILE)) return fs.readFileSync(EXT_TOKEN_FILE, 'utf8').trim();
  const token = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(EXT_TOKEN_FILE, token, { mode: 0o600 });
  return token;
}

let pendingExtRequests = new Map(); // requestId -> { resolve, reject, timer }
let extRequestCounter = 0;

function relayToRenderer(channel, payload, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    if (!mainWindow) return reject(new Error('no-window'));
    const requestId = `ext-${++extRequestCounter}-${Date.now()}`;
    const timer = setTimeout(() => {
      pendingExtRequests.delete(requestId);
      reject(new Error('timeout'));
    }, timeoutMs);
    pendingExtRequests.set(requestId, { resolve, reject, timer });
    mainWindow.webContents.send(channel, { requestId, ...payload });
  });
}

// Renderer, kullanıcı işlemini (arama sonucu / onay-red) tamamlayınca burayı çağırır
ipcMain.handle('ext-response', (_, { requestId, payload }) => {
  const pending = pendingExtRequests.get(requestId);
  if (!pending) return false;
  clearTimeout(pending.timer);
  pendingExtRequests.delete(requestId);
  pending.resolve(payload);
  return true;
});

ipcMain.handle('get-ext-token', () => getOrCreateExtToken());
ipcMain.handle('ext-bridge-status', () => ({ running: !!extServer, socketPath: EXT_SOCKET_PATH }));

let extServer = null;

function startExtensionBridge() {
  if (extServer) return;
  const token = getOrCreateExtToken();

  // Unix socket dosyası önceki çalıştırmadan kalmışsa temizle
  if (process.platform !== 'win32' && fs.existsSync(EXT_SOCKET_PATH)) {
    try { fs.unlinkSync(EXT_SOCKET_PATH); } catch {}
  }

  extServer = net.createServer((socket) => {
    let buf = '';
    socket.on('data', async (chunk) => {
      buf += chunk.toString('utf8');
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        await handleExtMessage(socket, line);
      }
    });
    socket.on('error', () => {});
  });

  extServer.on('error', (e) => console.error('[fuin-ext-bridge] socket hatası:', e.message));
  extServer.listen(EXT_SOCKET_PATH, () => {
    console.log('[fuin-ext-bridge] dinliyor:', EXT_SOCKET_PATH);
  });

  async function handleExtMessage(socket, line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    const reply = (obj) => { try { socket.write(JSON.stringify(obj) + '\n'); } catch {} };

    if (!msg.token || !safeCompare(msg.token, token)) {
      return reply({ id: msg.id, error: 'unauthorized' });
    }
    if (!isUnlocked) {
      return reply({ id: msg.id, error: 'locked' });
    }

    try {
      if (msg.type === 'lookup') {
        const matches = await relayToRenderer('ext-lookup-request', { domain: msg.domain });
        reply({ id: msg.id, matches });
      } else if (msg.type === 'reveal') {
        const result = await relayToRenderer('ext-reveal-request', { entryId: msg.entryId, domain: msg.domain });
        reply({ id: msg.id, ...result });
      } else {
        reply({ id: msg.id, error: 'unknown-type' });
      }
    } catch (e) {
      reply({ id: msg.id, error: e.message === 'timeout' ? 'timeout' : 'internal-error' });
    }
  }
}

function stopExtensionBridge() {
  if (extServer) { try { extServer.close(); } catch {} extServer = null; }
}
