'use strict';

const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const NATIVE_HOST_NAME = 'com.fuin.nativehost';

function getChromeOriginsFilePath(app) {
  return app ? path.join(app.getPath('userData'), 'fuin.chrome-origins.json') : null;
}

function loadSavedChromeOrigins(app) {
  try {
    const f = getChromeOriginsFilePath(app);
    if (f && fs.existsSync(f)) {
      const data = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (Array.isArray(data)) return data.filter(s => typeof s === 'string' && s.startsWith('chrome-extension://'));
    }
  } catch {}
  return [];
}

function saveChromeOrigins(app, origins) {
  try {
    const f = getChromeOriginsFilePath(app);
    if (f) {
      fs.mkdirSync(path.dirname(f), { recursive: true });
      fs.writeFileSync(f, JSON.stringify(origins, null, 2), { mode: 0o600, encoding: 'utf8' });
    }
  } catch {}
}

function getKnownExtensionIds(app) {
  const publishedId = process.env.FUIN_CHROME_EXTENSION_ID || '';
  const extraOrigins = process.env.FUIN_CHROME_ORIGINS
    ? process.env.FUIN_CHROME_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
    : [];
  const savedOrigins = loadSavedChromeOrigins(app);

  const uniqueOrigins = Array.from(new Set([
    ...(publishedId ? [`chrome-extension://${publishedId}/`] : []),
    ...extraOrigins,
    ...savedOrigins,
  ]));

  return {
    chromeOrigins: uniqueOrigins,
    firefoxIds: ['fuin-app@sombo.dev', 'fuin@sombo.dev'],
  };
}

function registerChromeOrigin(app, extensionId) {
  if (!extensionId || typeof extensionId !== 'string') {
    return { ok: false, error: 'invalid-id' };
  }
  const cleanId = extensionId.trim().toLowerCase();
  if (!/^[a-p]{32}$/.test(cleanId)) {
    return { ok: false, error: 'invalid-format' };
  }
  const origin = `chrome-extension://${cleanId}/`;
  const saved = loadSavedChromeOrigins(app);
  if (!saved.includes(origin)) {
    saved.push(origin);
    saveChromeOrigins(app, saved);
  }
  const knownIds = getKnownExtensionIds(app);
  const results = autoInstallNativeMessagingHosts(app, knownIds);
  return { ok: true, origin, installedCount: results.filter(Boolean).length };
}

function getExtTokenPath(app) {
  return path.join(app.getPath('userData'), 'fuin.ext-token');
}

function getExtSocketPath(app) {
  return process.platform === 'win32'
    ? '\\\\.\\pipe\\fuin-ext-bridge'
    : path.join(app.getPath('userData'), 'fuin-ext.sock');
}

function getNativeHostJsPath(app) {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'native-host', 'host.js')
    : path.join(__dirname, '..', 'native-host', 'host.js');
}

function ensureNativeHostWrapper(app) {
  const hostJs = getNativeHostJsPath(app).replace(/"/g, '');
  const wrapperDir = app.getPath('userData');
  const electronPath = process.execPath.replace(/"/g, '');
  fs.mkdirSync(wrapperDir, { recursive: true });

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

function writeNativeHostManifest(targetPath, key, values, app) {
  try {
    const manifest = {
      name: NATIVE_HOST_NAME,
      description: 'Fuin Şifre Yöneticisi — Native Messaging Köprüsü',
      path: ensureNativeHostWrapper(app),
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

function registerWindowsRegistryKey(subKey, manifestPath) {
  if (process.platform !== 'win32') return;
  try {
    const { spawnSync } = require('child_process');
    spawnSync('reg.exe', ['add', `HKCU\\Software\\${subKey}\\NativeMessagingHosts\\${NATIVE_HOST_NAME}`, '/ve', '/t', 'REG_SZ', '/d', manifestPath, '/f'], { stdio: 'ignore' });
  } catch (e) {
    console.error('[native-host-registry] Windows registry kaydı başarısız:', subKey, e.message);
  }
}

function autoInstallNativeMessagingHosts(app, knownExtensionIds) {
  const ids = knownExtensionIds || getKnownExtensionIds();
  const home = app.getPath('home');
  const userData = app.getPath('userData');
  const results = [];

  if (ids.chromeOrigins && ids.chromeOrigins.length) {
    if (process.platform === 'win32') {
      const winChromeManifest = path.join(userData, `${NATIVE_HOST_NAME}-chrome.json`);
      if (writeNativeHostManifest(winChromeManifest, 'allowed_origins', ids.chromeOrigins, app)) {
        registerWindowsRegistryKey('Google\\Chrome', winChromeManifest);
        registerWindowsRegistryKey('Microsoft\\Edge', winChromeManifest);
        results.push(true);
      }
    } else {
      const chromeTargets = process.platform === 'darwin' ? [
        path.join(home, 'Library/Application Support/Google/Chrome/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, 'Library/Application Support/Microsoft Edge/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      ] : [
        path.join(home, '.config/google-chrome/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, '.config/microsoft-edge/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, '.config/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      ];
      for (const t of chromeTargets) results.push(writeNativeHostManifest(t, 'allowed_origins', ids.chromeOrigins, app));
    }
  }

  if (ids.firefoxIds && ids.firefoxIds.length) {
    if (process.platform === 'win32') {
      const winFirefoxManifest = path.join(userData, `${NATIVE_HOST_NAME}-firefox.json`);
      if (writeNativeHostManifest(winFirefoxManifest, 'allowed_extensions', ids.firefoxIds, app)) {
        registerWindowsRegistryKey('Mozilla', winFirefoxManifest);
        results.push(true);
      }
    } else {
      const firefoxTargets = process.platform === 'darwin' ? [
        path.join(home, 'Library/Application Support/zen/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, 'Library/Application Support/Mozilla/NativeMessagingHosts', `${NATIVE_HOST_NAME}.json`),
      ] : [
        path.join(home, '.zen/native-messaging-hosts', `${NATIVE_HOST_NAME}.json`),
        path.join(home, '.mozilla/native-messaging-hosts', `${NATIVE_HOST_NAME}.json`),
      ];
      for (const t of firefoxTargets) results.push(writeNativeHostManifest(t, 'allowed_extensions', ids.firefoxIds, app));
    }
  }

  console.log(`[native-host-install] ${results.filter(Boolean).length}/${results.length} manifest/kayıt işlendi`);
  return results;
}

function getOrCreateExtToken(app) {
  const tokenFile = getExtTokenPath(app);
  if (fs.existsSync(tokenFile)) {
    try {
      const raw = fs.readFileSync(tokenFile, 'utf8').trim();
      if (/^[0-9a-f]{64}$/i.test(raw)) {
        if (process.platform !== 'win32') {
          try { fs.chmodSync(tokenFile, 0o600); } catch {}
        }
        return raw;
      }
    } catch {}
  }
  const token = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(tokenFile, token, { mode: 0o600, encoding: 'utf8' });
  if (process.platform !== 'win32') {
    try { fs.chmodSync(tokenFile, 0o600); } catch {}
  }
  return token;
}

function safeCompare(a, b) {
  const key = crypto.randomBytes(32);
  const h1 = crypto.createHmac('sha256', key).update(String(a)).digest();
  const h2 = crypto.createHmac('sha256', key).update(String(b)).digest();
  return crypto.timingSafeEqual(h1, h2);
}

let extServer = null;
const pendingExtRequests = new Map(); // requestId -> { resolve, reject, timer }
let extRequestCounter = 0;
let lastBridgeOptions = null;
let socketWatchdog = null;

function ensureSocketAlive() {
  if (process.platform === 'win32' || !extServer || !lastBridgeOptions) return;
  const socketPath = getExtSocketPath(lastBridgeOptions.app);
  if (!fs.existsSync(socketPath)) {
    console.warn('[fuin-ext-bridge] Socket file missing while server is active. Recreating listener at:', socketPath);
    try { extServer.close(); } catch {}
    extServer = null;
    startExtensionBridge(lastBridgeOptions);
  }
}

function relayToRenderer(getMainWindow, channel, payload, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const mainWindow = getMainWindow();
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

function handleExtResponse(requestId, payload) {
  const pending = pendingExtRequests.get(requestId);
  if (!pending) return false;
  clearTimeout(pending.timer);
  pendingExtRequests.delete(requestId);
  pending.resolve(payload);
  return true;
}

function startExtensionBridge({ app, getMainWindow, getIsUnlocked, onActivity }) {
  lastBridgeOptions = { app, getMainWindow, getIsUnlocked, onActivity };
  if (extServer) return;
  const token = getOrCreateExtToken(app);
  const socketPath = getExtSocketPath(app);

  if (process.platform !== 'win32' && fs.existsSync(socketPath)) {
    try { fs.unlinkSync(socketPath); } catch {}
  }

  extServer = net.createServer((socket) => {
    let buf = '';
    socket.on('data', async (chunk) => {
      buf += chunk.toString('utf8');
      if (buf.length > 65536) {
        socket.destroy();
        return;
      }
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
  extServer.listen(socketPath, () => {
    if (process.platform !== 'win32') {
      try { fs.chmodSync(socketPath, 0o600); } catch {}
    }
    console.log('[fuin-ext-bridge] dinliyor:', socketPath);
  });

  if (!socketWatchdog && process.platform !== 'win32') {
    socketWatchdog = setInterval(ensureSocketAlive, 3000);
    if (typeof socketWatchdog.unref === 'function') {
      socketWatchdog.unref();
    }
  }

  async function handleExtMessage(socket, line) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    const reply = (obj) => { try { socket.write(JSON.stringify(obj) + '\n'); } catch {} };

    if (!msg.token || typeof msg.token !== 'string' || !safeCompare(msg.token, token)) {
      return reply({ id: msg.id, error: 'unauthorized' });
    }
    if (msg.type === 'open-app') {
      const win = getMainWindow();
      if (win && !win.isDestroyed()) {
        if (win.isMinimized()) win.restore();
        win.show();
        win.focus();
      }
      return reply({ id: msg.id, ok: true });
    }
    if (!getIsUnlocked()) {
      return reply({ id: msg.id, error: 'locked' });
    }

    if (typeof onActivity === 'function') {
      try { onActivity(); } catch {}
    }

    try {
      if (msg.type === 'lookup') {
        const matches = await relayToRenderer(getMainWindow, 'ext-lookup-request', { domain: msg.domain });
        reply({ id: msg.id, matches });
      } else if (msg.type === 'reveal') {
        const result = await relayToRenderer(getMainWindow, 'ext-reveal-request', { entryId: msg.entryId, domain: msg.domain });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'check-save-candidate') {
        const result = await relayToRenderer(getMainWindow, 'ext-check-save-candidate-request', {
          domain: msg.domain,
          username: msg.username,
          password: msg.password
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'save-credential') {
        if (!msg.domain || !msg.password || typeof msg.password !== 'string') {
          return reply({ id: msg.id, error: 'invalid-credential' });
        }
        const result = await relayToRenderer(getMainWindow, 'ext-save-credential-request', {
          domain: msg.domain,
          username: msg.username || '',
          password: msg.password,
          updateEntryId: msg.updateEntryId
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'exclude-domain') {
        const result = await relayToRenderer(getMainWindow, 'ext-exclude-domain-request', {
          domain: msg.domain || ''
        });
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
  if (socketWatchdog) {
    clearInterval(socketWatchdog);
    socketWatchdog = null;
  }
  if (extServer) {
    try { extServer.close(); } catch {}
    extServer = null;
  }
}

function getExtBridgeStatus(app) {
  return {
    running: !!extServer,
    socketPath: getExtSocketPath(app),
  };
}

function getMaskedToken(app) {
  const token = getOrCreateExtToken(app);
  return token.slice(0, 8) + '••••••••';
}

module.exports = {
  NATIVE_HOST_NAME,
  getKnownExtensionIds,
  getExtTokenPath,
  getExtSocketPath,
  getNativeHostJsPath,
  ensureNativeHostWrapper,
  writeNativeHostManifest,
  registerWindowsRegistryKey,
  autoInstallNativeMessagingHosts,
  getOrCreateExtToken,
  safeCompare,
  handleExtResponse,
  startExtensionBridge,
  stopExtensionBridge,
  getExtBridgeStatus,
  getMaskedToken,
  registerChromeOrigin,
  loadSavedChromeOrigins,
  getChromeOriginsFilePath,
};
