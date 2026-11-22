'use strict';

const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const NATIVE_HOST_NAME = 'com.fuin.nativehost';
const PROTOCOL_VERSION = 1; // Native-host & eklenti protokol sürümü
const DEFAULT_CHROME_EXTENSION_ID = 'fnnfdonpocachpdjkdjpgpmodjnahpbh';
const MAX_BAD_AUTH_PER_SOCKET = 5;
const SOCKET_IDLE_TIMEOUT_MS = 60000;

function ensurePrivateDirSync(dirPath) {
  if (!dirPath || typeof dirPath !== 'string') {
    throw new Error('Invalid directory path');
  }
  fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    const resolved = path.resolve(dirPath);
    const tmpRoot = path.resolve(os.tmpdir());
    if (resolved !== tmpRoot && resolved !== '/tmp' && resolved !== '/private/tmp') {
      try {
        const st = fs.lstatSync(dirPath);
        if (!st.isSymbolicLink() && st.isDirectory()) {
          fs.chmodSync(dirPath, 0o700);
        }
      } catch {}
    }
  }
  return dirPath;
}

function unlinkIfSymlinkSync(filePath) {
  try {
    const st = fs.lstatSync(filePath);
    if (st.isSymbolicLink()) {
      fs.unlinkSync(filePath);
      return true;
    }
  } catch (err) {
    if (err && err.code !== 'ENOENT') throw err;
  }
  return false;
}

function getChromeOriginsFilePath(app) {
  return app ? path.join(app.getPath('userData'), 'fuin.chrome-origins.json') : null;
}

function loadSavedChromeOrigins(app) {
  try {
    const f = getChromeOriginsFilePath(app);
    if (f) {
      const st = fs.lstatSync(f);
      if (st.isSymbolicLink() || !st.isFile()) return [];
      const data = JSON.parse(fs.readFileSync(f, 'utf8'));
      if (Array.isArray(data)) {
        return data
          .filter(s => typeof s === 'string' && /^chrome-extension:\/\/[a-p]{32}\/$/.test(s))
          .slice(0, 16);
      }
    }
  } catch {}
  return [];
}

function saveChromeOrigins(app, origins) {
  try {
    const f = getChromeOriginsFilePath(app);
    if (f) {
      ensurePrivateDirSync(path.dirname(f));
      unlinkIfSymlinkSync(f);
      fs.writeFileSync(f, JSON.stringify(origins.slice(0, 16), null, 2), { mode: 0o600, encoding: 'utf8' });
      if (process.platform !== 'win32') {
        try { fs.chmodSync(f, 0o600); } catch {}
      }
    }
  } catch {}
}

function getKnownExtensionIds(app) {
  const publishedId = process.env.FUIN_CHROME_EXTENSION_ID || DEFAULT_CHROME_EXTENSION_ID;
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
    if (saved.length >= 16) saved.shift();
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

function deriveWin32PipePath(token) {
  const pipeTag = crypto.createHmac('sha256', String(token)).update('fuin-win32-pipe-v1').digest('hex').slice(0, 24);
  return `\\\\.\\pipe\\fuin-ext-${pipeTag}`;
}

function getExtSocketPath(app) {
  if (process.platform === 'win32') {
    const token = getOrCreateExtToken(app);
    return deriveWin32PipePath(token);
  }
  return path.join(app.getPath('userData'), 'fuin-ext.sock');
}

function getNativeHostJsPath(app) {
  return app.isPackaged
    ? path.join(process.resourcesPath, 'native-host', 'host.js')
    : path.join(__dirname, '..', 'native-host', 'host.js');
}

function validateWrapperExecPath(rawPath, label) {
  if (typeof rawPath !== 'string' || !rawPath.trim()) {
    throw new Error(`Invalid ${label}: empty path`);
  }
  if (/[\r\n\0]/.test(rawPath)) {
    throw new Error(`Invalid ${label}: contains control characters`);
  }
  return rawPath;
}

function escapePosixShellArg(arg) {
  return `'${String(arg).replace(/'/g, "'\\''")}'`;
}

function formatNativeHostWrapperScript(electronPath, hostJs, platform = process.platform) {
  const safeElectron = validateWrapperExecPath(electronPath, 'electronPath');
  const safeHostJs = validateWrapperExecPath(hostJs, 'hostJs');
  if (platform === 'win32') {
    if (/"/.test(safeElectron) || /"/.test(safeHostJs)) {
      throw new Error('Invalid Windows wrapper path: contains double quote');
    }
    const batElectron = safeElectron.replace(/%/g, '%%');
    const batHostJs = safeHostJs.replace(/%/g, '%%');
    return `@echo off\r\nset ELECTRON_RUN_AS_NODE=1\r\n"${batElectron}" "${batHostJs}" %*\r\n`;
  }
  return `#!/bin/sh\nexport ELECTRON_RUN_AS_NODE=1\nexec ${escapePosixShellArg(safeElectron)} ${escapePosixShellArg(safeHostJs)} "$@"\n`;
}

function ensureNativeHostWrapper(app) {
  const hostJs = getNativeHostJsPath(app);
  const wrapperDir = app.getPath('userData');
  const electronPath = process.execPath;
  ensurePrivateDirSync(wrapperDir);

  const scriptContent = formatNativeHostWrapperScript(electronPath, hostJs, process.platform);
  if (process.platform === 'win32') {
    const batPath = path.join(wrapperDir, 'fuin-host.bat');
    unlinkIfSymlinkSync(batPath);
    fs.writeFileSync(batPath, scriptContent, { mode: 0o700, encoding: 'utf8' });
    return batPath;
  }
  const shPath = path.join(wrapperDir, 'fuin-host.sh');
  unlinkIfSymlinkSync(shPath);
  fs.writeFileSync(shPath, scriptContent, { mode: 0o700, encoding: 'utf8' });
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
    unlinkIfSymlinkSync(targetPath);
    fs.writeFileSync(targetPath, JSON.stringify(manifest, null, 2), { mode: 0o600, encoding: 'utf8' });
    if (process.platform !== 'win32') {
      try { fs.chmodSync(targetPath, 0o600); } catch {}
    }
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
  const ids = knownExtensionIds || getKnownExtensionIds(app);
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
  const userDataDir = path.dirname(tokenFile);
  ensurePrivateDirSync(userDataDir);

  let existingStat = null;
  try {
    existingStat = fs.lstatSync(tokenFile);
  } catch (err) {
    if (err && err.code !== 'ENOENT') throw err;
  }

  if (existingStat) {
    if (existingStat.isSymbolicLink()) {
      // Never read or write through a symlink; unlink only the symlink itself and regenerate cleanly
      fs.unlinkSync(tokenFile);
    } else if (!existingStat.isFile()) {
      throw new Error('Refusing non-regular extension token path');
    } else {
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
  }

  const token = crypto.randomBytes(32).toString('hex');
  const tmpFile = path.join(
    userDataDir,
    `.fuin.ext-token.${process.pid}.${Date.now()}.${crypto.randomBytes(8).toString('hex')}.tmp`
  );
  let fd;
  try {
    fd = fs.openSync(tmpFile, 'wx', 0o600);
    if (process.platform !== 'win32') {
      try { fs.fchmodSync(fd, 0o600); } catch {}
    }
    const buf = Buffer.from(token, 'utf8');
    let offset = 0;
    while (offset < buf.length) {
      offset += fs.writeSync(fd, buf, offset, buf.length - offset);
    }
    try { fs.fsyncSync(fd); } catch {}
  } catch (err) {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
      fd = undefined;
    }
    try { fs.unlinkSync(tmpFile); } catch {}
    throw err;
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }

  try {
    fs.renameSync(tmpFile, tokenFile);
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch {}
    throw err;
  }

  if (process.platform !== 'win32') {
    try {
      const finalStat = fs.lstatSync(tokenFile);
      if (!finalStat.isSymbolicLink() && finalStat.isFile()) {
        fs.chmodSync(tokenFile, 0o600);
      }
    } catch {}
  }
  return token;
}

function safeCompare(a, b) {
  const key = crypto.randomBytes(32);
  const h1 = crypto.createHmac('sha256', key).update(String(a)).digest();
  const h2 = crypto.createHmac('sha256', key).update(String(b)).digest();
  return crypto.timingSafeEqual(h1, h2);
}

function getBridgeListenOptions(socketPath, platform = process.platform) {
  if (platform === 'win32') {
    return { path: socketPath, readableAll: false, writableAll: false };
  }
  return socketPath;
}

let extServer = null;
const pendingExtRequests = new Map(); // requestId -> { resolve, reject, timer }
let extRequestCounter = 0;
let lastBridgeOptions = null;
let socketWatchdog = null;

function ensureSocketAlive() {
  if (process.platform === 'win32' || !extServer || !lastBridgeOptions) return;
  const socketPath = getExtSocketPath(lastBridgeOptions.app);
  let alive = false;
  try {
    const st = fs.lstatSync(socketPath);
    alive = !st.isSymbolicLink() && st.isSocket();
  } catch {}
  if (!alive) {
    console.warn('[fuin-ext-bridge] Socket file missing or invalid while server is active. Recreating listener at:', socketPath);
    try { extServer.close(); } catch {}
    extServer = null;
    startExtensionBridge(lastBridgeOptions);
  }
}

function relayToRenderer(getMainWindow, channel, payload, timeoutMs = 30000) {
  return new Promise((resolve, reject) => {
    const mainWindow = getMainWindow();
    if (!mainWindow || mainWindow.isDestroyed?.()) return reject(new Error('no-window'));
    if (pendingExtRequests.size >= 64) return reject(new Error('busy'));
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

  if (process.platform !== 'win32') {
    ensurePrivateDirSync(path.dirname(socketPath));
    let sockStat = null;
    try {
      sockStat = fs.lstatSync(socketPath);
    } catch (err) {
      if (err && err.code !== 'ENOENT') throw err;
    }
    if (sockStat) {
      if (sockStat.isSymbolicLink()) {
        // Safely unlink only the symlink itself — never follow it
        try { fs.unlinkSync(socketPath); } catch {}
      } else if (sockStat.isSocket()) {
        try { fs.unlinkSync(socketPath); } catch {}
      } else {
        throw new Error(`Refusing to overwrite non-socket extension bridge path: ${socketPath}`);
      }
    }
  }

  extServer = net.createServer((socket) => {
    const socketState = { badAuthCount: 0, terminated: false };
    socket.setTimeout(SOCKET_IDLE_TIMEOUT_MS, () => {
      try { socket.destroy(); } catch {}
    });
    let buf = '';
    socket.on('data', async (chunk) => {
      if (socket.destroyed || socketState.terminated) return;
      buf += chunk.toString('utf8');
      if (buf.length > 65536) {
        socketState.terminated = true;
        socket.destroy();
        return;
      }
      let nl;
      while ((nl = buf.indexOf('\n')) >= 0) {
        if (socket.destroyed || socketState.terminated) return;
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (!line.trim()) continue;
        await handleExtMessage(socket, line, socketState);
      }
    });
    socket.on('error', () => {});
  });

  extServer.on('error', (e) => console.error('[fuin-ext-bridge] socket hatası:', e.message));
  const listenOptions = getBridgeListenOptions(socketPath, process.platform);
  extServer.listen(listenOptions, () => {
    if (process.platform !== 'win32') {
      try {
        const st = fs.lstatSync(socketPath);
        if (!st.isSymbolicLink() && st.isSocket()) {
          fs.chmodSync(socketPath, 0o600);
        }
      } catch {}
    }
    console.log('[fuin-ext-bridge] dinliyor:', socketPath);
  });

  if (!socketWatchdog && process.platform !== 'win32') {
    socketWatchdog = setInterval(ensureSocketAlive, 3000);
    if (typeof socketWatchdog.unref === 'function') {
      socketWatchdog.unref();
    }
  }

  const rateBuckets = new Map();
  function checkRateLimit(key, maxCount, windowMs) {
    const now = Date.now();
    const arr = (rateBuckets.get(key) || []).filter(ts => now - ts < windowMs);
    if (arr.length >= maxCount) {
      rateBuckets.set(key, arr);
      return false;
    }
    arr.push(now);
    rateBuckets.set(key, arr);
    return true;
  }

  async function handleExtMessage(socket, line, socketState) {
    let msg;
    try { msg = JSON.parse(line); } catch { return; }
    const reply = (obj) => { try { socket.write(JSON.stringify(obj) + '\n'); } catch {} };

    if (!msg.token || typeof msg.token !== 'string' || !safeCompare(msg.token, token)) {
      socketState.badAuthCount += 1;
      if (socketState.badAuthCount >= MAX_BAD_AUTH_PER_SOCKET) {
        socketState.terminated = true;
        try {
          socket.end(JSON.stringify({ id: msg.id, error: 'unauthorized' }) + '\n', () => {
            try { socket.destroy(); } catch {}
          });
        } catch {
          try { socket.destroy(); } catch {}
        }
        const killTimer = setTimeout(() => {
          try { if (!socket.destroyed) socket.destroy(); } catch {}
        }, 250);
        if (typeof killTimer.unref === 'function') killTimer.unref();
        return;
      }
      return reply({ id: msg.id, error: 'unauthorized' });
    }
    socketState.badAuthCount = 0;
    if (!checkRateLimit('global', 80, 10000)) {
      return reply({ id: msg.id, error: 'rate-limited' });
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
    if (msg.type === 'ping') {
      return reply({ id: msg.id, ok: true, pong: true, protocolVersion: PROTOCOL_VERSION, timestamp: Date.now() });
    }
    if (msg.type === 'handshake') {
      const clientProto = Number.isFinite(Number(msg.protocolVersion)) ? Number(msg.protocolVersion) : 1;
      const hostProto = Number.isFinite(Number(msg.hostProtocolVersion)) ? Number(msg.hostProtocolVersion) : null;
      const compatible = (clientProto === PROTOCOL_VERSION) && (hostProto === null || hostProto === PROTOCOL_VERSION);
      let appVer = '1.0.0';
      try {
        if (app && typeof app.getVersion === 'function') appVer = app.getVersion();
      } catch {}
      return reply({
        id: msg.id,
        ok: true,
        protocolVersion: PROTOCOL_VERSION,
        minProtocolVersion: PROTOCOL_VERSION,
        clientProtocolVersion: clientProto,
        hostProtocolVersion: hostProto,
        appVersion: appVer,
        unlocked: !!getIsUnlocked(),
        compatible
      });
    }
    if (msg.protocolVersion !== undefined) {
      const reqProto = Number(msg.protocolVersion);
      if (!Number.isFinite(reqProto) || reqProto !== PROTOCOL_VERSION) {
        return reply({
          id: msg.id,
          error: 'protocol-mismatch',
          protocolVersion: PROTOCOL_VERSION,
          clientProtocolVersion: Number.isFinite(reqProto) ? reqProto : null,
          compatible: false
        });
      }
    }
    if (!getIsUnlocked()) {
      return reply({ id: msg.id, error: 'locked' });
    }

    if (typeof onActivity === 'function') {
      try { onActivity(); } catch {}
    }

    try {
      if (msg.type === 'lookup') {
        const domain = String(msg.domain || '').slice(0, 253);
        const matches = await relayToRenderer(getMainWindow, 'ext-lookup-request', { domain });
        reply({ id: msg.id, matches });
      } else if (msg.type === 'list-vault-items') {
        const result = await relayToRenderer(getMainWindow, 'ext-list-vault-items-request', {});
        reply({ id: msg.id, ...(result && typeof result === 'object' ? result : { cards: [], notes: [] }) });
      } else if (msg.type === 'reveal') {
        const result = await relayToRenderer(getMainWindow, 'ext-reveal-request', {
          entryId: String(msg.entryId || '').slice(0, 128),
          domain: String(msg.domain || '').slice(0, 253)
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'copy-secure') {
        const allowedFields = new Set(['username', 'password', 'cardNumber', 'cardCvv', 'secureNote']);
        const result = await relayToRenderer(getMainWindow, 'ext-copy-secure-request', {
          entryId: String(msg.entryId || '').slice(0, 128),
          domain: String(msg.domain || '').slice(0, 253),
          field: allowedFields.has(msg.field) ? msg.field : 'password'
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'check-save-candidate') {
        if (!checkRateLimit('check-save', 30, 60000)) {
          return reply({ id: msg.id, error: 'rate-limited', shouldPrompt: false });
        }
        const result = await relayToRenderer(getMainWindow, 'ext-check-save-candidate-request', {
          domain: String(msg.domain || '').slice(0, 253),
          username: String(msg.username || '').slice(0, 512),
          password: String(msg.password || '').slice(0, 1024)
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'save-credential') {
        if (!checkRateLimit('save-cred', 10, 60000)) {
          return reply({ id: msg.id, error: 'rate-limited' });
        }
        if (
          !msg.domain || typeof msg.domain !== 'string' || msg.domain.length > 253 ||
          !msg.password || typeof msg.password !== 'string' || msg.password.length > 1024 ||
          (msg.username && String(msg.username).length > 512)
        ) {
          return reply({ id: msg.id, error: 'invalid-credential' });
        }
        const result = await relayToRenderer(getMainWindow, 'ext-save-credential-request', {
          domain: msg.domain.slice(0, 253),
          username: String(msg.username || '').slice(0, 512),
          password: msg.password,
          updateEntryId: msg.updateEntryId ? String(msg.updateEntryId).slice(0, 128) : undefined
        });
        reply({ id: msg.id, ...result });
      } else if (msg.type === 'exclude-domain') {
        if (!checkRateLimit('exclude-dom', 20, 60000)) {
          return reply({ id: msg.id, error: 'rate-limited' });
        }
        const result = await relayToRenderer(getMainWindow, 'ext-exclude-domain-request', {
          domain: String(msg.domain || '').slice(0, 253)
        });
        reply({ id: msg.id, ...result });
      } else {
        reply({ id: msg.id, error: 'unknown-type' });
      }
    } catch (e) {
      const code = (e.message === 'timeout' || e.message === 'busy') ? e.message : 'internal-error';
      reply({ id: msg.id, error: code });
    }
  }
}

function stopExtensionBridge() {
  if (socketWatchdog) {
    clearInterval(socketWatchdog);
    socketWatchdog = null;
  }
  for (const [, pending] of pendingExtRequests.entries()) {
    clearTimeout(pending.timer);
    try { pending.reject(new Error('stopped')); } catch {}
  }
  pendingExtRequests.clear();
  if (extServer) {
    try { extServer.close(); } catch {}
    extServer = null;
  }
  if (process.platform !== 'win32' && lastBridgeOptions?.app) {
    try {
      const sock = getExtSocketPath(lastBridgeOptions.app);
      if (sock) {
        const st = fs.lstatSync(sock);
        if (!st.isSymbolicLink() && st.isSocket()) {
          fs.unlinkSync(sock);
        }
      }
    } catch {}
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
  PROTOCOL_VERSION,
  MAX_BAD_AUTH_PER_SOCKET,
  ensurePrivateDirSync,
  formatNativeHostWrapperScript,
  getBridgeListenOptions,
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
