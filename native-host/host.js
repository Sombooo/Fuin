#!/usr/bin/env node
'use strict';
// ═══════════════════════════════════════════════════════════════════
// FUIN NATIVE MESSAGING HOST
//
// Tarayıcı bu process'i kendi başlatır ve stdin/stdout üzerinden
// Chrome'un "Native Messaging" protokolüyle konuşur:
//   [4 byte little-endian uzunluk][UTF-8 JSON mesaj]
//
// Bu host, gelen her mesajı Fuin'in yerel socket'ine (main.js'de
// başlatılan extServer) iletir, cevabı alır ve aynı protokolle
// tarayıcıya geri yazar. Kendisi hiçbir veri saklamaz veya görmez
// dışında yalnızca aktarım anındaki JSON payload.
// ═══════════════════════════════════════════════════════════════════
const net = require('net');
const fs  = require('fs');
const os  = require('os');
const path = require('path');
const crypto = require('crypto');

const PRODUCT_NAME = 'Fuin';
const MAX_MSG_SIZE = 1024 * 1024; // 1 MB güvenlik sınırı

function getUserDataPath() {
  const home = os.homedir();
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', PRODUCT_NAME);
  if (process.platform === 'win32')  return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), PRODUCT_NAME);
  return path.join(process.env.XDG_CONFIG_HOME || path.join(home, '.config'), PRODUCT_NAME);
}

const USER_DATA    = getUserDataPath();
const TOKEN_FILE   = path.join(USER_DATA, 'fuin.ext-token');

function getSocketPath(token) {
  if (process.platform === 'win32') {
    const pipeTag = crypto.createHmac('sha256', String(token)).update('fuin-win32-pipe-v1').digest('hex').slice(0, 24);
    return `\\\\.\\pipe\\fuin-ext-${pipeTag}`;
  }
  return path.join(USER_DATA, 'fuin-ext.sock');
}

// ── Chrome Native Messaging stdio protokolü ─────────────────────────
function readMessages(onMessage) {
  let buf = Buffer.alloc(0);
  process.stdin.on('data', (chunk) => {
    if (buf.length + chunk.length > MAX_MSG_SIZE + 4) {
      process.stderr.write('Message buffer exceeded limit\n');
      process.exit(1);
    }
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      if (buf.length < 4) return;
      const len = buf.readUInt32LE(0);
      if (len > MAX_MSG_SIZE) { process.stderr.write('Message too large\n'); process.exit(1); }
      if (buf.length < 4 + len) return;
      const msgBuf = buf.slice(4, 4 + len);
      buf = buf.slice(4 + len);
      try { onMessage(JSON.parse(msgBuf.toString('utf8'))); } catch { /* bozuk mesajı yoksay */ }
    }
  });
}

function writeMessage(obj) {
  const json = Buffer.from(JSON.stringify(obj), 'utf8');
  const len  = Buffer.alloc(4);
  len.writeUInt32LE(json.length, 0);
  process.stdout.write(Buffer.concat([len, json]));
}

// ── Fuin'e bağlan ve isteği ilet ────────────────────────────────────
function forwardToFuin(request, cb) {
  let done = false;
  const safeCb = (res) => {
    if (!done) {
      done = true;
      cb(res);
    }
  };

  let token;
  try {
    // Güvenlik: Token dosyasının varlığını, tipini, izinlerini ve sahipliğini doğrula
    const stat = fs.statSync(TOKEN_FILE);
    if (!stat.isFile()) {
      return safeCb({ error: 'token-file-invalid' });
    }
    if (process.platform !== 'win32') {
      if (typeof process.getuid === 'function' && stat.uid !== process.getuid()) {
        return safeCb({ error: 'token-file-wrong-owner' });
      }
      const mode = stat.mode & 0o777;
      if (mode !== 0o600) {
        return safeCb({ error: 'token-file-insecure-permissions' });
      }
    }
    token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
    if (!token || !/^[0-9a-f]{64}$/i.test(token)) {
      return safeCb({ error: 'token-file-invalid' });
    }
  } catch { return safeCb({ error: 'fuin-not-installed-or-never-run' }); }

  const socket = net.createConnection(getSocketPath(token));
  let buf = '';
  const reqId = request.id || crypto.randomBytes(8).toString('hex');

  socket.on('connect', () => {
    socket.write(JSON.stringify({ ...request, id: reqId, token }) + '\n');
  });
  socket.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    if (buf.length > MAX_MSG_SIZE) {
      socket.destroy();
      return safeCb({ error: 'response-too-large' });
    }
    const nl = buf.indexOf('\n');
    if (nl >= 0) {
      try { safeCb(JSON.parse(buf.slice(0, nl))); } catch { safeCb({ error: 'bad-response' }); }
      socket.end();
    }
  });
  socket.on('error', () => safeCb({ error: 'fuin-not-running' }));
  socket.on('timeout', () => { socket.destroy(); safeCb({ error: 'timeout' }); });
  socket.setTimeout(32000);
}

const ALLOWED_TYPES = new Set([
  'lookup',
  'reveal',
  'open-app',
  'check-save-candidate',
  'save-credential',
  'exclude-domain',
  'copy-secure'
]);

function clampField(val, maxLen) {
  return String(val || '').slice(0, maxLen);
}

readMessages((msg) => {
  if (!msg || typeof msg.type !== 'string') return writeMessage({ error: 'bad-request' });
  if (!ALLOWED_TYPES.has(msg.type)) return writeMessage({ error: 'unknown-type' });

  // Güvenlik: İletilen mesajlarda yalnızca bilinen alanları ve güvenli uzunluk sınırlarını geçir
  const sanitized = { type: msg.type };
  if (msg.type === 'lookup') {
    sanitized.domain = clampField(msg.domain, 253);
  } else if (msg.type === 'reveal') {
    sanitized.entryId = clampField(msg.entryId, 128);
    sanitized.domain = clampField(msg.domain, 253);
  } else if (msg.type === 'copy-secure') {
    sanitized.entryId = clampField(msg.entryId, 128);
    sanitized.domain = clampField(msg.domain, 253);
    sanitized.field = msg.field === 'username' ? 'username' : 'password';
  } else if (msg.type === 'check-save-candidate') {
    sanitized.domain = clampField(msg.domain, 253);
    sanitized.username = clampField(msg.username, 512);
    sanitized.password = clampField(msg.password, 1024);
  } else if (msg.type === 'save-credential') {
    sanitized.domain = clampField(msg.domain, 253);
    sanitized.username = clampField(msg.username, 512);
    sanitized.password = clampField(msg.password, 1024);
    if (msg.updateEntryId) sanitized.updateEntryId = clampField(msg.updateEntryId, 128);
  } else if (msg.type === 'exclude-domain') {
    sanitized.domain = clampField(msg.domain, 253);
  }
  forwardToFuin(sanitized, (result) => writeMessage(result));
});

// stdin kapanınca (tarayıcı eklentiyi/portu kapattı) sessizce çık
process.stdin.on('end', () => process.exit(0));
