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

const PRODUCT_NAME = 'Fuin';

function getUserDataPath() {
  const home = os.homedir();
  if (process.platform === 'darwin') return path.join(home, 'Library', 'Application Support', PRODUCT_NAME);
  if (process.platform === 'win32')  return path.join(process.env.APPDATA || path.join(home, 'AppData', 'Roaming'), PRODUCT_NAME);
  return path.join(process.env.XDG_CONFIG_HOME || path.join(home, '.config'), PRODUCT_NAME);
}

const USER_DATA    = getUserDataPath();
const TOKEN_FILE   = path.join(USER_DATA, 'fuin.ext-token');
const SOCKET_PATH  = process.platform === 'win32'
  ? '\\\\.\\pipe\\fuin-ext-bridge'
  : path.join(USER_DATA, 'fuin-ext.sock');

// ── Chrome Native Messaging stdio protokolü ─────────────────────────
function readMessages(onMessage) {
  let buf = Buffer.alloc(0);
  process.stdin.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      if (buf.length < 4) return;
      const len = buf.readUInt32LE(0);
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
  let token;
  try { token = fs.readFileSync(TOKEN_FILE, 'utf8').trim(); }
  catch { return cb({ error: 'fuin-not-installed-or-never-run' }); }

  const socket = net.createConnection(SOCKET_PATH);
  let buf = '';
  const reqId = request.id || Math.random().toString(36).slice(2);

  socket.on('connect', () => {
    socket.write(JSON.stringify({ ...request, id: reqId, token }) + '\n');
  });
  socket.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    const nl = buf.indexOf('\n');
    if (nl >= 0) {
      try { cb(JSON.parse(buf.slice(0, nl))); } catch { cb({ error: 'bad-response' }); }
      socket.end();
    }
  });
  socket.on('error', () => cb({ error: 'fuin-not-running' }));
  socket.on('timeout', () => { socket.destroy(); cb({ error: 'timeout' }); });
  socket.setTimeout(35000);
}

readMessages((msg) => {
  if (!msg || !msg.type) return writeMessage({ error: 'bad-request' });
  forwardToFuin(msg, (result) => writeMessage(result));
});

// stdin kapanınca (tarayıcı eklentiyi/portu kapattı) sessizce çık
process.stdin.on('end', () => process.exit(0));
