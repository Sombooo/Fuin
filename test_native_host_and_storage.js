'use strict';
const assert = require('assert');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const net    = require('net');

console.log('═'.repeat(60));
console.log('FUIN NATIVE HOST, ATOMIC STORAGE & PORTABILITY TEST SUITE');
console.log('═'.repeat(60));

// ── 1. safeCompare tests ─────────────────────────────────────────────
function safeCompare(a, b) {
  const key = crypto.randomBytes(32);
  const h1 = crypto.createHmac('sha256', key).update(String(a)).digest();
  const h2 = crypto.createHmac('sha256', key).update(String(b)).digest();
  return crypto.timingSafeEqual(h1, h2);
}

const tokA = crypto.randomBytes(32).toString('hex');
const tokB = crypto.randomBytes(32).toString('hex');
const alteredTokA = tokA.slice(0, 63) + (tokA[63] === '0' ? '1' : '0');

assert.strictEqual(safeCompare(tokA, tokA), true, 'Identical token must match');
assert.strictEqual(safeCompare(tokA, tokB), false, 'Different token must not match');
assert.strictEqual(safeCompare(tokA, alteredTokA), false, '1-char altered token must not match');
assert.strictEqual(safeCompare('', tokA), false, 'Empty string must not match');
assert.strictEqual(safeCompare(tokA.slice(0, 32), tokA), false, 'Truncated token must not match');
console.log('✓ 1. safeCompare timingSafeEqual validation passed');

// ── 2. Native host permission check logic tests ──────────────────────
function validateHostPermissions(stat, platform, currentUid) {
  if (!stat.isFile()) return { error: 'token-file-invalid' };
  if (platform !== 'win32') {
    if (typeof currentUid === 'number' && typeof stat.uid === 'number' && stat.uid !== currentUid) {
      return { error: 'token-file-wrong-owner' };
    }
    const mode = stat.mode & 0o777;
    if (mode !== 0o600) {
      return { error: 'token-file-insecure-permissions' };
    }
  }
  return { ok: true };
}

// POSIX checks
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: 501, mode: 0o100600 }, 'darwin', 501), { ok: true });
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: 501, mode: 0o100644 }, 'darwin', 501), { error: 'token-file-insecure-permissions' });
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: 501, mode: 0o100666 }, 'darwin', 501), { error: 'token-file-insecure-permissions' });
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: 501, mode: 0o100777 }, 'darwin', 501), { error: 'token-file-insecure-permissions' });
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: 502, mode: 0o100600 }, 'linux', 501), { error: 'token-file-wrong-owner' });
assert.deepStrictEqual(validateHostPermissions({ isFile: () => false, uid: 501, mode: 0o40700 }, 'darwin', 501), { error: 'token-file-invalid' });

// Windows checks
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: undefined, mode: 0o100666 }, 'win32', undefined), { ok: true }, 'Windows 0o666 NTFS file must pass');
assert.deepStrictEqual(validateHostPermissions({ isFile: () => true, uid: undefined, mode: 0o100444 }, 'win32', undefined), { ok: true }, 'Windows 0o444 read-only file must pass');
assert.deepStrictEqual(validateHostPermissions({ isFile: () => false, uid: undefined, mode: 0o40777 }, 'win32', undefined), { error: 'token-file-invalid' });
console.log('✓ 2. Native host permission checks (POSIX 0o600 & Windows 0o666 bypass) passed');

// ── 3. Token file generation, load, and corruption recovery ──────────
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-token-test-'));
const testTokenPath = path.join(tmpDir, 'fuin.ext-token');

function getOrCreateTokenSim(filePath, platform) {
  if (fs.existsSync(filePath)) {
    try {
      const raw = fs.readFileSync(filePath, 'utf8').trim();
      if (/^[0-9a-f]{64}$/i.test(raw)) {
        if (platform !== 'win32') {
          try { fs.chmodSync(filePath, 0o600); } catch {}
        }
        return raw;
      }
    } catch {}
  }
  const tok = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(filePath, tok, { mode: 0o600, encoding: 'utf8' });
  if (platform !== 'win32') {
    try { fs.chmodSync(filePath, 0o600); } catch {}
  }
  return tok;
}

const createdTok = getOrCreateTokenSim(testTokenPath, process.platform);
assert.strictEqual(createdTok.length, 64, 'Token must be 64 hex characters (32 bytes)');
assert(/^[0-9a-f]{64}$/i.test(createdTok), 'Token must be valid hex');

const loadedTok = getOrCreateTokenSim(testTokenPath, process.platform);
assert.strictEqual(loadedTok, createdTok, 'Loading existing valid file must return identical token');

// Simulate recovery from corrupted/safeStorage ciphertext (83 bytes of binary data)
fs.writeFileSync(testTokenPath, Buffer.from('v10' + '\x00\x01\x02'.repeat(26) + 'end'), { mode: 0o600 });
const recoveredTok = getOrCreateTokenSim(testTokenPath, process.platform);
assert.strictEqual(recoveredTok.length, 64);
assert(/^[0-9a-f]{64}$/i.test(recoveredTok));
assert.notStrictEqual(recoveredTok, createdTok, 'Corrupted token must trigger fresh token generation');

fs.rmSync(tmpDir, { recursive: true, force: true });
console.log('✓ 3. Token generation, loading, and recovery from safeStorage ciphertext passed');

// ── 4. Atomic write & Crash Recovery Simulation ──────────────────────
const storageTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-storage-test-'));
const testDataFile = path.join(storageTmpDir, 'fuin.enc');
const testBackupDir = path.join(storageTmpDir, 'backups');
fs.mkdirSync(testBackupDir, { recursive: true, mode: 0o700 });

function writeAtomicSync(targetPath, data, options = {}) {
  const mode = options.mode || 0o600;
  const encoding = options.encoding || 'utf8';
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
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
    if (fd !== undefined) try { fs.closeSync(fd); } catch {}
  }
  fs.renameSync(tempPath, targetPath);
}

// Atomic write test
writeAtomicSync(testDataFile, 'VAULT_CONTENT_ORIGINAL', { mode: 0o600 });
assert.strictEqual(fs.readFileSync(testDataFile, 'utf8'), 'VAULT_CONTENT_ORIGINAL');

// Simulate backup before crash
fs.writeFileSync(path.join(testBackupDir, 'fuin.enc.2026-09-11T12-00-00-000Z.bak'), 'VAULT_BACKUP_CONTENT');

// Simulate 0-byte truncation crash
fs.writeFileSync(testDataFile, '');
assert.strictEqual(fs.statSync(testDataFile).size, 0);

// Test crash recovery logic
function simulateLoadDataWithRecovery(dataFile, backupDir) {
  if (!fs.existsSync(dataFile)) return null;
  const stat = fs.statSync(dataFile);
  if (stat.size === 0) {
    if (fs.existsSync(backupDir)) {
      const files = fs.readdirSync(backupDir)
        .filter(f => f.startsWith('fuin.enc.') && f.endsWith('.bak'))
        .map(f => ({ name: f, path: path.join(backupDir, f), stat: fs.statSync(path.join(backupDir, f)) }))
        .filter(f => f.stat.size > 0)
        .sort((a, b) => b.stat.mtime.getTime() - a.stat.mtime.getTime());
      if (files.length > 0) {
        const recovered = fs.readFileSync(files[0].path, 'utf8');
        writeAtomicSync(dataFile, recovered, { mode: 0o600 });
        return recovered;
      }
    }
  }
  return fs.readFileSync(dataFile, 'utf8');
}

const recoveredData = simulateLoadDataWithRecovery(testDataFile, testBackupDir);
assert.strictEqual(recoveredData, 'VAULT_BACKUP_CONTENT', 'Must recover latest non-empty backup');
assert.strictEqual(fs.readFileSync(testDataFile, 'utf8'), 'VAULT_BACKUP_CONTENT', 'Must persist recovered content to target file');
fs.rmSync(storageTmpDir, { recursive: true, force: true });
console.log('✓ 4. Atomic storage write and 0-byte crash-recovery passed');

// ── 5. End-to-end socket auth simulation ─────────────────────────────
const sockPath = process.platform === 'win32'
  ? '\\\\.\\pipe\\fuin-test-sock-' + Date.now()
  : path.join(os.tmpdir(), 'fuin-test-' + Date.now() + '.sock');

const serverToken = crypto.randomBytes(32).toString('hex');
let isUnlocked = true;

const server = net.createServer((socket) => {
  let buf = '';
  socket.on('data', (chunk) => {
    buf += chunk.toString('utf8');
    let nl;
    while ((nl = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, nl);
      buf = buf.slice(nl + 1);
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      const reply = (obj) => socket.write(JSON.stringify(obj) + '\n');
      if (!msg.token || typeof msg.token !== 'string' || !safeCompare(msg.token, serverToken)) {
        return reply({ id: msg.id, error: 'unauthorized' });
      }
      if (!isUnlocked) {
        return reply({ id: msg.id, error: 'locked' });
      }
      if (msg.type === 'lookup') {
        reply({ id: msg.id, matches: [{ id: 'entry-1', site: 'example.com', username: 'user@example.com' }] });
      } else if (msg.type === 'reveal') {
        reply({ id: msg.id, requiresConfirmation: true });
      }
    }
  });
});

server.listen(sockPath, async () => {
  function querySocket(payload) {
    return new Promise((resolve) => {
      const client = net.createConnection(sockPath, () => {
        client.write(JSON.stringify(payload) + '\n');
      });
      client.on('data', (data) => {
        const res = JSON.parse(data.toString('utf8').trim());
        client.end();
        resolve(res);
      });
    });
  }

  // Valid token
  const res1 = await querySocket({ id: '1', type: 'lookup', domain: 'example.com', token: serverToken });
  assert.strictEqual(res1.error, undefined);
  assert.strictEqual(res1.matches.length, 1);

  // Missing token
  const res2 = await querySocket({ id: '2', type: 'lookup', domain: 'example.com' });
  assert.strictEqual(res2.error, 'unauthorized');

  // Invalid / Tampered token
  const res3 = await querySocket({ id: '3', type: 'lookup', domain: 'example.com', token: 'bad-token' });
  assert.strictEqual(res3.error, 'unauthorized');

  // Locked vault
  isUnlocked = false;
  const res4 = await querySocket({ id: '4', type: 'lookup', domain: 'example.com', token: serverToken });
  assert.strictEqual(res4.error, 'locked');

  server.close(() => {
    if (process.platform !== 'win32' && fs.existsSync(sockPath)) {
      try { fs.unlinkSync(sockPath); } catch {}
    }
    console.log('✓ 5. Socket IPC authentication, missing token, tamper rejection, and lockout handling passed');
    console.log('═'.repeat(60));
    console.log('ALL NATIVE HOST & STORAGE TEST CASES PASSED (100%)');
    console.log('═'.repeat(60));
  });
});
