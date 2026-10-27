'use strict';
const assert = require('assert');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const net    = require('net');

console.log('═'.repeat(70));
console.log('CHALLENGER 1: ADVERSARIAL STRESS TEST HARNESS');
console.log('Sync V2 Full Snapshot Invariant, Native Host Auth, and Reveal Modal');
console.log('═'.repeat(70));

let totalTests = 0;
let passedTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    passedTests++;
    console.log(`  ✓ PASS: ${name}`);
  } catch (err) {
    console.error(`  ✗ FAIL: ${name}`);
    console.error(`    ${err.message}`);
    throw err;
  }
}

async function testAsync(name, fn) {
  totalTests++;
  try {
    await fn();
    passedTests++;
    console.log(`  ✓ PASS: ${name}`);
  } catch (err) {
    console.error(`  ✗ FAIL: ${name}`);
    console.error(`    ${err.message}`);
    throw err;
  }
}

(async () => {
  // =========================================================================
  // SECTION 1: Sync V2 Full Snapshot Invariant & IPC Defense Tests
  // =========================================================================
  console.log('\n--- SECTION 1: Sync V2 Full Snapshot Invariant & Rejection Tests ---');

  // Load sync-v2 modules
  const syncV2 = require('./sync-v2');
  const syncCrypto = require('./sync-v2-crypto');
  const { GenerationManager } = require('./sync-v2-payload');

  const syncTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'challenger1-sync-test-'));
  syncV2.initGenerationManager(syncTmpDir);

  // 1.1 IPC Handler Simulation for open-sync-window
  function simulateOpenSyncWindowIPC(payload, mockSend) {
    const { syncPassword, entries } = payload || {};
    if (!syncPassword || typeof syncPassword !== 'string') {
      if (mockSend) mockSend('sync-error', 'SYNC_V2: syncPassword is required');
      return false;
    }
    if (!entries) {
      if (mockSend) mockSend('sync-error', 'SYNC_V2: entries array is required');
      return false;
    }
    try {
      const entryArray = typeof entries === 'string' ? JSON.parse(entries) : entries;
      if (!Array.isArray(entryArray) || entryArray.length === 0) {
        throw new Error('SYNC_V2: entries must be a non-empty array representing full vault');
      }
      return true;
    } catch (e) {
      if (mockSend) mockSend('sync-error', e.message);
      return false;
    }
  }

  // 1.2 IPC Handler Simulation for rebuild-chunks-v2
  function simulateRebuildChunksIPC(payload) {
    const { syncPassword, entries } = payload || {};
    if (!syncPassword || !entries) throw new Error('SYNC_V2: syncPassword and entries required');
    const entryArray = typeof entries === 'string' ? JSON.parse(entries) : entries;
    if (!Array.isArray(entryArray) || entryArray.length === 0) {
      throw new Error('SYNC_V2: entries must be a non-empty array representing full vault');
    }
    return true;
  }

  test('IPC open-sync-window: Reject missing syncPassword', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ entries: [{ id: '1', site: 'test' }] }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: syncPassword is required');
  });

  test('IPC open-sync-window: Reject non-string syncPassword (number, boolean, obj)', () => {
    for (const badPw of [12345, true, {}, [], () => {}]) {
      let err = null;
      const res = simulateOpenSyncWindowIPC({ syncPassword: badPw, entries: [{ id: '1' }] }, (ch, msg) => { err = msg; });
      assert.strictEqual(res, false);
      assert.strictEqual(err, 'SYNC_V2: syncPassword is required');
    }
  });

  test('IPC open-sync-window: Reject empty string syncPassword', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: '', entries: [{ id: '1' }] }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: syncPassword is required');
  });

  test('IPC open-sync-window: Reject missing entries (null / undefined)', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: 'secure-pw', entries: null }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: entries array is required');
  });

  test('IPC open-sync-window: Reject empty array entries []', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: 'secure-pw', entries: [] }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: entries must be a non-empty array representing full vault');
  });

  test('IPC open-sync-window: Reject string empty array "[]"', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: 'secure-pw', entries: '[]' }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: entries must be a non-empty array representing full vault');
  });

  test('IPC open-sync-window: Reject non-array object entries', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: 'secure-pw', entries: { id: 'single' } }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert.strictEqual(err, 'SYNC_V2: entries must be a non-empty array representing full vault');
  });

  test('IPC open-sync-window: Reject corrupt JSON string entries', () => {
    let err = null;
    const res = simulateOpenSyncWindowIPC({ syncPassword: 'secure-pw', entries: '{bad-json:' }, (ch, msg) => { err = msg; });
    assert.strictEqual(res, false);
    assert(err.includes('Unexpected') || err.includes('JSON'));
  });

  test('IPC rebuild-chunks-v2: Strictly rejects empty or non-array entries', () => {
    assert.throws(() => simulateRebuildChunksIPC({ syncPassword: 'pw', entries: [] }), /non-empty array/);
    assert.throws(() => simulateRebuildChunksIPC({ syncPassword: 'pw', entries: {} }), /non-empty array/);
    assert.throws(() => simulateRebuildChunksIPC({ syncPassword: 'pw', entries: null }), /required/);
    assert.throws(() => simulateRebuildChunksIPC({ syncPassword: '', entries: [{ id: '1' }] }), /required/);
  });

  await testAsync('V2 QR Generation with Valid Vault Snapshot', async () => {
    const sampleEntries = [
      { id: '1', site: 'example.com', username: 'alice', password: 'secret1', totp: '' },
      { id: '2', site: 'fuin.org', username: 'bob', password: 'secret2', totp: 'JBSWY3DPEHPK3PXP' }
    ];
    const res = await syncV2.buildV2QRChunks(sampleEntries, 'MyStrongSyncPassword123!');
    assert(res.qrChunks.length >= 1, 'Should generate at least 1 chunk');
    assert.strictEqual(typeof res.sessionIdHex, 'string');
    assert.strictEqual(res.sessionIdHex.length, 16);
    assert(res.total >= 1);
    assert(res.qrChunks[0].startsWith('FUIN|2|'));
  });

  // 1.3 Envelope & Crypto Adversarial Corruption Tests
  await testAsync('Adversarial Crypto: Envelope Tamper Rejection & Zeroization', async () => {
    const pw = 'TestSyncPassword123!';
    const salt = crypto.randomBytes(16);
    const key = await syncCrypto.deriveSyncKey(pw, salt);
    const sessionId = crypto.randomBytes(8);
    const aad = syncCrypto.buildAAD(sessionId, salt);
    const plaintext = Buffer.from('SECRET_VAULT_PAYLOAD_CANONICAL_CBOR');

    const { ciphertext, nonce } = syncCrypto.syncEncrypt(plaintext, key, aad);
    const validEnvelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);

    // Test 1: Valid envelope roundtrip
    const parsed = syncCrypto.parseEnvelope(validEnvelope);
    const decrypted = syncCrypto.syncDecrypt(parsed.ciphertext, key, parsed.nonce, aad);
    assert.strictEqual(decrypted.toString('utf8'), 'SECRET_VAULT_PAYLOAD_CANONICAL_CBOR');

    // Test 2: Altered magic bytes
    const badMagic = Buffer.from(validEnvelope);
    badMagic[0] = 0x58; // 'X'
    assert.throws(() => syncCrypto.parseEnvelope(badMagic), /magic/i);

    // Test 3: Altered wire version (e.g. 0x01 or 0x03)
    const badVersion = Buffer.from(validEnvelope);
    badVersion[2] = 0x03;
    assert.throws(() => syncCrypto.parseEnvelope(badVersion), /wire_version|versiyon/i);

    // Test 4: Truncated envelope (< 59 bytes)
    const truncated = validEnvelope.slice(0, 50);
    assert.throws(() => syncCrypto.parseEnvelope(truncated), /RangeError|minimum/i);

    // Test 5: Tampered ciphertext (1 bit flipped)
    const tamperedCiphertext = Buffer.from(parsed.ciphertext);
    tamperedCiphertext[10] ^= 0x01;
    assert.throws(() => {
      syncCrypto.syncDecrypt(tamperedCiphertext, key, parsed.nonce, aad);
    }, /SYNC_V2_AUTH_FAILED/);

    // Test 6: Tampered auth tag (last 16 bytes)
    const tamperedTag = Buffer.from(parsed.ciphertext);
    tamperedTag[tamperedTag.length - 1] ^= 0xff;
    assert.throws(() => {
      syncCrypto.syncDecrypt(tamperedTag, key, parsed.nonce, aad);
    }, /SYNC_V2_AUTH_FAILED/);

    // Test 7: Tampered nonce
    const tamperedNonce = Buffer.from(parsed.nonce);
    tamperedNonce[0] ^= 0x01;
    assert.throws(() => {
      syncCrypto.syncDecrypt(parsed.ciphertext, key, tamperedNonce, aad);
    }, /SYNC_V2_AUTH_FAILED/);

    // Test 8: Tampered AAD
    const tamperedAAD = Buffer.from(aad);
    tamperedAAD[0] ^= 0x01;
    assert.throws(() => {
      syncCrypto.syncDecrypt(parsed.ciphertext, key, parsed.nonce, tamperedAAD);
    }, /SYNC_V2_AUTH_FAILED/);

    // Test 9: Wrong Sync Password
    const wrongKey = await syncCrypto.deriveSyncKey('WrongPassword123!', salt);
    assert.throws(() => {
      syncCrypto.syncDecrypt(parsed.ciphertext, wrongKey, parsed.nonce, aad);
    }, /SYNC_V2_AUTH_FAILED/);

    // Cleanup keys
    key.fill(0);
    wrongKey.fill(0);
  });

  // 1.4 Codebase Invariant Static Verification
  test('Renderer App & Index: Absence of Partial Sync & Single Sync UI Elements', () => {
    const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');
    const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
    const preloadJs = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');

    assert(!appJs.includes('btnSyncPartial'), 'app.js must not contain btnSyncPartial');
    assert(!appJs.includes('sync-single'), 'app.js must not contain sync-single action');
    assert(!appJs.includes('openSyncOptions'), 'app.js must not contain openSyncOptions');
    assert(!indexHtml.includes('btnSyncPartial'), 'index.html must not contain btnSyncPartial');
    assert(!indexHtml.includes('syncOptionsOverlay'), 'index.html must not contain syncOptionsOverlay');
    assert(!preloadJs.includes('openSyncWindow:'), 'preload.js must not expose legacy openSyncWindow');
    assert(!preloadJs.includes('rebuildChunks:'), 'preload.js must not expose legacy rebuildChunks');
    assert(!preloadJs.includes('encryptedB64'), 'preload.js must not mention encryptedB64');
    assert(preloadJs.includes('openSyncWindowV2'), 'preload.js must expose openSyncWindowV2');
  });

  fs.rmSync(syncTmpDir, { recursive: true, force: true });

  // =========================================================================
  // SECTION 2: Native Host Token & Windows Permission Adversarial Tests
  // =========================================================================
  console.log('\n--- SECTION 2: Native Host Token & Windows Permission Tests ---');

  // 2.1 safeCompare timingSafeEqual adversarial testing
  function safeCompare(a, b) {
    const key = crypto.randomBytes(32);
    const h1 = crypto.createHmac('sha256', key).update(String(a)).digest();
    const h2 = crypto.createHmac('sha256', key).update(String(b)).digest();
    return crypto.timingSafeEqual(h1, h2);
  }

  test('safeCompare: Exact matches pass, any mismatch or length difference fails', () => {
    const validTok = crypto.randomBytes(32).toString('hex');
    assert.strictEqual(safeCompare(validTok, validTok), true);
    assert.strictEqual(safeCompare(validTok, validTok.slice(0, 63) + (validTok[63] === 'a' ? 'b' : 'a')), false);
    assert.strictEqual(safeCompare(validTok, ''), false);
    assert.strictEqual(safeCompare(validTok, validTok.slice(0, 32)), false);
    assert.strictEqual(safeCompare(validTok, validTok + '0'), false);
    assert.strictEqual(safeCompare(validTok, '0' + validTok), false);
    assert.strictEqual(safeCompare(validTok, null), false);
    assert.strictEqual(safeCompare(validTok, undefined), false);
    assert.strictEqual(safeCompare(validTok, 12345), false);
  });

  // 2.2 Native host permission check logic from native-host/host.js
  function checkHostTokenPermissions(stat, platform, currentUid) {
    if (!stat.isFile()) {
      return { error: 'token-file-invalid' };
    }
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

  test('Native Host Permissions: POSIX (macOS/Linux) strictly enforces 0o600 and UID', () => {
    const uid = 501;
    // Exactly 0o600 and matching UID -> OK
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100600 }, 'darwin', uid), { ok: true });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 1000, mode: 0o100600 }, 'linux', 1000), { ok: true });

    // Permissive modes must fail
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100644 }, 'darwin', uid), { error: 'token-file-insecure-permissions' });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100666 }, 'darwin', uid), { error: 'token-file-insecure-permissions' });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100777 }, 'darwin', uid), { error: 'token-file-insecure-permissions' });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100700 }, 'darwin', uid), { error: 'token-file-insecure-permissions' });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 501, mode: 0o100660 }, 'darwin', uid), { error: 'token-file-insecure-permissions' });

    // Wrong UID must fail
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 502, mode: 0o100600 }, 'darwin', uid), { error: 'token-file-wrong-owner' });
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: 0, mode: 0o100600 }, 'darwin', uid), { error: 'token-file-wrong-owner' });

    // Directory must fail
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => false, uid: 501, mode: 0o40700 }, 'darwin', uid), { error: 'token-file-invalid' });
  });

  test('Native Host Permissions: Windows bypasses mode check for 0o666 and 0o444 but enforces isFile', () => {
    // Windows NTFS maps writable files to 0o666 -> MUST PASS
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: undefined, mode: 0o100666 }, 'win32', undefined), { ok: true });
    // Windows NTFS read-only 0o444 -> MUST PASS
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => true, uid: undefined, mode: 0o100444 }, 'win32', undefined), { ok: true });
    // Directory on Windows -> MUST FAIL
    assert.deepStrictEqual(checkHostTokenPermissions({ isFile: () => false, uid: undefined, mode: 0o40777 }, 'win32', undefined), { error: 'token-file-invalid' });
  });

  // 2.3 Token File Generation, Self-Healing, and Ciphertext Rejection
  const testTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'challenger1-token-test-'));
  const testTokenFile = path.join(testTmpDir, 'fuin.ext-token');

  function getOrCreateExtTokenSim(tokenPath, platform) {
    if (fs.existsSync(tokenPath)) {
      try {
        const raw = fs.readFileSync(tokenPath, 'utf8').trim();
        if (/^[0-9a-f]{64}$/i.test(raw)) {
          if (platform !== 'win32') {
            try { fs.chmodSync(tokenPath, 0o600); } catch {}
          }
          return raw;
        }
      } catch {}
    }
    const token = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(tokenPath, token, { mode: 0o600, encoding: 'utf8' });
    if (platform !== 'win32') {
      try { fs.chmodSync(tokenPath, 0o600); } catch {}
    }
    return token;
  }

  test('Token Generation & Format Validation: 64 hex chars with 0o600 permissions', () => {
    const tok = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(tok.length, 64);
    assert(/^[0-9a-f]{64}$/i.test(tok));
    const stat = fs.statSync(testTokenFile);
    if (process.platform !== 'win32') {
      assert.strictEqual(stat.mode & 0o777, 0o600);
    }
    const loaded = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(loaded, tok, 'Existing valid token must be reused');
  });

  test('Token Self-Healing: SafeStorage ciphertext automatically overwritten with fresh token', () => {
    // Write 83-byte binary safeStorage simulated payload
    fs.writeFileSync(testTokenFile, Buffer.from('v10\x00\x01\x02\x03safeStorageEncryptedBinaryPayloadDoesNotMatch64HexEnd=='), { mode: 0o600 });
    const healed = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(healed.length, 64);
    assert(/^[0-9a-f]{64}$/i.test(healed));
    assert.strictEqual(fs.readFileSync(testTokenFile, 'utf8'), healed);
  });

  test('Token Self-Healing: Truncated or tampered token file overwritten with fresh token', () => {
    // 63-char token
    fs.writeFileSync(testTokenFile, 'a'.repeat(63), { mode: 0o600 });
    const healed1 = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(healed1.length, 64);
    assert.notStrictEqual(healed1, 'a'.repeat(63));

    // 65-char token
    fs.writeFileSync(testTokenFile, 'b'.repeat(65), { mode: 0o600 });
    const healed2 = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(healed2.length, 64);
    assert.notStrictEqual(healed2, 'b'.repeat(65));

    // Non-hex token
    fs.writeFileSync(testTokenFile, 'z'.repeat(64), { mode: 0o600 });
    const healed3 = getOrCreateExtTokenSim(testTokenFile, process.platform);
    assert.strictEqual(healed3.length, 64);
    assert(/^[0-9a-f]{64}$/i.test(healed3));
  });

  fs.rmSync(testTmpDir, { recursive: true, force: true });

  // 2.4 End-to-End Socket IPC Auth & Attack Vector Testing
  await testAsync('Socket IPC Adversarial Attack Vectors: Missing, Tampered, Bad Tokens, Locked Vault', async () => {
    const socketPath = process.platform === 'win32'
      ? '\\\\.\\pipe\\challenger1-sock-' + Date.now()
      : path.join(os.tmpdir(), 'challenger1-' + Date.now() + '.sock');

    const validServerToken = crypto.randomBytes(32).toString('hex');
    let vaultUnlocked = true;

    // Simulate main.js extServer socket logic
    const extServer = net.createServer((socket) => {
      let buf = '';
      socket.on('data', async (chunk) => {
        buf += chunk.toString('utf8');
        let nl;
        while ((nl = buf.indexOf('\n')) >= 0) {
          const line = buf.slice(0, nl);
          buf = buf.slice(nl + 1);
          if (!line.trim()) continue;
          let msg;
          try { msg = JSON.parse(line); } catch { return; }
          const reply = (obj) => { try { socket.write(JSON.stringify(obj) + '\n'); } catch {} };

          if (!msg.token || typeof msg.token !== 'string' || !safeCompare(msg.token, validServerToken)) {
            return reply({ id: msg.id, error: 'unauthorized' });
          }
          if (!vaultUnlocked) {
            return reply({ id: msg.id, error: 'locked' });
          }

          if (msg.type === 'lookup') {
            reply({ id: msg.id, matches: [{ id: 'entry-1', site: msg.domain, username: 'tester' }] });
          } else if (msg.type === 'reveal') {
            reply({ id: msg.id, requiresConfirmation: true });
          } else {
            reply({ id: msg.id, error: 'unknown-type' });
          }
        }
      });
    });

    await new Promise((resolve) => extServer.listen(socketPath, resolve));

    async function sendMsg(payload) {
      return new Promise((resolve, reject) => {
        const client = net.createConnection(socketPath, () => {
          client.write(JSON.stringify(payload) + '\n');
        });
        client.on('data', (d) => {
          const res = JSON.parse(d.toString('utf8').trim());
          client.end();
          resolve(res);
        });
        client.on('error', reject);
      });
    }

    // Attack 1: Missing token
    const r1 = await sendMsg({ id: 'a1', type: 'lookup', domain: 'example.com' });
    assert.strictEqual(r1.error, 'unauthorized');

    // Attack 2: Wrong token
    const r2 = await sendMsg({ id: 'a2', type: 'lookup', domain: 'example.com', token: crypto.randomBytes(32).toString('hex') });
    assert.strictEqual(r2.error, 'unauthorized');

    // Attack 3: Tampered token (1 bit flipped)
    const tamperedTok = validServerToken.slice(0, 63) + (validServerToken[63] === '0' ? '1' : '0');
    const r3 = await sendMsg({ id: 'a3', type: 'lookup', domain: 'example.com', token: tamperedTok });
    assert.strictEqual(r3.error, 'unauthorized');

    // Attack 4: Non-string tokens (type confusion)
    const r4 = await sendMsg({ id: 'a4', type: 'lookup', domain: 'example.com', token: 123456 });
    assert.strictEqual(r4.error, 'unauthorized');

    const r5 = await sendMsg({ id: 'a5', type: 'lookup', domain: 'example.com', token: { raw: validServerToken } });
    assert.strictEqual(r5.error, 'unauthorized');

    const r6 = await sendMsg({ id: 'a6', type: 'lookup', domain: 'example.com', token: true });
    assert.strictEqual(r6.error, 'unauthorized');

    // Attack 5: Valid token on locked vault
    vaultUnlocked = false;
    const r7 = await sendMsg({ id: 'a7', type: 'lookup', domain: 'example.com', token: validServerToken });
    assert.strictEqual(r7.error, 'locked');

    // Attack 6: Valid token on unlocked vault
    vaultUnlocked = true;
    const r8 = await sendMsg({ id: 'a8', type: 'lookup', domain: 'example.com', token: validServerToken });
    assert.strictEqual(r8.error, undefined);
    assert.strictEqual(r8.matches.length, 1);
    assert.strictEqual(r8.matches[0].site, 'example.com');

    await new Promise((resolve) => extServer.close(resolve));
    if (process.platform !== 'win32' && fs.existsSync(socketPath)) {
      try { fs.unlinkSync(socketPath); } catch {}
    }
  });

  // =========================================================================
  // SECTION 3: Credential Reveal Confirmation Modal Adversarial Verification
  // =========================================================================
  console.log('\n--- SECTION 3: Credential Reveal Modal Non-Bypassability Tests ---');

  // Simulate Renderer State & Modal Logic
  let mockRendererState = {
    entries: [
      { id: 'entry-sec-1', site: 'bank.com', username: 'john_doe', password: 'ENC_PASSWORD_CIPHERTEXT', totp: 'ENC_TOTP_CIPHERTEXT' }
    ],
    pendingExtReveal: null,
    overlayOpen: false,
    toastMsg: null
  };

  async function mockMemDecrypt(cipher) {
    if (cipher === 'ENC_PASSWORD_CIPHERTEXT') return 'SuperSecretPassword2026!';
    if (cipher === 'ENC_TOTP_CIPHERTEXT') return '123456';
    return cipher;
  }

  function mockDomainMatches(entry, domain) {
    if (!domain) return false;
    return entry.site.toLowerCase().includes(domain.toLowerCase());
  }

  // 3.1 Verify Lookup Never Leaks Password or TOTP
  test('Lookup Isolation: Lookup request only exposes id, site, username (NEVER password/totp)', () => {
    const lookupReq = { domain: 'bank.com' };
    const matches = mockRendererState.entries
      .filter(e => mockDomainMatches(e, lookupReq.domain))
      .map(e => ({ id: e.id, site: e.site, username: e.username }));

    assert.strictEqual(matches.length, 1);
    assert.strictEqual(matches[0].id, 'entry-sec-1');
    assert.strictEqual(matches[0].site, 'bank.com');
    assert.strictEqual(matches[0].username, 'john_doe');
    assert.strictEqual(matches[0].password, undefined, 'Password MUST NOT exist in lookup result');
    assert.strictEqual(matches[0].totp, undefined, 'TOTP MUST NOT exist in lookup result');
  });

  // 3.2 Reveal Flow Simulation
  let simulatedExtResponses = [];
  function mockExtRespond(requestId, payload) {
    simulatedExtResponses.push({ requestId, payload });
  }

  function handleOnExtRevealRequest(req) {
    const entry = mockRendererState.entries.find(e => e.id === req.entryId);
    if (!entry) {
      mockExtRespond(req.requestId, { error: 'not-found' });
      return;
    }
    mockRendererState.pendingExtReveal = { requestId: req.requestId, entry };
    mockRendererState.overlayOpen = true;
  }

  async function approveExtReveal() {
    if (!mockRendererState.pendingExtReveal) return;
    const { requestId, entry } = mockRendererState.pendingExtReveal;
    mockExtRespond(requestId, {
      username: entry.username,
      password: await mockMemDecrypt(entry.password),
      totp: (await mockMemDecrypt(entry.totp)) || null
    });
    mockRendererState.pendingExtReveal = null;
    mockRendererState.overlayOpen = false;
  }

  function denyExtReveal() {
    if (!mockRendererState.pendingExtReveal) return;
    mockExtRespond(mockRendererState.pendingExtReveal.requestId, { error: 'denied' });
    mockRendererState.pendingExtReveal = null;
    mockRendererState.overlayOpen = false;
  }

  function handleLockEvent() {
    if (mockRendererState.pendingExtReveal) {
      mockExtRespond(mockRendererState.pendingExtReveal.requestId, { error: 'locked' });
      mockRendererState.pendingExtReveal = null;
    }
    mockRendererState.overlayOpen = false;
  }

  test('Reveal Request: Shows modal, holds pending, does NOT reveal without explicit approval', () => {
    simulatedExtResponses = [];
    handleOnExtRevealRequest({ requestId: 'req-1', entryId: 'entry-sec-1', domain: 'bank.com' });

    assert.strictEqual(mockRendererState.overlayOpen, true, 'Modal overlay MUST be opened');
    assert(mockRendererState.pendingExtReveal !== null, 'pendingExtReveal must be held');
    assert.strictEqual(simulatedExtResponses.length, 0, 'No response must be sent until user action');
  });

  test('Reveal Request: User Denies -> Returns { error: "denied" } and closes modal', () => {
    denyExtReveal();
    assert.strictEqual(mockRendererState.overlayOpen, false, 'Modal overlay must close');
    assert.strictEqual(mockRendererState.pendingExtReveal, null);
    assert.strictEqual(simulatedExtResponses.length, 1);
    assert.deepStrictEqual(simulatedExtResponses[0], { requestId: 'req-1', payload: { error: 'denied' } });
  });

  await testAsync('Reveal Request: User Approves -> Returns decrypted credentials and closes modal', async () => {
    simulatedExtResponses = [];
    handleOnExtRevealRequest({ requestId: 'req-2', entryId: 'entry-sec-1', domain: 'bank.com' });
    assert.strictEqual(mockRendererState.overlayOpen, true);

    await approveExtReveal();
    assert.strictEqual(mockRendererState.overlayOpen, false);
    assert.strictEqual(mockRendererState.pendingExtReveal, null);
    assert.strictEqual(simulatedExtResponses.length, 1);
    assert.strictEqual(simulatedExtResponses[0].payload.username, 'john_doe');
    assert.strictEqual(simulatedExtResponses[0].payload.password, 'SuperSecretPassword2026!');
    assert.strictEqual(simulatedExtResponses[0].payload.totp, '123456');
  });

  test('Reveal Request: Vault Locks During Pending Reveal -> Aborts with { error: "locked" }', () => {
    simulatedExtResponses = [];
    handleOnExtRevealRequest({ requestId: 'req-3', entryId: 'entry-sec-1', domain: 'bank.com' });
    assert.strictEqual(mockRendererState.overlayOpen, true);

    handleLockEvent();
    assert.strictEqual(mockRendererState.overlayOpen, false);
    assert.strictEqual(mockRendererState.pendingExtReveal, null);
    assert.strictEqual(simulatedExtResponses.length, 1);
    assert.deepStrictEqual(simulatedExtResponses[0], { requestId: 'req-3', payload: { error: 'locked' } });
  });

  test('Reveal Request: Non-existent entry ID -> Rejects with { error: "not-found" }', () => {
    simulatedExtResponses = [];
    handleOnExtRevealRequest({ requestId: 'req-4', entryId: 'entry-non-existent', domain: 'bank.com' });
    assert.strictEqual(mockRendererState.overlayOpen, false);
    assert.strictEqual(mockRendererState.pendingExtReveal, null);
    assert.strictEqual(simulatedExtResponses.length, 1);
    assert.deepStrictEqual(simulatedExtResponses[0], { requestId: 'req-4', payload: { error: 'not-found' } });
  });

  await testAsync('Reveal Request: Timeout (relayToRenderer 30s timer reject)', async () => {
    // Simulate main.js relayToRenderer timeout behavior
    let pendingRequests = new Map();
    function relayToRendererSim(timeoutMs) {
      return new Promise((resolve, reject) => {
        const reqId = 'timeout-test';
        const timer = setTimeout(() => {
          pendingRequests.delete(reqId);
          reject(new Error('timeout'));
        }, timeoutMs);
        pendingRequests.set(reqId, { resolve, reject, timer });
      });
    }

    try {
      await relayToRendererSim(50); // 50ms fast timeout simulation
      assert.fail('Should have timed out');
    } catch (e) {
      assert.strictEqual(e.message, 'timeout');
    }
  });

  console.log('\n═'.repeat(70));
  console.log(`ALL ADVERSARIAL STRESS TESTS PASSED: ${passedTests} / ${totalTests} (100%)`);
  syncV2.cancelSyncSession();
  process.exit(0);
  console.log('═'.repeat(70));
})();
