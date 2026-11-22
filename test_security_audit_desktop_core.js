'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN SECURITY AUDIT REMEDIATION TEST SUITE — DESKTOP CORE
 * Covers: CRYPTO-02, UPD-01, UPD-02, SYNC-01, SYNC-02, SYNC-03, SYNC-05, SYNC-07,
 *         and CRYPTO-01 (sync-lan.js & jsonImporter.js sanitization)
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const Module = require('module');
const os = require('os');
const path = require('path');

const syncLan = require('./sync-lan.js');
const jsonImporter = require('./services/importers/jsonImporter.js');

let passed = 0;
let failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err && err.stack ? err.stack : err}`);
    failed++;
  }
}

function makeByteStream(chunks) {
  let idx = 0;
  return {
    getReader() {
      return {
        async read() {
          if (idx >= chunks.length) return { done: true, value: undefined };
          return { done: false, value: chunks[idx++] };
        },
        async cancel() { idx = chunks.length; }
      };
    }
  };
}

function makeMockResponse({ ok = true, status = 200, url, chunks = [], headers = {} }) {
  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    normalizedHeaders[k.toLowerCase()] = String(v);
  }
  const buffers = chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)));
  return {
    ok,
    status,
    url,
    headers: { get: (n) => normalizedHeaders[String(n).toLowerCase()] || null },
    body: makeByteStream(buffers),
    async text() { return Buffer.concat(buffers).toString('utf8'); }
  };
}

function loadIsolatedMain(tmpRoot) {
  const userDataDir = path.join(tmpRoot, 'userData');
  const tempDir = path.join(tmpRoot, 'temp');
  fs.mkdirSync(userDataDir, { recursive: true, mode: 0o700 });
  fs.mkdirSync(tempDir, { recursive: true, mode: 0o700 });

  const mainHandlers = {};
  const openedPaths = [];
  const origReq = Module.prototype.require;
  Module.prototype.require = function (id) {
    if (id === 'electron') {
      return {
        app: {
          getPath: (name) => (name === 'temp' ? tempDir : userDataDir),
          getVersion: () => '1.0.0-test',
          isPackaged: false,
          quit: () => {},
          whenReady: () => new Promise(() => {}),
          on: () => {}
        },
        session: { defaultSession: { webRequest: { onHeadersReceived: () => {} } } },
        BrowserWindow: class {
          constructor() {
            return {
              webContents: { send: () => {}, on: () => {}, setWindowOpenHandler: () => {} },
              on: () => {},
              setContentProtection: () => {},
              loadFile: () => {},
              show: () => {},
              hide: () => {},
              isVisible: () => true
            };
          }
        },
        ipcMain: {
          handle: (ch, fn) => { mainHandlers[ch] = fn; },
          on: () => {}
        },
        dialog: {},
        clipboard: { writeText: () => {}, readText: () => '' },
        powerMonitor: { on: () => {}, getSystemIdleTime: () => 0 },
        shell: {
          openPath: async (p) => {
            openedPaths.push(p);
            return '';
          },
          openExternal: () => {}
        },
        Tray: class { setToolTip() {} popUpContextMenu() {} setContextMenu() {} on() {} },
        Menu: { buildFromTemplate: () => ({}) },
        nativeImage: { createFromPath: () => ({ resize: () => ({}) }) },
        systemPreferences: { canPromptTouchID: () => false },
        safeStorage: {
          isEncryptionAvailable: () => true,
          encryptString: (s) => Buffer.from(String(s), 'utf8'),
          decryptString: (b) => Buffer.from(b).toString('utf8')
        },
        Notification: class { static isSupported() { return false; } show() {} }
      };
    }
    return origReq.apply(this, arguments);
  };

  try {
    const mainResolved = require.resolve('./main.js');
    delete require.cache[mainResolved];
    const mainMod = require('./main.js');
    return { mainMod, mainHandlers, userDataDir, tempDir, openedPaths };
  } finally {
    Module.prototype.require = origReq;
  }
}

function sendHttpPost(port, urlPath, bodyObjOrStr, extraHeaders = {}) {
  return new Promise((resolve, reject) => {
    const raw = typeof bodyObjOrStr === 'string' ? bodyObjOrStr : JSON.stringify(bodyObjOrStr);
    const headers = Object.assign(
      {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(raw)
      },
      extraHeaders
    );
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: urlPath,
        method: 'POST',
        headers
      },
      (res) => {
        let data = '';
        res.on('data', (c) => { data += c; });
        res.on('end', () => {
          let parsed = null;
          try { parsed = JSON.parse(data); } catch {}
          resolve({ status: res.statusCode, data: parsed || data });
        });
      }
    );
    req.on('error', reject);
    req.write(raw);
    req.end();
  });
}

(async () => {
  console.log('\n═══════════════════════════════════════════════════════════════════════');
  console.log('FUIN SECURITY AUDIT REMEDIATION SUITE — DESKTOP CORE');
  console.log('═══════════════════════════════════════════════════════════════════════\n');

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-audit-core-'));
  const origFetch = global.fetch;

  try {
    // ── 1. CRYPTO-02: Authoritative Unlock, Lockout Isolation & Mutex ────────
    console.log('[1. CRYPTO-02: Authoritative Unlock, Lockout Isolation & Decrypt Mutex]');
    const mainEnv = loadIsolatedMain(path.join(tmpRoot, 'crypto02'));
    const { mainHandlers, userDataDir } = mainEnv;

    const realPw = 'RealMasterPassword!2026';
    const vaultObj = {
      type: 'fuin/vault',
      entries: [{ id: 'v1', site: 'example.com', username: 'alice', password: 'secret' }]
    };

    await runTest('1.1 Initial vault creation (save-data without DATA_FILE) sets authoritative unlock; lock clears it', async () => {
      const encVault = await mainHandlers['encrypt'](null, { data: vaultObj, password: realPw });
      assert.strictEqual(await mainHandlers['save-data'](null, encVault), true);

      // Lock vault
      assert.strictEqual(await mainHandlers['set-unlock-state'](null, false), true);

      // Renderer MUST NOT be able to re-unlock via set-unlock-state(true)
      const forged = await mainHandlers['set-unlock-state'](null, true);
      assert.strictEqual(forged, false, 'set-unlock-state(true) must NEVER unlock when locked');
    });

    await runTest('1.2 Locked mutating IPC handlers strictly reject (save-data, save-touchid-key, save-recovery-pair, save-recovery, save-master-enc, register-chrome-ext-id, decrypt-backup)', async () => {
      await assert.rejects(async () => mainHandlers['save-data'](null, 'tampered'), /Vault is locked/);
      await assert.rejects(async () => mainHandlers['save-touchid-key'](null, 'forged-key'), /Vault is locked/);
      await assert.rejects(
        async () => mainHandlers['save-recovery-pair'](null, { recovery: 'r', masterEnc: 'm' }),
        /Vault is locked/
      );
      await assert.rejects(async () => mainHandlers['save-recovery'](null, 'r'), /Vault is locked/);
      await assert.rejects(async () => mainHandlers['save-master-enc'](null, 'm'), /Vault is locked/);
      await assert.rejects(
        async () => mainHandlers['register-chrome-ext-id'](null, { extensionId: 'a'.repeat(32) }),
        /Vault is locked/
      );
      const fakeBackup = await mainHandlers['encrypt'](null, { data: { hello: 1 }, password: 'BackupPassword1!' });
      await assert.rejects(
        async () => mainHandlers['decrypt-backup'](null, { b64: fakeBackup, password: 'BackupPassword1!' }),
        /Vault is locked/
      );
    });

    await runTest('1.3 Decrypting arbitrary ciphertext does NOT unlock or reset lockout; concurrent decrypts serialize cleanly', async () => {
      const onDiskEnc = await mainHandlers['load-data']();
      const decoyEnc = await mainHandlers['encrypt'](null, { data: { decoy: true }, password: 'DecoyPassword!1' });

      // Fire 2 concurrent wrong-password attempts against on-disk vault; mutex must serialize so 2nd sees lockout
      const results = await Promise.allSettled([
        mainHandlers['decrypt'](null, { b64: onDiskEnc, password: 'WrongPassword1!' }),
        mainHandlers['decrypt'](null, { b64: onDiskEnc, password: 'WrongPassword2!' })
      ]);
      assert.strictEqual(results[0].status, 'rejected');
      assert.strictEqual(results[1].status, 'rejected');
      assert.ok(
        results[1].reason.message.includes('Too many attempts'),
        `2nd concurrent decrypt should hit serialized lockout, got: ${results[1].reason.message}`
      );

      // Expire the lockout window manually in fuin.lockout? Wait: delay for count=1 is 2000ms. Wait 2.1s.
      await new Promise((r) => setTimeout(r, 2150));

      // Now decrypt arbitrary decoy ciphertext with known password — MUST NOT reset lockout.count or unlock!
      const decoyOut = await mainHandlers['decrypt'](null, { b64: decoyEnc, password: 'DecoyPassword!1' });
      assert.strictEqual(decoyOut.decoy, true);

      // Vault must STILL be locked!
      await assert.rejects(async () => mainHandlers['save-touchid-key'](null, 'x'), /Vault is locked/);

      // Lockout counter must NOT have been reset to 0 by decoy decrypt
      const lockoutRaw = JSON.parse(fs.readFileSync(path.join(userDataDir, 'fuin.lockout'), 'utf8'));
      const lockoutData = JSON.parse(lockoutRaw.data);
      assert.strictEqual(lockoutData.count, 1, 'Arbitrary ciphertext decrypt MUST NOT reset lockout counter');

      // Real on-disk DATA_FILE decrypt unlocks authoritatively and resets lockout counter to 0
      const realOut = await mainHandlers['decrypt'](null, { b64: onDiskEnc, password: realPw });
      assert.strictEqual(realOut.type, 'fuin/vault');

      const lockoutAfter = JSON.parse(JSON.parse(fs.readFileSync(path.join(userDataDir, 'fuin.lockout'), 'utf8')).data);
      assert.strictEqual(lockoutAfter.count, 0, 'Authoritative on-disk DATA_FILE decrypt must reset lockout counter');

      // Mutating IPCs now succeed
      assert.strictEqual(await mainHandlers['save-touchid-key'](null, realPw), true);
      assert.strictEqual(
        await mainHandlers['save-recovery-pair'](null, { recovery: 'valid-rec', masterEnc: 'valid-master' }),
        true
      );
    });

    await runTest('1.4 decrypt-backup enforces lockout increment on failure when unlocked', async () => {
      const backupCipher = await mainHandlers['encrypt'](null, { data: { b: 1 }, password: 'GoodBackupPw!1' });
      await assert.rejects(
        () => mainHandlers['decrypt-backup'](null, { b64: backupCipher, password: 'BadBackupPw!1' })
      );
      // Immediately following attempt must be rejected by lockout backoff
      await assert.rejects(
        () => mainHandlers['decrypt-backup'](null, { b64: backupCipher, password: 'GoodBackupPw!1' }),
        /Too many attempts/
      );
    });

    // ── 2. UPD-01 & UPD-02: Private Updates Dir, Fail-Closed SHA-256 & Re-Verify ─
    console.log('\n[2. UPD-01 & UPD-02: Private Updates Dir, Fail-Closed SHA-256 & Install Re-Verify]');
    const updEnv = loadIsolatedMain(path.join(tmpRoot, 'updater'));
    const mockEvent = { sender: { send: () => {} } };

    await runTest('2.1 download-update writes to private userData/updates (never temp/fuin-updates) with 0o700/0o600', async () => {
      const bytes = Buffer.from('FUIN-OFFICIAL-UPDATER-PAYLOAD');
      const sha = crypto.createHash('sha256').update(bytes).digest('hex');
      global.fetch = async () =>
        makeMockResponse({
          url: 'https://objects.githubusercontent.com/Fuin-1.0.0.dmg',
          chunks: [bytes],
          headers: { 'content-length': bytes.length }
        });

      const res = await updEnv.mainHandlers['download-update'](mockEvent, {
        url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-1.0.0.dmg',
        filename: 'Fuin-1.0.0.dmg',
        expectedSha256: sha
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.verified, true);
      assert.ok(res.filePath.startsWith(path.join(updEnv.userDataDir, 'updates') + path.sep));
      assert.strictEqual(fs.existsSync(path.join(updEnv.tempDir, 'fuin-updates')), false, 'Must NOT use temp/fuin-updates');
      if (process.platform !== 'win32') {
        assert.strictEqual(fs.lstatSync(path.join(updEnv.userDataDir, 'updates')).mode & 0o777, 0o700);
        assert.strictEqual(fs.lstatSync(res.filePath).mode & 0o777, 0o600);
      }

      // install-update succeeds when unmodified
      updEnv.openedPaths.length = 0;
      assert.strictEqual(await updEnv.mainHandlers['install-update'](mockEvent, { filePath: res.filePath }), true);
      assert.strictEqual(updEnv.openedPaths.length, 1);

      // Tampering on disk before install-update MUST fail re-verification
      fs.writeFileSync(res.filePath, Buffer.from('TAMPERED-AFTER-DOWNLOAD'));
      updEnv.openedPaths.length = 0;
      await assert.rejects(
        () => updEnv.mainHandlers['install-update'](mockEvent, { filePath: res.filePath }),
        /SHA-256 integrity verification failed before install/
      );
      assert.strictEqual(updEnv.openedPaths.length, 0);
    });

    await runTest('2.2 download-update fails CLOSED when SHA-256 is missing; updateManager requires verified===true', async () => {
      const res = await updEnv.mainHandlers['download-update'](mockEvent, {
        url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-NoHash.dmg',
        filename: 'Fuin-NoHash.dmg'
      });
      assert.strictEqual(res.success, false);
      assert.strictEqual(res.verified, false);
      assert.strictEqual(res.error, 'sha256-missing');
      assert.strictEqual(fs.existsSync(path.join(updEnv.userDataDir, 'updates', 'Fuin-NoHash.dmg')), false);

      const updateMgrSrc = fs.readFileSync(path.join(__dirname, 'renderer', 'modules', 'updateManager.js'), 'utf8');
      assert.ok(updateMgrSrc.includes('res.verified === true'), 'updateManager.js must require res.verified === true');
    });

    // ── 3. SYNC-01: Strict Canonical RFC1918 & IPv6 Validation ───────────────
    console.log('\n[3. SYNC-01: Strict Canonical IPv4/IPv6 Guard]');

    await runTest('3.1 isRFC1918OrLoopback blocks octal, hex, userinfo, and loose IPv6 prefix SSRF tricks', () => {
      const malicious = [
        '010.8.8.8',
        '0177.0.0.1',
        '192.168.001.1',
        '10.00.0.1',
        '0x7f.0.0.1',
        '127.1',
        'fc:x@attacker.example',
        'fe80:x@attacker.example',
        'fd00:1@evil.com',
        'fc00:not-an-ip',
        'fe80:foo',
        '192.168.1.1@evil.com',
        '192.168.1.1:8765',
        '::ffff:8.8.8.8',
        '::ffff:010.8.8.8',
        '8.8.8.8',
        '2001:db8::1',
        '192.168.1.1?foo=bar'
      ];
      for (const ip of malicious) {
        assert.strictEqual(syncLan.isRFC1918OrLoopback(ip), false, `Must reject SSRF vector: ${ip}`);
      }

      const valid = [
        '127.0.0.1',
        '10.0.0.1',
        '172.16.0.1',
        '172.31.255.254',
        '192.168.0.10',
        '169.254.1.1',
        '::1',
        '::ffff:192.168.1.10',
        'fe80::1ff:fe23:4567:890a',
        'fc00::1',
        'fd12:3456:789a:1::1'
      ];
      for (const ip of valid) {
        assert.strictEqual(syncLan.isRFC1918OrLoopback(ip), true, `Must accept valid LAN IP: ${ip}`);
      }
    });

    // ── 4. SYNC-02 & SYNC-03: Pairing Isolation, Revocation & Memory-Only ────
    console.log('\n[4. SYNC-02 & SYNC-03: Pairing Proof Hardening, Shadow-Clone Revocation & Memory-Only Pending]');

    await runTest('4.1 /pair rejects pairedDevices key fallback, missing action/direction/deviceId, and expired pending keys', async () => {
      const dir = path.join(tmpRoot, 'sync02');
      fs.mkdirSync(dir, { recursive: true });
      // Plant a stale legacy fuin.pending-pairings.json -> PairingManager constructor must delete it
      const stalePendingPath = path.join(dir, 'fuin.pending-pairings.json');
      fs.writeFileSync(stalePendingPath, '[{"pairKeyHex":"deadbeef"}]');

      const pm = new syncLan.PairingManager(dir);
      assert.strictEqual(fs.existsSync(stalePendingPath), false, 'Stale fuin.pending-pairings.json must be deleted on init');

      const existingKey = crypto.randomBytes(32);
      pm.addPairedDevice({
        deviceId: 'legit-phone',
        deviceName: 'Legit Phone',
        pairKeyHex: existingKey.toString('hex')
      });

      const server = new syncLan.EphemeralServer({ pairingManager: pm, getVaultEntries: () => [] });
      const { port } = await server.start({ port: 0 });

      // Attack A: /sync -> /pair substitution using an existing pairedDevices key MUST return 401
      const subProof = syncLan.encryptLanPayload({
        action: 'pair',
        direction: 'request',
        deviceId: 'shadow-clone',
        deviceName: 'Shadow',
        timestamp: Date.now()
      }, existingKey);
      const subRes = await sendHttpPost(port, '/pair', { deviceId: 'shadow-clone', ...subProof });
      assert.strictEqual(subRes.status, 401, '/pair must NOT fall back to pairedDevices');
      assert.strictEqual(pm.isDevicePaired('shadow-clone'), false);

      // Attack B: Missing direction or wrong action under valid pending key MUST return 400
      const qr = pm.generatePairingData({ port });
      const pendingKeyBuf = Buffer.from(qr.pairKey, 'hex');
      const noDirProof = syncLan.encryptLanPayload({
        action: 'pair',
        deviceId: 'phone-nodir',
        timestamp: Date.now()
      }, pendingKeyBuf);
      const noDirRes = await sendHttpPost(port, '/pair', { deviceId: 'phone-nodir', ...noDirProof });
      assert.strictEqual(noDirRes.status, 400, '/pair must require direction === request');

      // Attack C: Missing inner decryptedProof.deviceId (even when outer body.deviceId is set) MUST return 400
      const noInnerIdProof = syncLan.encryptLanPayload({
        action: 'pair',
        direction: 'request',
        timestamp: Date.now()
      }, pendingKeyBuf);
      const noInnerIdRes = await sendHttpPost(port, '/pair', { deviceId: 'outer-spoofed-id', ...noInnerIdProof });
      assert.strictEqual(noInnerIdRes.status, 400, '/pair must never fall back to unauthenticated outer body.deviceId');

      // Attack D: Pending pairing expired (> 120s) MUST return 401
      pm.pendingPairings.get(qr.pairKey).createdAt = Date.now() - (syncLan.EPHEMERAL_TIMEOUT_MS + 5000);
      const expiredProof = syncLan.encryptLanPayload({
        action: 'pair',
        direction: 'request',
        deviceId: 'phone-expired',
        timestamp: Date.now()
      }, pendingKeyBuf);
      const expiredRes = await sendHttpPost(port, '/pair', { deviceId: 'phone-expired', ...expiredProof });
      assert.strictEqual(expiredRes.status, 401, 'Expired pendingPairing (>120s) must be rejected');

      // Stopping server clears memory-only pendingPairings
      pm.generatePairingData({ port });
      assert.strictEqual(pm.pendingPairings.size, 1);
      await server.stop('test-stop');
      assert.strictEqual(pm.pendingPairings.size, 0, 'EphemeralServer.stop() must clear pendingPairings');
      assert.strictEqual(fs.existsSync(stalePendingPath), false, 'pendingPairings must NEVER be persisted to disk');
    });

    await runTest('4.2 removePairedDevice deletes ALL shadow records sharing the revoked pairKeyHex', () => {
      const dir = path.join(tmpRoot, 'sync02-revoke');
      fs.mkdirSync(dir, { recursive: true });
      const pm = new syncLan.PairingManager(dir);
      const sharedKeyHex = crypto.randomBytes(32).toString('hex');
      const otherKeyHex = crypto.randomBytes(32).toString('hex');

      pm.addPairedDevice({ deviceId: 'phone-orig', deviceName: 'Orig', pairKeyHex: sharedKeyHex });
      pm.addPairedDevice({ deviceId: 'phone-shadow', deviceName: 'Shadow', pairKeyHex: sharedKeyHex });
      pm.addPairedDevice({ deviceId: 'phone-other', deviceName: 'Other', pairKeyHex: otherKeyHex });

      assert.strictEqual(pm.removePairedDevice('phone-orig'), true);
      assert.strictEqual(pm.isDevicePaired('phone-orig'), false);
      assert.strictEqual(pm.isDevicePaired('phone-shadow'), false, 'Shadow clone sharing pairKeyHex must also be revoked');
      assert.strictEqual(pm.isDevicePaired('phone-other'), true, 'Unrelated device must remain paired');
    });

    // ── 5. SYNC-05: HTTP Boundary, Browser/CORS/Host Guards & Concurrency Cap ─
    console.log('\n[5. SYNC-05: EphemeralServer HTTP Boundary & Concurrency Hardening]');

    await runTest('5.1 Server sets connection/timeout limits and rejects Origin, Sec-Fetch-Site, bad Host, non-JSON Content-Type, and >2 concurrent body reads', async () => {
      const dir = path.join(tmpRoot, 'sync05');
      fs.mkdirSync(dir, { recursive: true });
      const pm = new syncLan.PairingManager(dir);
      const phoneKey = crypto.randomBytes(32);
      pm.addPairedDevice({ deviceId: 'known-phone', deviceName: 'Phone', pairKeyHex: phoneKey.toString('hex') });

      const server = new syncLan.EphemeralServer({ pairingManager: pm, getVaultEntries: () => [] });
      const { port } = await server.start({ port: 0 });

      try {
        assert.strictEqual(server.server.maxConnections, 8);
        assert.strictEqual(server.server.headersTimeout, 10000);
        assert.strictEqual(server.server.requestTimeout, 30000);

        // Origin header -> 403
        const originRes = await sendHttpPost(port, '/sync', {}, { Origin: 'https://evil.example' });
        assert.strictEqual(originRes.status, 403, 'Origin header must be rejected with 403');

        // Sec-Fetch-Site header -> 403
        const sfsRes = await sendHttpPost(port, '/sync', {}, { 'Sec-Fetch-Site': 'cross-site' });
        assert.strictEqual(sfsRes.status, 403, 'Sec-Fetch-Site header must be rejected with 403');

        // Bad Host header (DNS rebinding) -> 403
        const hostRes = await sendHttpPost(port, '/sync', {}, { Host: 'rebind.attacker.example:8765' });
        assert.strictEqual(hostRes.status, 403, 'Non-local Host header must be rejected with 403');

        // Non-JSON Content-Type -> 415
        const ctRes = await sendHttpPost(port, '/sync', 'plain=1', { 'Content-Type': 'text/plain' });
        assert.strictEqual(ctRes.status, 415, 'Non-application/json Content-Type must be rejected with 415');

        // Unified 401 oracle check: unknown device vs known device with wrong key MUST both return 401
        const badEnc = syncLan.encryptLanPayload({ entries: [] }, crypto.randomBytes(32));
        const unknownRes = await sendHttpPost(port, '/sync', { deviceId: 'does-not-exist', ...badEnc });
        const knownWrongKeyRes = await sendHttpPost(port, '/sync', { deviceId: 'known-phone', ...badEnc });
        assert.strictEqual(unknownRes.status, 401);
        assert.strictEqual(knownWrongKeyRes.status, 401);

        // Concurrent body-read cap: open 2 stalled POST bodies, 3rd must immediately get 429
        const stalledReqs = [];
        for (let i = 0; i < 2; i++) {
          const req = http.request({
            hostname: '127.0.0.1',
            port,
            path: '/sync',
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Content-Length': 1024
            }
          });
          req.on('error', () => {});
          req.write('{'); // send partial body so server holds in-flight body read open
          stalledReqs.push(req);
        }
        await new Promise((r) => setTimeout(r, 60));

        const capRes = await sendHttpPost(port, '/sync', { deviceId: 'x', nonce: 'aa', ciphertext: 'bb' });
        assert.strictEqual(capRes.status, 429, '3rd concurrent body read must be rejected with 429');

        for (const req of stalledReqs) {
          try { req.destroy(); } catch {}
        }
      } finally {
        await server.stop('test-done');
      }
    });

    // ── 6. SYNC-07: Dedicated Random Fallback Key & Migration ────────────────
    console.log('\n[6. SYNC-07: Dedicated 0o600 Random Fallback Key & Legacy Migration]');

    await runTest('6.1 PairingManager uses dedicated 0o600 random fuin.pairing.key and migrates legacy v1 store', () => {
      const dir = path.join(tmpRoot, 'sync07');
      fs.mkdirSync(dir, { recursive: true });

      const pm1 = new syncLan.PairingManager(dir);
      const pairKeyHex = crypto.randomBytes(32).toString('hex');
      pm1.addPairedDevice({ deviceId: 'dev-v2', deviceName: 'V2 Device', pairKeyHex });

      const keyPath = path.join(dir, 'fuin.pairing.key');
      assert.ok(fs.existsSync(keyPath), 'Dedicated fuin.pairing.key must be created');
      if (process.platform !== 'win32') {
        assert.strictEqual(fs.lstatSync(keyPath).mode & 0o777, 0o600, 'fuin.pairing.key must be mode 0o600');
      }
      const storedEnvelope = JSON.parse(fs.readFileSync(path.join(dir, 'fuin.paired-devices.json'), 'utf8'));
      assert.strictEqual(storedEnvelope.localEncrypted, true);
      assert.strictEqual(storedEnvelope.keyVersion, 2);

      // Verify legacy device-id-derived key CANNOT decrypt v2 envelope
      const legacyKey = pm1._deriveLegacyDeviceIdFallbackKey();
      assert.throws(() => pm1._decryptLocalEnvelope(storedEnvelope, legacyKey));
      legacyKey.fill(0);

      // Verify backward-compatible migration from legacy v1 envelope -> v2
      const migDir = path.join(tmpRoot, 'sync07-mig');
      fs.mkdirSync(migDir, { recursive: true });
      const legacyDevId = 'fuin-desktop-legacy1234';
      fs.writeFileSync(path.join(migDir, 'fuin.device-id'), legacyDevId, { mode: 0o600 });
      const oldKey = crypto.scryptSync(legacyDevId, 'FUIN_LOCAL_PAIRING_STORE_V1', 32);
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', oldKey, iv);
      const legacyRecords = [{ deviceId: 'legacy-phone', deviceName: 'Old Phone', pairKeyHex, pairedAt: Date.now(), lastSyncAt: null }];
      const enc = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(legacyRecords), 'utf8')), cipher.final()]);
      const tag = cipher.getAuthTag();
      oldKey.fill(0);
      fs.writeFileSync(
        path.join(migDir, 'fuin.paired-devices.json'),
        JSON.stringify({ localEncrypted: true, iv: iv.toString('base64'), tag: tag.toString('base64'), payload: enc.toString('base64') }),
        { mode: 0o600 }
      );

      const pmMigrated = new syncLan.PairingManager(migDir);
      assert.strictEqual(pmMigrated.isDevicePaired('legacy-phone'), true, 'Legacy v1 store must load cleanly');
      const migratedEnv = JSON.parse(fs.readFileSync(path.join(migDir, 'fuin.paired-devices.json'), 'utf8'));
      assert.strictEqual(migratedEnv.keyVersion, 2, 'Legacy v1 store must auto-migrate to keyVersion 2');
    });

    // ── 7. CRYPTO-01: Sync & Importer Sanitization ───────────────────────────
    console.log('\n[7. CRYPTO-01: Entry site Coercion & cardBrand Allowlist Sanitization]');

    await runTest('7.1 sync-lan normalizeEntry & mergeVaultEntries coerce non-string site and sanitize cardBrand', () => {
      const n1 = syncLan.normalizeEntry({
        id: 'c1',
        type: 'card',
        site: { notAString: true },
        cardBrand: '<button data-action="perm-del-pw">DEL</button>'
      });
      assert.strictEqual(n1.site, '', 'Non-string site must be coerced to empty string');
      assert.strictEqual(n1.cardBrand, '', 'Malicious HTML cardBrand must be stripped');

      const n2 = syncLan.normalizeEntry({
        id: 'c2',
        type: 'card',
        site: 'My Card',
        cardBrand: 'Mastercard'
      });
      assert.strictEqual(n2.site, 'My Card');
      assert.strictEqual(n2.cardBrand, 'Mastercard');
    });

    await runTest('7.2 jsonImporter sanitizes HTML/XSS cardBrand in both Bitwarden and Fuin JSON imports', () => {
      const evilBw = JSON.stringify({
        encrypted: false,
        items: [
          {
            type: 3,
            name: 'Corp Card',
            card: {
              cardholderName: 'Alice',
              number: '4111111111111111',
              brand: '<img src=x onerror=alert(1)>'
            }
          },
          {
            type: 3,
            name: 'Good Card',
            card: {
              cardholderName: 'Bob',
              number: '5500000000000004',
              brand: 'Visa'
            }
          }
        ]
      });
      const bwRes = jsonImporter.importJSON(evilBw);
      assert.strictEqual(bwRes.entries.length, 2);
      assert.strictEqual(bwRes.entries[0].cardBrand, undefined, 'Malicious Bitwarden cardBrand must be stripped');
      assert.strictEqual(bwRes.entries[1].cardBrand, 'Visa', 'Allowlisted Bitwarden cardBrand must be preserved');

      const evilFuin = JSON.stringify({
        type: 'fuin/vault',
        entries: [
          {
            type: 'card',
            site: 'Bank Card',
            cardholderName: 'Eve',
            cardNumber: '9792000000000001',
            cardBrand: '<BUTTON DATA-ACTION="PERM-DEL-PW">X</BUTTON>'
          },
          {
            type: 'card',
            site: 'Troy Card',
            cardholderName: 'Ali',
            cardNumber: '9792000000000002',
            cardBrand: 'troy'
          }
        ]
      });
      const fuinRes = jsonImporter.importJSON(evilFuin);
      assert.strictEqual(fuinRes.entries.length, 2);
      assert.strictEqual(fuinRes.entries[0].cardBrand, undefined, 'Malicious Fuin cardBrand must be stripped');
      assert.strictEqual(fuinRes.entries[1].cardBrand, 'Troy', 'Allowlisted Fuin cardBrand must normalize cleanly');
    });
  } finally {
    global.fetch = origFetch;
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch {}
  }

  console.log(`\nDesktop Core Security Audit Suite: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
