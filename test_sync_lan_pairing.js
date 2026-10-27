'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST SUITE: test_sync_lan_pairing.js
 *
 * Verifies Acceptance Criteria:
 *   1. Statik QR'dan 32-bayt CSPRNG pairKey ve pairing payload üretimi (R1)
 *   2. Eşleşme (pairing) kaydı, persistansı ve tek tıkla iptal (revocation) (R1)
 *   3. Yetkisiz anahtar, bilinmeyen cihaz ve tahrif edilmiş paketlerin reddi (R2)
 *   4. Ephemeral yerel ağ soketi yaşam döngüsü:
 *      - Arka planda açık dinleyici bulunmaması
 *      - RFC1918 arayüz kontrolü (dış IP'lerin engellenmesi)
 *      - İşlem bittiğinde derhal kapanması
 *      - set-unlock-state(false) ve kasa kilitlenmesi durumunda derhal kapanması
 *      - 120 saniyelik zaman aşımı koruması
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');
const http   = require('http');

const syncLan = require('./sync-lan.js');
const syncCrypto = require('./sync-v2-crypto.js');

console.log('═'.repeat(75));
console.log('FUIN TEST: LAN PAIRING & EPHEMERAL TRANSPORT SECURITY');
console.log('═'.repeat(75));

let passes = 0;
let failures = 0;

function test(desc, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✕ [FAIL] ${desc}`);
    console.error(`         ${err.message}`);
    failures++;
  }
}

async function asyncTest(desc, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✕ [FAIL] ${desc}`);
    console.error(`         ${err.message}`);
    failures++;
  }
}

async function runAll() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-lan-test-'));

  const Module = require('module');
  const mainHandlers = {};
  const mockPowerMonitor = { on: () => {}, getSystemIdleTime: () => 0 };
  const mockMainWindow = {
    webContents: { send: () => {} },
    on: () => {},
    setContentProtection: () => {},
    loadFile: () => {},
    show: () => {},
    hide: () => {},
    isVisible: () => true
  };
  const origReq = Module.prototype.require;
  Module.prototype.require = function(id) {
    if (id === 'electron') {
      return {
        app: { getPath: () => tmpDir, isPackaged: false, quit: () => {}, whenReady: () => Promise.resolve(), on: () => {} },
        session: { defaultSession: { webRequest: { onHeadersReceived: () => {} } } },
        BrowserWindow: class { constructor() { return mockMainWindow; } },
        ipcMain: { handle: (ch, fn) => { mainHandlers[ch] = fn; }, on: () => {} },
        dialog: {}, clipboard: { writeText: () => {} }, powerMonitor: mockPowerMonitor, shell: {}, Tray: class { setToolTip(){} popUpContextMenu(){} setContextMenu(){} on(){} }, Menu: { buildFromTemplate: () => ({}) }, nativeImage: { createFromPath: () => ({ resize: () => ({}) }) }, systemPreferences: {}, safeStorage: {}
      };
    }
    return origReq.apply(this, arguments);
  };
  const mainMod = require('./main.js');

  // ── TEST 1: STATIC QR PAIRING PAYLOAD GENERATION (R1) ──────────────────────
  test('A. Statik QR payload gerekli tüm alanları içerir', () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const pairing = pm.generatePairingData({ port: 8765 });

    assert.strictEqual(pairing.protocol, 'fuin-lan-v1');
    assert.strictEqual(pairing.type, 'pairing');
    assert.ok(typeof pairing.deviceId === 'string' && pairing.deviceId.length > 0, 'deviceId string olmalı');
    assert.ok(typeof pairing.pairKey === 'string' && /^[0-9a-f]{64}$/.test(pairing.pairKey), 'pairKey tam 64 hex karakter (32 bytes) olmalı');
    assert.strictEqual(pairing.port, 8765);
    assert.ok(Array.isArray(pairing.addresses) && pairing.addresses.length > 0, 'addresses en az bir IP içermeli');

    const keyBuf = Buffer.from(pairing.pairKey, 'hex');
    assert.strictEqual(keyBuf.length, 32, 'pairKey tam 32 bayt CSPRNG olmalı');
  });

  test('B. Her pairing çağrısı benzersiz CSPRNG pairKey üretir', () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const p1 = pm.generatePairingData();
    const p2 = pm.generatePairingData();

    assert.notStrictEqual(p1.pairKey, p2.pairKey, 'Her pairKey birbirinden farklı olmalı');
    assert.strictEqual(p1.deviceId, p2.deviceId, 'Masaüstü deviceId kararlı (stable) olmalı');
  });

  // ── TEST 2: PAIRING REGISTRATION, STORAGE & REVOCATION (R1) ────────────────
  test('C. Cihaz eşleştirme, kalıcı kayıt ve tek tıkla iptal (revocation)', () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const mockMobileId = 'mobile-device-xyz';
    const mockPairKeyHex = crypto.randomBytes(32).toString('hex');

    // Başlangıçta eşleşmiş cihaz yok
    assert.strictEqual(pm.isDevicePaired(mockMobileId), false);
    assert.strictEqual(pm.getDeviceKey(mockMobileId), null);

    // Cihazı ekle
    pm.addPairedDevice({
      deviceId: mockMobileId,
      deviceName: 'iPhone 15 Pro',
      pairKeyHex: mockPairKeyHex
    });

    assert.strictEqual(pm.isDevicePaired(mockMobileId), true);
    const retrievedKey = pm.getDeviceKey(mockMobileId);
    assert.ok(Buffer.isBuffer(retrievedKey));
    assert.strictEqual(retrievedKey.toString('hex'), mockPairKeyHex);

    // UI listesi hassas anahtarı gizlemeli (maskelemeli)
    const devices = pm.getPairedDevices();
    assert.strictEqual(devices.length, 1);
    assert.strictEqual(devices[0].deviceId, mockMobileId);
    assert.strictEqual(devices[0].deviceName, 'iPhone 15 Pro');
    assert.ok(devices[0].keyPreview.includes('...'), 'Anahtar masked olmalı');
    assert.strictEqual(devices[0].pairKeyHex, undefined, 'Ham anahtar UI listesinde sızdırılmamalı');

    // Disk persistansı doğrulama (yeni instance ile okuma)
    const pm2 = new syncLan.PairingManager(tmpDir);
    assert.strictEqual(pm2.isDevicePaired(mockMobileId), true);
    assert.strictEqual(pm2.getDeviceKey(mockMobileId).toString('hex'), mockPairKeyHex);

    // Tek tıkla iptal (Revocation)
    const revoked = pm2.removePairedDevice(mockMobileId);
    assert.strictEqual(revoked, true);
    assert.strictEqual(pm2.isDevicePaired(mockMobileId), false);
    assert.strictEqual(pm2.getDeviceKey(mockMobileId), null);

    // Diske de iptalin yansıdığını doğrula
    const pm3 = new syncLan.PairingManager(tmpDir);
    assert.strictEqual(pm3.isDevicePaired(mockMobileId), false);
    assert.strictEqual(pm3.getPairedDevices().length, 0);
  });

  // ── TEST 3: RFC1918 INTERFACE FILTERING (R2) ──────────────────────────────
  test('D. RFC1918 ve yerel ağ filtreleme mantığı', () => {
    // Geçerli yerel ağ adresleri
    assert.strictEqual(syncLan.isRFC1918OrLoopback('127.0.0.1'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('10.0.0.1'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('10.254.12.34'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('172.16.0.5'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('172.31.255.254'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('192.168.1.100'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('169.254.1.1'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('::1'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('::ffff:192.168.1.5'), true);

    // İnternet / genel IP adresleri (ENGELENMELİ)
    assert.strictEqual(syncLan.isRFC1918OrLoopback('8.8.8.8'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('1.1.1.1'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('172.15.0.1'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('172.32.0.1'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('93.184.216.34'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('invalid-ip'), false);
  });

  // ── TEST 4: CRYPTO PACKET FRAMING & UNAUTHORIZED REJECTION (R2) ───────────
  test('E. XChaCha20-Poly1305 LAN şifreleme ve yetkisiz anahtar reddi', () => {
    const validKey = crypto.randomBytes(32);
    const attackerKey = crypto.randomBytes(32);
    const payload = { test: 'secret_vault_data', timestamp: Date.now() };

    // Şifrele
    const encPacket = syncLan.encryptLanPayload(payload, validKey);
    assert.ok(typeof encPacket.nonce === 'string');
    assert.ok(typeof encPacket.ciphertext === 'string');

    // Doğru anahtarla çöz
    const decrypted = syncLan.decryptLanPayload(encPacket, validKey);
    assert.deepStrictEqual(decrypted, payload);

    // Yanlış anahtar ile çözme (REDDEDİLMELİ)
    assert.throws(() => {
      syncLan.decryptLanPayload(encPacket, attackerKey);
    }, /SYNC_V2_AUTH_FAILED|Sifre cozme basarisiz/);

    // Tahrif edilmiş ciphertext (REDDEDİLMELİ)
    const tampered = { ...encPacket };
    const rawCipher = Buffer.from(tampered.ciphertext, 'hex');
    rawCipher[0] ^= 0x01; // flip 1 bit
    tampered.ciphertext = rawCipher.toString('hex');

    assert.throws(() => {
      syncLan.decryptLanPayload(tampered, validKey);
    }, /SYNC_V2_AUTH_FAILED|Sifre cozme basarisiz/);

    // Tahrif edilmiş nonce (REDDEDİLMELİ)
    const tamperedNonce = { ...encPacket };
    const rawNonce = Buffer.from(tamperedNonce.nonce, 'hex');
    rawNonce[0] ^= 0x01;
    tamperedNonce.nonce = rawNonce.toString('hex');

    assert.throws(() => {
      syncLan.decryptLanPayload(tamperedNonce, validKey);
    }, /SYNC_V2_AUTH_FAILED|Sifre cozme basarisiz/);
  });

  // ── TEST 5: EPHEMERAL SERVER LIFECYCLE & TWO-WAY INTEGRATION (R2) ──────────
  await asyncTest('F. Ephemeral Server: Başlatma, yetkilendirme, veri aktarımı ve anında kapanma', async () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const mobileId = 'mobile-test-123';
    const pairKey = crypto.randomBytes(32);

    pm.addPairedDevice({
      deviceId: mobileId,
      deviceName: 'Test Phone',
      pairKeyHex: pairKey.toString('hex')
    });

    let vaultEntries = [
      { id: '1', site: 'github.com', username: 'desktop_user', password: 'desktop_pw', updatedAt: 100 }
    ];

    let appliedEntries = null;
    let closedReason = null;

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => vaultEntries,
      applyMergedEntries: (merged) => {
        appliedEntries = merged;
      }
    });

    server.onClosed((reason) => {
      closedReason = reason;
    });

    // Başlangıçta kapalı olmalı
    assert.strictEqual(server.isListening(), false);

    // 0 portu ile başlat (dinamik boş port)
    const sInfo = await server.start({ port: 0, timeoutMs: 120000 });
    assert.strictEqual(server.isListening(), true);
    const assignedPort = server.getPort();
    assert.ok(assignedPort > 0);

    // Case 1: Eşleşmemiş cihaz isteği (401 Reddedilmeli)
    const rogueResponse = await makePostRequest(assignedPort, '/sync', {
      deviceId: 'unknown-rogue-device',
      nonce: crypto.randomBytes(24).toString('hex'),
      ciphertext: crypto.randomBytes(32).toString('hex')
    });
    assert.strictEqual(rogueResponse.status, 401, 'Eşleşmemiş cihaz 401 Unauthorized dönmeli');

    // Case 2: Bilinen cihaz ama yanlış şifreli veri (403 Reddedilmeli)
    const fakeKey = crypto.randomBytes(32);
    const fakeEnc = syncLan.encryptLanPayload({ entries: [] }, fakeKey);
    const authFailResponse = await makePostRequest(assignedPort, '/sync', {
      deviceId: mobileId,
      nonce: fakeEnc.nonce,
      ciphertext: fakeEnc.ciphertext
    });
    assert.strictEqual(authFailResponse.status, 403, 'Yanlış anahtarlı istek 403 Forbidden dönmeli');

    // Case 3: Geçerli istek (Başarılı senkronizasyon ve iki yönlü birleştirme)
    const mobileEntries = [
      { id: '2', site: 'gitlab.com', username: 'mobile_user', password: 'mobile_pw', updatedAt: 150 }
    ];
    const validEnc = syncLan.encryptLanPayload({ entries: mobileEntries }, pairKey);

    const successResponse = await makePostRequest(assignedPort, '/sync', {
      deviceId: mobileId,
      nonce: validEnc.nonce,
      ciphertext: validEnc.ciphertext
    });

    assert.strictEqual(successResponse.status, 200);
    assert.strictEqual(successResponse.data.success, true);

    // Yanıtın da pairKey ile şifreli olduğunu ve çözülebildiğini doğrula
    const decryptedReply = syncLan.decryptLanPayload({
      nonce: successResponse.data.nonce,
      ciphertext: successResponse.data.ciphertext
    }, pairKey);

    assert.strictEqual(decryptedReply.protocol, 'fuin-lan-v1');
    assert.strictEqual(decryptedReply.entries.length, 2, 'İki taraflı kayıtlar birleştirilmiş olmalı');

    // Masaüstü vault güncellendi mi?
    assert.ok(appliedEntries, 'applyMergedEntries çağrılmış olmalı');
    assert.strictEqual(appliedEntries.length, 2);

    // Kural: "işlem tamamlandığında veya kasa kilitlendiğinde derhal kapatılmalıdır" (R2)
    // Yanıt tamamlandıktan sonra soket otomatik kapanmış olmalıdır!
    await new Promise(r => setTimeout(r, 50));
    assert.strictEqual(server.isListening(), false, 'İşlem bittiğinde dinleyici derhal kapanmalıdır');
    assert.strictEqual(closedReason, 'completed');
  });

  // ── TEST 6: LOCK & UNLOCK-STATE VAULT SHUTDOWN (R2 AC) ─────────────────────
  await asyncTest('G. Kasa kilitlendiğinde veya set-unlock-state(false) olunca soket derhal kapatılır', async () => {
    const pm = new syncLan.PairingManager(tmpDir);
    let closedReason = null;

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => []
    });

    server.onClosed((reason) => {
      closedReason = reason;
    });

    // Dinleyiciyi başlat
    await server.start({ port: 0 });
    assert.strictEqual(server.isListening(), true);

    // Kilitlenme simülasyonu: stop('vault-locked')
    await server.stop('vault-locked');

    assert.strictEqual(server.isListening(), false, 'Kilitlenmede soket derhal kapatılmalıdır');
    assert.strictEqual(closedReason, 'vault-locked');
  });

  // ── TEST 7: 120-SECOND AUTO TIMEOUT EXPIRY (R2) ───────────────────────────
  await asyncTest('H. Dinleyici 120 saniyelik ömrünü aşamaz ve zaman aşımında kapanır', async () => {
    const pm = new syncLan.PairingManager(tmpDir);
    let closedReason = null;

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => []
    });

    server.onClosed((reason) => {
      closedReason = reason;
    });

    // Test için kısa süre (50ms) ver
    await server.start({ port: 0, timeoutMs: 50 });
    assert.strictEqual(server.isListening(), true);

    await new Promise(r => setTimeout(r, 80));

    assert.strictEqual(server.isListening(), false, 'Zaman aşımında soket otomatik kapanmalıdır');
    assert.strictEqual(closedReason, 'timeout');
  });

  // ── TEST 8: REAL MAIN.JS IPC INTEGRATION & LOCK SHUTDOWN ──────────────────
  await asyncTest('I. main.js IPC: set-unlock-state(false) kilitlenmesinde soketin kapanması doğrulaması', async () => {
    assert.ok(mainHandlers['set-unlock-state'], 'set-unlock-state IPC kayıtlı olmalı');
    assert.ok(mainHandlers['lan-start-sync'], 'lan-start-sync IPC kayıtlı olmalı');
    assert.ok(mainHandlers['lan-set-sync-mode'], 'lan-set-sync-mode IPC kayıtlı olmalı');

    // 1. Kilit açık yap
    await mainHandlers['set-unlock-state'](null, true);

    // 2. LAN moduna al
    await mainHandlers['lan-set-sync-mode'](null, 'lan');

    // 3. Ephemeral server başlat
    const syncRes = await mainHandlers['lan-start-sync'](null, { entries: [] });
    assert.ok(syncRes.port > 0, 'Port atanmış olmalı');

    const ephemeralServer = mainMod.getEphemeralLanServer();
    assert.strictEqual(ephemeralServer.isListening(), true, 'Sunucu dinlemede olmalı');

    // 4. Kilit kapat (set-unlock-state false) -> Sunucu anında kapanmalı!
    await mainHandlers['set-unlock-state'](null, false);
    assert.strictEqual(ephemeralServer.isListening(), false, 'Kilit kapandığında ephemeral sunucu derhal kapanmalıdır (R2)');

    // 5. Kasa kilitliyken sync başlatma reddedilmeli
    await assert.rejects(async () => {
      await mainHandlers['lan-start-sync'](null, { entries: [] });
    }, /SYNC_LAN: Vault is locked/);
  });

  // ── TEST 9: AIR-GAP SETTINGS TOGGLE (R4) ───────────────────────────────────
  await asyncTest('J. Ayarlardan Air-Gap seçildiğinde ağ devre dışı kalır ve open-sync-window hazırdır', async () => {
    // 1. Kilit aç
    await mainHandlers['set-unlock-state'](null, true);

    // 2. Sync modunu Air-Gap'e geçir
    await mainHandlers['lan-set-sync-mode'](null, 'airgap');
    assert.strictEqual(await mainHandlers['lan-get-sync-mode'](), 'airgap');

    // 3. Air-Gap modundayken LAN sync başlatma reddedilmeli (R4: Ağ modülleri tamamen devre dışı)
    await assert.rejects(async () => {
      await mainHandlers['lan-start-sync'](null, { entries: [] });
    }, /Air-Gap mode is active/);

    // 4. open-sync-window IPC handler'ının var olduğu ve kilit açıkken erişilebilir olduğu doğrulanır
    assert.ok(mainHandlers['open-sync-window'], 'open-sync-window handler korunmalı');

    // 5. Tekrar LAN moduna geçiş
    await mainHandlers['lan-set-sync-mode'](null, 'lan');
    assert.strictEqual(await mainHandlers['lan-get-sync-mode'](), 'lan');
  });

  // ── TEST 10: PENDING PAIRING DISK PERSISTENCE ACROSS RESTARTS (R1) ──────────
  test('K. Pending pairing persistansı ve masaüstü yeniden başlatılmasında korunması', () => {
    const pm1 = new syncLan.PairingManager(tmpDir);
    const pData = pm1.generatePairingData();
    assert.ok(pm1.pendingPairings.has(pData.pairKey));

    // Masaüstü uygulamasının kapatılıp yeniden açılması simülasyonu
    const pmRestarted = new syncLan.PairingManager(tmpDir);
    assert.ok(pmRestarted.pendingPairings.has(pData.pairKey), 'Pending pairing diskten geri yüklenmeli');
    const key = pmRestarted.getDeviceKey(pData.pairKey);
    assert.ok(Buffer.isBuffer(key));
    assert.strictEqual(key.toString('hex'), pData.pairKey);
  });

  // ── TEST 11: END-TO-END QR OPTICAL PAIRING & AUTO-FINALIZATION (R1, R2) ────
  await asyncTest('L. Gerçek optik eşleşme akışı: QR okuma -> ilk sync ile kesinleşme -> ayarlar listesi -> iptal', async () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const pairingQr = pm.generatePairingData();
    const pairKeyBuf = Buffer.from(pairingQr.pairKey, 'hex');

    // Başlangıçta henüz teyitli eşleşmiş cihaz yok
    const initialPaired = pm.getPairedDevices();
    const initialCount = initialPaired.length;

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => [{ id: '1', site: 'example.com', username: 'admin', password: 'pw', updatedAt: 100 }],
      applyMergedEntries: () => {}
    });

    await server.start({ port: 0 });
    const port = server.getPort();

    // Mobil QR okudu ve ilk sync isteğini gönderiyor (pendingPairKey ile)
    const mobilePayload = { entries: [{ id: '2', site: 'mobile.com', username: 'm', password: 'pw', updatedAt: 200 }] };
    const enc = syncLan.encryptLanPayload(mobilePayload, pairKeyBuf);

    const syncRes = await makePostRequest(port, '/sync', {
      deviceId: pairingQr.deviceId,
      deviceName: 'Pixel 8',
      pendingPairKey: pairingQr.pairKey,
      nonce: enc.nonce,
      ciphertext: enc.ciphertext
    });

    assert.strictEqual(syncRes.status, 200);
    assert.strictEqual(syncRes.data.success, true);

    // Eşleşme otomatik olarak kesinleşti ve ayarlardaki listeye eklendi mi?
    const afterDevices = pm.getPairedDevices();
    assert.strictEqual(afterDevices.length, initialCount + 1, 'Cihaz pairedDevices listesine eklenmeli');
    assert.strictEqual(afterDevices[afterDevices.length - 1].deviceName, 'Pixel 8');

    // Şimdi cihazı masaüstü ayarlarından iptal et (Revocation)
    const revoked = pm.removePairedDevice(pairingQr.deviceId);
    assert.strictEqual(revoked, true);

    // Sunucuyu tekrar başlatıp iptal edilmiş cihazın isteğini sına
    await server.start({ port: 0 });
    const newPort = server.getPort();

    const secondSyncRes = await makePostRequest(newPort, '/sync', {
      deviceId: pairingQr.deviceId,
      pendingPairKey: pairingQr.pairKey,
      nonce: enc.nonce,
      ciphertext: enc.ciphertext
    });

    // İptal edildiği için 401 ile anında reddedilmeli
    assert.strictEqual(secondSyncRes.status, 401, 'İptal edilen cihaz reddedilmeli');
    await server.stop();
  });

  // ── TEST 12: MULTIPLE DEVICES INDEPENDENT PAIRING & REVOCATION (R1) ────────
  await asyncTest('M. Çoklu mobil cihaz eşleşmesi: İki telefonun bağımsız eşleşmesi, birlikte listelenmesi ve tek tek iptali', async () => {
    const pm = new syncLan.PairingManager(tmpDir);

    // Telefon 1 (iPhone 15) için QR üret
    const qr1 = pm.generatePairingData();
    const key1 = Buffer.from(qr1.pairKey, 'hex');

    // Telefon 2 (Pixel 8) için QR üret
    const qr2 = pm.generatePairingData();
    const key2 = Buffer.from(qr2.pairKey, 'hex');

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => [{ id: '1', site: 'shared.com', username: 'u', password: 'p', updatedAt: 100 }],
      applyMergedEntries: () => {}
    });

    // 1. Telefon 1 senkronize eder ve eşleşir
    await server.start({ port: 0 });
    const p1 = server.getPort();

    const enc1 = syncLan.encryptLanPayload({ entries: [] }, key1);
    const res1 = await makePostRequest(p1, '/sync', {
      deviceId: qr1.deviceId,
      mobileDeviceId: 'phone-iphone-15',
      deviceName: 'iPhone 15 Pro',
      pendingPairKey: qr1.pairKey,
      nonce: enc1.nonce,
      ciphertext: enc1.ciphertext
    });
    assert.strictEqual(res1.status, 200);

    // 2. Telefon 2 senkronize eder ve eşleşir
    await server.start({ port: 0 });
    const p2 = server.getPort();

    const enc2 = syncLan.encryptLanPayload({ entries: [] }, key2);
    const res2 = await makePostRequest(p2, '/sync', {
      deviceId: qr2.deviceId,
      mobileDeviceId: 'phone-pixel-8',
      deviceName: 'Google Pixel 8',
      pendingPairKey: qr2.pairKey,
      nonce: enc2.nonce,
      ciphertext: enc2.ciphertext
    });
    assert.strictEqual(res2.status, 200);

    // 3. Ayarlar ekranında her iki telefon da listelenmeli (üst üste binmemeli)
    const devices = pm.getPairedDevices();
    const iphone = devices.find(d => d.deviceId === 'phone-iphone-15');
    const pixel = devices.find(d => d.deviceId === 'phone-pixel-8');

    assert.ok(iphone, 'iPhone 15 Pro kayıtlı olmalı');
    assert.ok(pixel, 'Pixel 8 kayıtlı olmalı');
    assert.strictEqual(iphone.deviceName, 'iPhone 15 Pro');
    assert.strictEqual(pixel.deviceName, 'Google Pixel 8');

    // 4. Sadece iPhone'u iptal et
    const revoked = pm.removePairedDevice('phone-iphone-15');
    assert.strictEqual(revoked, true);

    // 5. Pixel 8 halen eşleşmiş olmalı
    assert.strictEqual(pm.isDevicePaired('phone-pixel-8'), true);
    assert.strictEqual(pm.isDevicePaired('phone-iphone-15'), false);

    // 6. Pixel 8 hala başarıyla bağlanabilmeli
    await server.start({ port: 0 });
    const p3 = server.getPort();
    const encPixel = syncLan.encryptLanPayload({ entries: [] }, key2);
    const resPixel = await makePostRequest(p3, '/sync', {
      deviceId: qr2.deviceId,
      mobileDeviceId: 'phone-pixel-8',
      nonce: encPixel.nonce,
      ciphertext: encPixel.ciphertext
    });
    assert.strictEqual(resPixel.status, 200, 'Pixel 8 eşleşmesi korunmalı ve bağlanabilmeli');

    // 7. iPhone 15 ise 401 ile reddedilmeli
    await server.start({ port: 0 });
    const p4 = server.getPort();
    const encIphone = syncLan.encryptLanPayload({ entries: [] }, key1);
    const resIphone = await makePostRequest(p4, '/sync', {
      deviceId: qr1.deviceId,
      mobileDeviceId: 'phone-iphone-15',
      nonce: encIphone.nonce,
      ciphertext: encIphone.ciphertext
    });
    assert.strictEqual(resIphone.status, 401, 'İptal edilen iPhone reddedilmeli');
    await server.stop();
  });

  // ── TEST 13: IPV6 LOCAL FILTERING (R2) ──────────────────────────────────────
  test('N. IPv6 yerel ağ (fe80:: link-local, fc00::/fd00:: unique-local) kontrolü', () => {
    // Yerel IPv6 kabul edilmeli
    assert.strictEqual(syncLan.isRFC1918OrLoopback('fe80::1ff:fe23:4567:890a'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('fd12:3456:789a:1::1'), true);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('fc00::1'), true);

    // Genel internet IPv6 engellenmeli
    assert.strictEqual(syncLan.isRFC1918OrLoopback('2001:0db8:85a3:0000:0000:8a2e:0370:7334'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('2607:f8b0:4005:805::200e'), false);
  });

  // ── TEST 14: DIRECT /pair HTTP ENDPOINT & onDevicePaired CALLBACK (R1) ─────
  await asyncTest('O. Doğrudan /pair HTTP uç noktası ve onDevicePaired geri çağrımı', async () => {
    const pm = new syncLan.PairingManager(tmpDir);
    const qrPayload = pm.generatePairingData();
    let pairedEventData = null;

    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      onDevicePaired: (device) => {
        pairedEventData = device;
      }
    });

    await server.start({ port: 0 });
    const port = server.getPort();

    // 1. Düz metin (legacy) pairKeyHex artık güvenlik gereği 400 ile reddedilmeli
    const legacyRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-test-legacy',
      deviceName: 'Legacy Phone',
      pairKeyHex: qrPayload.pairKey
    });
    assert.strictEqual(legacyRes.status, 400, 'Düz metin pairKeyHex reddedilmeli');

    // 2. Yetkisiz AEAD anahtarı ile /pair (401 Reddedilmeli)
    const rogueProof = syncLan.encryptLanPayload({ action: 'pair', deviceId: 'mobile-test-rogue', timestamp: Date.now() }, crypto.randomBytes(32));
    const rogueRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-test-rogue',
      deviceName: 'Rogue Phone',
      ...rogueProof
    });
    assert.strictEqual(rogueRes.status, 401, 'Yetkisiz AEAD kanıtı 401 dönmeli');

    // 3. Eksik alanlar ile /pair (400 Reddedilmeli)
    const malformedRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-test'
    });
    assert.strictEqual(malformedRes.status, 400, 'Eksik alan 400 dönmeli');

    // 4. Geçerli AEAD kanıtı ile /pair (200 Başarılı + imzalı pair-ack)
    const validProof = syncLan.encryptLanPayload({
      action: 'pair',
      direction: 'request',
      deviceId: 'mobile-galaxy-s24',
      deviceName: 'Samsung S24',
      timestamp: Date.now()
    }, Buffer.from(qrPayload.pairKey, 'hex'));
    const validRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-galaxy-s24',
      deviceName: 'Samsung S24',
      ...validProof
    });
    assert.strictEqual(validRes.status, 200, 'Geçerli AEAD pairing 200 dönmeli');
    assert.strictEqual(validRes.data.success, true);
    assert.strictEqual(validRes.data.desktopDeviceId, pm.getDesktopDeviceId());
    assert.ok(validRes.data.nonce && validRes.data.ciphertext, 'İmzalı pair-ack dönmeli');

    // 4. Device pm kayıtlarına eklenmiş ve onDevicePaired tetiklenmiş olmalı
    assert.strictEqual(pm.isDevicePaired('mobile-galaxy-s24'), true);
    assert.ok(pairedEventData);
    assert.strictEqual(pairedEventData.deviceId, 'mobile-galaxy-s24');
    assert.strictEqual(pairedEventData.deviceName, 'Samsung S24');

    await server.stop();
  });

  // ── TEST 15: IPC lan-generate-pairing-qr GUARDS (R1, R4) ────────────────────
  await asyncTest('P. lan-generate-pairing-qr IPC kilit ve Air-Gap koruma kontrolleri', async () => {
    // 1. Kasa kilitliyken pairing QR üretimi reddedilmeli
    await mainHandlers['set-unlock-state'](null, false);
    await assert.rejects(async () => {
      await mainHandlers['lan-generate-pairing-qr'](null);
    }, /SYNC_LAN: Vault is locked/);

    // 2. Kilit aç
    await mainHandlers['set-unlock-state'](null, true);

    // 3. Air-Gap modundayken pairing QR üretimi reddedilmeli
    await mainHandlers['lan-set-sync-mode'](null, 'airgap');
    await assert.rejects(async () => {
      await mainHandlers['lan-generate-pairing-qr'](null);
    }, /Air-Gap mode is active/);

    // 4. LAN modunda başarılı üretim
    await mainHandlers['lan-set-sync-mode'](null, 'lan');
    const qrData = await mainHandlers['lan-generate-pairing-qr'](null, { port: 9999 });
    assert.strictEqual(qrData.port, 9999);
    assert.strictEqual(qrData.protocol, 'fuin-lan-v1');
    assert.ok(qrData.pairKey);
  });

  // ── TEST 16: STRICT RFC1918 PARSING & PORT REJECTION (R2) ──────────────────
  test('Q. isRFC1918OrLoopback porta sahip veya geçersiz formatlı IP\'leri engeller', () => {
    assert.strictEqual(syncLan.isRFC1918OrLoopback('127.0.0.1:8765'), false, 'Port içeren IP reddedilmeli');
    assert.strictEqual(syncLan.isRFC1918OrLoopback('192.168.1.1:80'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('10.0.0.1abc'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('192.168.1'), false);
    assert.strictEqual(syncLan.isRFC1918OrLoopback('192.168.1.1.1'), false);
  });

  // ── TEST 17: AEAD-ENCRYPTED /pair HANDSHAKE & NONCE REPLAY PROTECTION ───────
  await asyncTest('R. Şifreli (AEAD) /pair el sıkışması (düz metin pairKey olmadan) ve Nonce Replay engellemesi', async () => {
    const pm = new syncLan.PairingManager(path.join(tmpDir, 'enc-pair-test'));
    const qrPayload = pm.generatePairingData({ port: 0 });
    const pairKeyBuf = Buffer.from(qrPayload.pairKey, 'hex');

    let pairedCallbackFired = false;
    const server = new syncLan.EphemeralServer({
      pairingManager: pm,
      getVaultEntries: () => [],
      applyMergedEntries: () => {},
      onDevicePaired: () => { pairedCallbackFired = true; }
    });

    const { port } = await server.start({ port: 0 });

    // 1. Yanlış anahtarla şifrelenmiş /pair kanıtı reddedilmeli (401)
    const wrongKey = crypto.randomBytes(32);
    const wrongProof = syncLan.encryptLanPayload({
      action: 'pair',
      deviceId: 'mobile-attacker',
      deviceName: 'Attacker',
      timestamp: Date.now()
    }, wrongKey);
    const wrongRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-attacker',
      deviceName: 'Attacker',
      nonce: wrongProof.nonce,
      ciphertext: wrongProof.ciphertext
    });
    assert.strictEqual(wrongRes.status, 401, 'Yanlış AEAD kanıtı 401 dönmeli');

    // 2. Doğru anahtarla şifrelenmiş /pair kanıtı (HTTP gövdesinde pairKeyHex YOK) kabul edilmeli (200)
    const validProof = syncLan.encryptLanPayload({
      action: 'pair',
      deviceId: 'mobile-secure-1',
      deviceName: 'Secure Phone',
      timestamp: Date.now()
    }, pairKeyBuf);
    const validRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-secure-1',
      deviceName: 'Secure Phone',
      nonce: validProof.nonce,
      ciphertext: validProof.ciphertext
    });
    assert.strictEqual(validRes.status, 200, 'Şifreli /pair kanıtı 200 dönmeli');
    assert.strictEqual(pm.isDevicePaired('mobile-secure-1'), true);
    assert.strictEqual(pairedCallbackFired, true);

    // 3. Aynı /pair paketinin tekrar gönderilmesi (Replay) reddedilmeli (400)
    const replayRes = await makePostRequest(port, '/pair', {
      deviceId: 'mobile-secure-1',
      deviceName: 'Secure Phone',
      nonce: validProof.nonce,
      ciphertext: validProof.ciphertext
    });
    assert.strictEqual(replayRes.status, 400, 'Aynı nonce ile replay edilen paket 400 ile reddedilmeli');

    await server.stop();
  });

  // Cleanup tmpDir
  try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}

  console.log('═'.repeat(75));
  console.log(`SONUÇ: ${passes} BAŞARILI, ${failures} BAŞARISIZ`);
  console.log('═'.repeat(75));

  if (failures > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

function makePostRequest(port, urlPath, payload) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(payload);
    const req = http.request({
      hostname: '127.0.0.1',
      port: port,
      path: urlPath,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        let parsed = null;
        try { parsed = JSON.parse(body); } catch {}
        resolve({
          status: res.statusCode,
          headers: res.headers,
          data: parsed || body
        });
      });
    });

    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

runAll().catch(e => {
  console.error('Fatal test error:', e);
  process.exit(1);
});
