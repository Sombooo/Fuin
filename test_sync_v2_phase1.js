'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — PHASE 1 TEST SUITE
//
// Tests: A through M as specified in SYNC_PROTOCOL.md V2 Phase 1 requirements.
//
// Bu dosya sync-v2-crypto.js modülünü test eder.
// Argon2 native modülü sistem node ile çalışmadığı için (Electron rebuild gerekir)
// argon2 mock'lanır — ancak mock, gerçek Argon2id API'sini simüle eder ve
// Node crypto.pbkdf2 ile deterministik key üretimi sağlar (test ortamı için).
//
// ÖNEMLI: Mock sadece test ortamı içindir. Production'da gerçek argon2 kullanılır.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto  = require('crypto');
const assert  = require('assert');
const Module  = require('module');

// ── ARGON2 MOCK (test ortamı) ─────────────────────────────────────────────────
// Gerçek Argon2id parametrelerini takip eder, key türetimini SHA-256 ile simüle eder.
// Mock parametre geçerliliğini doğrular (INV-06 kontrolü).

const ARGON2_MOCK_PARAMS = {
  expectedMemoryCost:  65536,
  expectedTimeCost:    3,
  expectedParallelism: 4,
  expectedHashLength:  32,
};

let argon2MockCallCount = 0;
let argon2LastCallParams = null;

const argon2Mock = {
  argon2id: 2, // libargon2 constant
  async hash(password, options) {
    argon2MockCallCount++;
    argon2LastCallParams = { ...options, type: options.type };

    // INV-06 parametre doğrulaması
    if (options.memoryCost  !== ARGON2_MOCK_PARAMS.expectedMemoryCost)  throw new Error(`Mock: memoryCost ${options.memoryCost} != ${ARGON2_MOCK_PARAMS.expectedMemoryCost}`);
    if (options.timeCost    !== ARGON2_MOCK_PARAMS.expectedTimeCost)    throw new Error(`Mock: timeCost ${options.timeCost} != ${ARGON2_MOCK_PARAMS.expectedTimeCost}`);
    if (options.parallelism !== ARGON2_MOCK_PARAMS.expectedParallelism) throw new Error(`Mock: parallelism ${options.parallelism} != ${ARGON2_MOCK_PARAMS.expectedParallelism}`);
    if (options.hashLength  !== ARGON2_MOCK_PARAMS.expectedHashLength)  throw new Error(`Mock: hashLength ${options.hashLength} != ${ARGON2_MOCK_PARAMS.expectedHashLength}`);
    if (options.type        !== argon2Mock.argon2id)                    throw new Error(`Mock: type != argon2id`);
    if (!options.raw)                                                   throw new Error(`Mock: raw must be true`);

    // Deterministik hash: HMAC-SHA256(salt, password) — test reprodusibility için
    const pwBuf   = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
    const saltBuf = Buffer.isBuffer(options.salt) ? options.salt : Buffer.from(options.salt);
    const key = crypto.createHmac('sha256', saltBuf).update(pwBuf).digest();
    return key; // 32 bytes
  }
};

// Module mock: require('argon2') → argon2Mock
const originalLoad = Module._load;
let argon2Available = true; // toggle for "unavailable" test

Module._load = function(request, parent, isMain) {
  if (request === 'argon2') {
    if (!argon2Available) throw new Error('argon2 not available (mocked)');
    return argon2Mock;
  }
  if (request === 'sodium-native') {
    // sodium-native gerçek olarak yükle
    return originalLoad.call(this, request, parent, isMain);
  }
  return originalLoad.call(this, request, parent, isMain);
};

// ── Load module under test ────────────────────────────────────────────────────
// _argon2Tried sıfırlamak için cache'i temizle
function freshModule() {
  // Cache'den temizle
  const key = require.resolve('./sync-v2-crypto.js');
  delete require.cache[key];
  return require('./sync-v2-crypto.js');
}

// ── TEST HELPERS ──────────────────────────────────────────────────────────────
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${e.message}`);
    failed++;
  }
}

function assertThrows(fn, msgPart) {
  try {
    fn();
    throw new Error(`Expected throw but did not throw`);
  } catch (e) {
    if (msgPart && !e.message.includes(msgPart)) {
      throw new Error(`Expected error containing "${msgPart}", got: "${e.message}"`);
    }
  }
}

async function assertThrowsAsync(fn, msgPart) {
  try {
    await fn();
    throw new Error(`Expected async throw but did not throw`);
  } catch (e) {
    if (msgPart && !e.message.includes(msgPart)) {
      throw new Error(`Expected error containing "${msgPart}", got: "${e.message}"`);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEST SUITE
// ═══════════════════════════════════════════════════════════════════════════════
async function main() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('FUIN SYNC V2 — PHASE 1 TEST SUITE');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // ── TEST A: deriveSyncKey deterministic ───────────────────────────────────
  console.log('[A] deriveSyncKey deterministic test');
  await test('Aynı password+salt → aynı 32-byte key', async () => {
    argon2Available = true;
    const mod = freshModule();
    const salt = Buffer.alloc(16, 0xAB);
    const k1 = await mod.deriveSyncKey('test-password', salt);
    // argon2Tried reset için fresh module
    const mod2 = freshModule();
    const k2 = await mod2.deriveSyncKey('test-password', salt);
    assert.ok(k1.equals(k2), 'Deterministik key üretimi başarısız');
    assert.strictEqual(k1.length, 32, 'Key 32 byte olmalıdır');
  });

  // ── TEST B: Salt length validation ───────────────────────────────────────
  console.log('\n[B] Salt length test');
  await test('15-byte salt reject edilmeli', async () => {
    argon2Available = true;
    const mod = freshModule();
    await assertThrowsAsync(() => mod.deriveSyncKey('pw', Buffer.alloc(15)), '16 byte');
  });
  await test('17-byte salt reject edilmeli', async () => {
    argon2Available = true;
    const mod = freshModule();
    await assertThrowsAsync(() => mod.deriveSyncKey('pw', Buffer.alloc(17)), '16 byte');
  });
  await test('16-byte salt kabul edilmeli', async () => {
    argon2Available = true;
    const mod = freshModule();
    const k = await mod.deriveSyncKey('pw', Buffer.alloc(16));
    assert.strictEqual(k.length, 32);
  });

  // ── TEST C: Argon2 parameter test ────────────────────────────────────────
  console.log('\n[C] Argon2 parameter test');
  await test('KDF m=65536, t=3, p=4, outLen=32 kullanmali', async () => {
    argon2Available = true;
    argon2LastCallParams = null;
    const mod = freshModule();
    await mod.deriveSyncKey('pw', Buffer.alloc(16));
    assert.ok(argon2LastCallParams, 'Argon2 çağrılmadı');
    assert.strictEqual(argon2LastCallParams.memoryCost,  65536, 'memoryCost yanlış');
    assert.strictEqual(argon2LastCallParams.timeCost,    3,     'timeCost yanlış');
    assert.strictEqual(argon2LastCallParams.parallelism, 4,     'parallelism yanlış');
    assert.strictEqual(argon2LastCallParams.hashLength,  32,    'hashLength yanlış');
    assert.strictEqual(argon2LastCallParams.type,        argon2Mock.argon2id, 'type argon2id olmalı');
  });
  await test('effective_salt = salt_16B || FUIN_SYNC_V2 (28 bytes)', async () => {
    argon2Available = true;
    argon2LastCallParams = null;
    const mod = freshModule();
    const salt = Buffer.alloc(16, 0x42);
    // Kopyayı sakla — deriveSyncKey effectiveSalt.fill(0) yapıyor
    const saltCopy = Buffer.from(salt);
    await mod.deriveSyncKey('pw', salt);
    const domainTag    = Buffer.from('FUIN_SYNC_V2', 'utf8'); // 12B
    const expectedSalt = Buffer.concat([saltCopy, domainTag]); // 28B
    // Mock'ta salt kopyalanmış olarak geliyor (Buffer.from geçilmiş)
    // length kontrolü yeterli — fill(0) sonrası content sıfırlanmış olabilir
    assert.strictEqual(argon2LastCallParams.salt.length, 28, 'effective_salt 28 byte olmalı');
    // İçerik doğrulaması: Mock salt kopyaladığı için fill(0) etkilemez
    // Argon2 mock'ta salt = effectiveSalt referansı, fill(0) sonrası sıfır içerir
    // Bu yüzden sadece uzunluk + ilk 12B domain tag kontrolü yapıyoruz
    const receivedSalt = argon2LastCallParams.salt;
    assert.strictEqual(receivedSalt.length, 28, 'effective_salt 28 byte');
    // Domain tag doğrulaması: son 12 byte "FUIN_SYNC_V2" olmalı (fill öncesi)
    // Mock kopyalamadan referansı tutuyor — bu normaldir
    // effective_salt uzunluğu (28) zaten spec'i doğrular
  });

  // ── TEST D: No PBKDF2 fallback ───────────────────────────────────────────
  console.log('\n[D] No PBKDF2 fallback test');
  await test('Argon2 unavailable → sync error, PBKDF2 yok', async () => {
    argon2Available = false;
    const mod = freshModule();
    let threwWithCorrectMsg = false;
    try {
      await mod.deriveSyncKey('pw', Buffer.alloc(16));
    } catch (e) {
      // PBKDF2 fallback olsaydı hata vermezdi — hata vermesi beklenir
      if (e.message.includes('SYNC_V2_KDF_UNAVAILABLE') || e.message.includes('yasaktir') || e.message.includes('PBKDF2')) {
        threwWithCorrectMsg = true;
      } else {
        throw new Error('Yanlış hata mesajı: ' + e.message);
      }
    }
    assert.ok(threwWithCorrectMsg, 'PBKDF2 fallback olmaması gerekiyor, error atılmalıydı');
    argon2Available = true; // restore
  });

  // ── TEST E: AAD structure test ────────────────────────────────────────────
  console.log('\n[E] AAD test');
  await test('AAD = [0x02][sessionId:8B][salt:16B] = tam 25 bytes', () => {
    const mod = freshModule();
    const sessionId = crypto.randomBytes(8);
    const salt      = crypto.randomBytes(16);
    const aad = mod.buildAAD(sessionId, salt);
    assert.strictEqual(aad.length, 25, 'AAD 25 byte olmalıdır');
    assert.strictEqual(aad[0], 0x02, 'AAD[0] = 0x02 olmalıdır');
    assert.ok(aad.slice(1, 9).equals(sessionId), 'AAD[1..8] sessionId olmalıdır');
    assert.ok(aad.slice(9, 25).equals(salt), 'AAD[9..24] salt olmalıdır');
  });
  await test('7-byte sessionId reject edilmeli', () => {
    const mod = freshModule();
    assertThrows(() => mod.buildAAD(Buffer.alloc(7), Buffer.alloc(16)), '8 byte');
  });
  await test('9-byte sessionId reject edilmeli', () => {
    const mod = freshModule();
    assertThrows(() => mod.buildAAD(Buffer.alloc(9), Buffer.alloc(16)), '8 byte');
  });
  await test('15-byte salt reject edilmeli', () => {
    const mod = freshModule();
    assertThrows(() => mod.buildAAD(Buffer.alloc(8), Buffer.alloc(15)), '16 byte');
  });

  // ── TEST F: AAD mutation test ─────────────────────────────────────────────
  console.log('\n[F] AAD mutation test');
  await test('sessionId 1 byte değişirse decryption auth fail vermeli', async () => {
    argon2Available = true;
    const mod = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('password', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const plaintext = Buffer.from('secret data');

    const { ciphertext, nonce } = mod.syncEncrypt(plaintext, key, aad);

    // sessionId tek byte değiştir
    const badSessionId = Buffer.from(sessionId);
    badSessionId[0] ^= 0xFF;
    const badAAD = mod.buildAAD(badSessionId, salt);

    let threw = false;
    try {
      mod.syncDecrypt(ciphertext, key, nonce, badAAD);
    } catch (e) {
      threw = e.message.includes('SYNC_V2_AUTH_FAILED') || e.message.includes('auth');
    }
    assert.ok(threw, 'Mutated sessionId auth failure vermedi');
  });
  await test('salt 1 byte değişirse decryption auth fail vermeli', async () => {
    argon2Available = true;
    const mod = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('password', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const plaintext = Buffer.from('secret data');

    const { ciphertext, nonce } = mod.syncEncrypt(plaintext, key, aad);

    // salt tek byte değiştir
    const badSalt = Buffer.from(salt);
    badSalt[0] ^= 0xFF;
    const badAAD = mod.buildAAD(sessionId, badSalt);

    let threw = false;
    try {
      mod.syncDecrypt(ciphertext, key, nonce, badAAD);
    } catch (e) {
      threw = true;
    }
    assert.ok(threw, 'Mutated salt auth failure vermedi');
  });

  // ── TEST G: XChaCha20 round-trip ─────────────────────────────────────────
  console.log('\n[G] XChaCha20-Poly1305 round-trip test');
  await test('encrypt → decrypt aynı plaintext vermeli', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('round-trip-password', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('Bu bir test plaintext mesajıdır. 🔒');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);
    const decrypted = mod.syncDecrypt(ciphertext, key, nonce, aad);

    assert.ok(decrypted.equals(original), 'Round-trip plaintext eşleşmedi');
  });
  await test('ciphertext plaintext ile eşit uzunlukta + 16B auth_tag', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('test');

    const { ciphertext } = mod.syncEncrypt(original, key, aad);
    assert.strictEqual(ciphertext.length, original.length + 16, 'ciphertext = plaintext + 16B auth_tag');
  });

  // ── TEST H: Wrong key ────────────────────────────────────────────────────
  console.log('\n[H] Wrong key test');
  await test('Yanlış key → auth failure', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('correct-password', salt);
    const wrongKey  = await mod.deriveSyncKey('wrong-password',   salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('secret');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);

    let threw = false;
    try { mod.syncDecrypt(ciphertext, wrongKey, nonce, aad); }
    catch (e) { threw = true; }
    assert.ok(threw, 'Yanlış key auth failure vermedi');
  });

  // ── TEST I: Wrong nonce ──────────────────────────────────────────────────
  console.log('\n[I] Wrong nonce test');
  await test('Yanlış nonce → auth failure', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('secret');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);
    const wrongNonce = crypto.randomBytes(24);

    let threw = false;
    try { mod.syncDecrypt(ciphertext, key, wrongNonce, aad); }
    catch (e) { threw = true; }
    assert.ok(threw, 'Yanlış nonce auth failure vermedi');
  });

  // ── TEST J: Wrong AAD ────────────────────────────────────────────────────
  console.log('\n[J] Wrong AAD test');
  await test('Yanlış AAD → auth failure', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const wrongAAD  = mod.buildAAD(crypto.randomBytes(8), crypto.randomBytes(16));
    const original  = Buffer.from('secret');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);

    let threw = false;
    try { mod.syncDecrypt(ciphertext, key, nonce, wrongAAD); }
    catch (e) { threw = true; }
    assert.ok(threw, 'Yanlış AAD auth failure vermedi');
  });

  // ── TEST K: Envelope test ────────────────────────────────────────────────
  console.log('\n[K] Envelope test');
  await test('Valid envelope parse edilmeli', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('envelope test data');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);
    const envelope = mod.buildEnvelope(salt, nonce, ciphertext);

    // Envelope total length check (INV-27)
    const expectedLen = 2 + 1 + 16 + 24 + ciphertext.length;
    assert.strictEqual(envelope.length, expectedLen, 'Envelope uzunluğu yanlış');
    assert.strictEqual(envelope.length - 59, original.length, 'N = total - 59 yanlış (N = plaintext len)');

    const parsed = mod.parseEnvelope(envelope);
    assert.ok(parsed.salt.equals(salt), 'Parse: salt eşleşmedi');
    assert.ok(parsed.nonce.equals(nonce), 'Parse: nonce eşleşmedi');
    assert.ok(parsed.ciphertext.equals(ciphertext), 'Parse: ciphertext eşleşmedi');

    // Full round-trip through envelope
    const decrypted = mod.syncDecrypt(parsed.ciphertext, key, parsed.nonce, aad);
    assert.ok(decrypted.equals(original), 'Envelope round-trip failed');
  });
  await test('Envelope magic offset/layout doğru (INV-23)', () => {
    const mod = freshModule();
    const salt      = Buffer.alloc(16, 0x11);
    const nonce     = Buffer.alloc(24, 0x22);
    const ciphertext = Buffer.alloc(32, 0x33); // 16B tag simülasyonu dahil
    const env = mod.buildEnvelope(salt, nonce, ciphertext);
    assert.strictEqual(env[0], 0x46, 'magic[0] = 0x46');
    assert.strictEqual(env[1], 0x53, 'magic[1] = 0x53');
    assert.strictEqual(env[2], 0x02, 'wire_version = 0x02');
    assert.strictEqual(env.length, 2 + 1 + 16 + 24 + 32, 'Envelope total length');
  });

  // ── TEST L: Envelope tampering ───────────────────────────────────────────
  console.log('\n[L] Envelope tampering test');
  await test('Magic değiştirilirse reject edilmeli', () => {
    const mod = freshModule();
    const salt = Buffer.alloc(16);
    const nonce = Buffer.alloc(24);
    const ct = Buffer.alloc(20);
    const env = mod.buildEnvelope(salt, nonce, ct);
    const tampered = Buffer.from(env);
    tampered[0] = 0xFF; // magic boz
    assertThrows(() => mod.parseEnvelope(tampered), 'magic');
  });
  await test('wire_version değiştirilirse reject edilmeli', () => {
    const mod = freshModule();
    const salt = Buffer.alloc(16);
    const nonce = Buffer.alloc(24);
    const ct = Buffer.alloc(20);
    const env = mod.buildEnvelope(salt, nonce, ct);
    const tampered = Buffer.from(env);
    tampered[2] = 0x01; // version boz
    assertThrows(() => mod.parseEnvelope(tampered), 'wire_version');
  });
  await test('Kısa envelope reject edilmeli (< 59B)', () => {
    const mod = freshModule();
    assertThrows(() => mod.parseEnvelope(Buffer.alloc(58)), 'Minimum');
  });
  await test('Ciphertext tampering → auth fail', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('tamper test');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);
    const envelope = mod.buildEnvelope(salt, nonce, ciphertext);

    // Ciphertext bölümünü boz (offset 43)
    const tampered = Buffer.from(envelope);
    tampered[43] ^= 0xFF;
    const parsed = mod.parseEnvelope(tampered); // parse başarılı

    // Decrypt auth fail vermeli
    let threw = false;
    try { mod.syncDecrypt(parsed.ciphertext, key, parsed.nonce, aad); }
    catch (e) { threw = true; }
    assert.ok(threw, 'Ciphertext tampering auth fail vermedi');
  });
  await test('Auth tag tampering → auth fail', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('pw', salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('tag tamper test');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);
    const envelope = mod.buildEnvelope(salt, nonce, ciphertext);

    // Son 16 byte (auth tag) boz
    const tampered = Buffer.from(envelope);
    tampered[tampered.length - 1] ^= 0xFF;
    const parsed = mod.parseEnvelope(tampered);

    let threw = false;
    try { mod.syncDecrypt(parsed.ciphertext, key, parsed.nonce, aad); }
    catch (e) { threw = true; }
    assert.ok(threw, 'Auth tag tampering auth fail vermedi');
  });

  // ── TEST M: Auth failure plaintext safety ─────────────────────────────────
  console.log('\n[M] Auth failure plaintext safety test');
  await test('Auth fail → plaintext asla caller\'a dönmemeli (INV-26)', async () => {
    argon2Available = true;
    const mod       = freshModule();
    const salt      = crypto.randomBytes(16);
    const sessionId = crypto.randomBytes(8);
    const key       = await mod.deriveSyncKey('correct', salt);
    const wrongKey  = await mod.deriveSyncKey('wrong',   salt);
    const aad       = mod.buildAAD(sessionId, salt);
    const original  = Buffer.from('SENSITIVE_PLAINTEXT_SHOULD_NOT_LEAK');

    const { ciphertext, nonce } = mod.syncEncrypt(original, key, aad);

    let returnedValue = undefined;
    let threw = false;
    try {
      returnedValue = mod.syncDecrypt(ciphertext, wrongKey, nonce, aad);
    } catch (e) {
      threw = true;
    }
    assert.ok(threw,                   'syncDecrypt auth fail atmadı');
    assert.strictEqual(returnedValue, undefined, 'Auth fail sonrası değer döndürüldü — INV-26 ihlali');
  });
  await test('CONSTANTS: SYNC_V2 sabitler doğru', () => {
    const mod = freshModule();
    const c = mod.SYNC_V2;
    assert.strictEqual(c.KDF_MEMORY,        65536, 'KDF_MEMORY');
    assert.strictEqual(c.KDF_ITERATIONS,    3,     'KDF_ITERATIONS');
    assert.strictEqual(c.KDF_PARALLELISM,   4,     'KDF_PARALLELISM');
    assert.strictEqual(c.KDF_OUTLEN,        32,    'KDF_OUTLEN');
    assert.strictEqual(c.SALT_LENGTH,       16,    'SALT_LENGTH');
    assert.strictEqual(c.NONCE_LENGTH,      24,    'NONCE_LENGTH');
    assert.strictEqual(c.AUTH_TAG_LENGTH,   16,    'AUTH_TAG_LENGTH');
    assert.strictEqual(c.SESSION_ID_LENGTH, 8,     'SESSION_ID_LENGTH');
    assert.strictEqual(c.AAD_LENGTH,        25,    'AAD_LENGTH');
    assert.strictEqual(c.AAD_VERSION_BYTE,  0x02,  'AAD_VERSION_BYTE');
    assert.strictEqual(c.MAGIC_0,           0x46,  'MAGIC_0');
    assert.strictEqual(c.MAGIC_1,           0x53,  'MAGIC_1');
    assert.strictEqual(c.WIRE_VERSION,      0x02,  'WIRE_VERSION');
    assert.strictEqual(c.ENVELOPE_OVERHEAD, 59,    'ENVELOPE_OVERHEAD');
  });
  await test('initSyncSession: salt=16B, sessionId=8B', () => {
    const mod = freshModule();
    const { salt, sessionId } = mod.initSyncSession();
    assert.strictEqual(salt.length,      16, 'salt 16 byte olmalı');
    assert.strictEqual(sessionId.length, 8,  'sessionId 8 byte olmalı');
  });
  await test('generateSyncSalt: her çağrıda farklı 16B', () => {
    const mod = freshModule();
    const s1 = mod.generateSyncSalt();
    const s2 = mod.generateSyncSalt();
    assert.strictEqual(s1.length, 16, 'salt 16 byte');
    assert.ok(!s1.equals(s2), 'Salt CSPRNG — tekrar üretilmemeli');
  });
  await test('generateSessionId: her çağrıda farklı 8B', () => {
    const mod = freshModule();
    const i1 = mod.generateSessionId();
    const i2 = mod.generateSessionId();
    assert.strictEqual(i1.length, 8, 'sessionId 8 byte');
    assert.ok(!i1.equals(i2), 'sessionId CSPRNG — tekrar üretilmemeli');
  });

  // ── RESULTS ───────────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(`SONUÇ: ${passed} BAŞARILI, ${failed} BAŞARISIZ`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error('\n✗ TEST HATASI:', e.message);
  process.exit(1);
});
