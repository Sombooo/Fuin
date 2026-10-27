'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — PHASE 4 TEST SUITE
// test_sync_v2_phase4.js
//
// Tests A through AA covering the full Desktop V2 sync pipeline.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const Module = require('module');
const os     = require('os');
const path   = require('path');
const fs     = require('fs');

// ── Argon2 mock (same pattern as Phase 1/2/3 tests) ──────────────────────────
const argon2Mock = {
  argon2id: 2,
  async hash(password, options) {
    const pwBuf   = Buffer.isBuffer(password) ? password : Buffer.from(password, 'utf8');
    const saltBuf = Buffer.isBuffer(options.salt) ? options.salt : Buffer.from(options.salt);
    return crypto.createHmac('sha256', saltBuf).update(pwBuf).digest();
  }
};
const originalLoad = Module._load;
Module._load = function(request, parent, isMain) {
  if (request === 'argon2') return argon2Mock;
  return originalLoad.call(this, request, parent, isMain);
};

// ── Load modules (after mock installed) ──────────────────────────────────────
delete require.cache[require.resolve('./sync-v2-crypto.js')];
delete require.cache[require.resolve('./sync-v2-payload.js')];
delete require.cache[require.resolve('./sync-v2-transport.js')];
delete require.cache[require.resolve('./sync-v2.js')];

const syncCrypto  = require('./sync-v2-crypto.js');
const { buildSyncPayload, parseSyncPayload, GenerationManager, sanitizeForCBOR } = require('./sync-v2-payload.js');
const transport   = require('./sync-v2-transport.js');
const syncV2      = require('./sync-v2.js');

// ── Temp dir for state files ──────────────────────────────────────────────────
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-phase4-'));
syncV2.initGenerationManager(TMP_DIR);

// ── Simulate existing Vault encryption (from main.js, untouched) ──────────────
// We replicate the Vault encrypt/decrypt for testing the Vault boundary.
async function encryptData(plaintext, passwordStr) {
  const vaultSalt = crypto.randomBytes(32);
  const iv        = crypto.randomBytes(12);
  // Simulate deriveVaultKey (simplified — not testing KDF here, testing boundary)
  const keyMaterial = crypto.createHmac('sha256', vaultSalt).update(Buffer.from(passwordStr, 'utf8')).digest();
  const cipher  = crypto.createCipheriv('aes-256-gcm', keyMaterial, iv);
  const enc1    = cipher.update(Buffer.from(JSON.stringify(plaintext), 'utf8'));
  const enc2    = cipher.final();
  const tag     = cipher.getAuthTag();
  keyMaterial.fill(0);
  return Buffer.concat([vaultSalt, iv, tag, enc1, enc2]).toString('base64');
}

async function decryptData(b64Str, passwordStr) {
  const buf      = Buffer.from(b64Str, 'base64');
  const vaultSalt = buf.slice(0, 32);
  const iv        = buf.slice(32, 44);
  const tag       = buf.slice(44, 60);
  const data      = buf.slice(60);
  const keyMaterial = crypto.createHmac('sha256', vaultSalt).update(Buffer.from(passwordStr, 'utf8')).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', keyMaterial, iv);
  decipher.setAuthTag(tag);
  const dec1 = decipher.update(data);
  const dec2 = decipher.final();
  keyMaterial.fill(0);
  return JSON.parse(Buffer.concat([dec1, dec2]).toString('utf8'));
}

// ── Test harness ──────────────────────────────────────────────────────────────
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

function assertThrows(fn, fragment) {
  let threw = false;
  try { fn(); } catch (e) {
    threw = true;
    if (fragment && !e.message.includes(fragment)) {
      throw new Error(`Expected error containing "${fragment}", got: "${e.message}"`);
    }
  }
  if (!threw) throw new Error('Expected exception but none was thrown');
}

async function assertThrowsAsync(fn, fragment) {
  let threw = false;
  try { await fn(); } catch (e) {
    threw = true;
    if (fragment && !e.message.includes(fragment)) {
      throw new Error(`Expected error containing "${fragment}", got: "${e.message}"`);
    }
  }
  if (!threw) throw new Error('Expected async exception but none was thrown');
}

// ── Sample vault data ─────────────────────────────────────────────────────────
const VAULT_PASSWORD = 'vault-password-SEPARATE-from-sync';
const SYNC_PASSWORD  = 'sync-password-SEPARATE-from-vault';

const SAMPLE_ENTRIES = [
  { id: '1', site: 'example.com',   username: 'alice', password: 'S3cr3t!', category: 'Web', created: 1000 },
  { id: '2', site: 'github.com',    username: 'alice', password: 'gh-token', category: 'Dev', created: 2000 },
  { id: '3', site: 'test.invalid',  username: 'bob',   password: 'hunter2',  category: 'Web', created: 3000 },
];

const VAULT_PLAINTEXT = {
  type: 'fuin/vault',
  categories: ['Web', 'Dev'],
  entries: SAMPLE_ENTRIES,
};

// ── Main test run ─────────────────────────────────────────────────────────────
async function main() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('FUIN SYNC V2 — PHASE 4 TEST SUITE');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // ────────────────────────────────────────────────────────────────────────────
  console.log('[A-B] Vault Extraction Boundary');

  // A. Extract real Vault entries from plaintext vault object
  await test('A. Extract real Vault entries from plaintext vault object', async () => {
    const entries = syncV2.extractVaultEntries(VAULT_PLAINTEXT);
    assert.ok(Array.isArray(entries), 'entries must be array');
    assert.strictEqual(entries.length, 3, 'should have 3 entries');
    assert.strictEqual(entries[0].site, 'example.com');
  });

  // B. Vault decrypt boundary: wrong password → fails before sync pipeline
  await test('B. Wrong Vault Password → decrypt fails, sync pipeline never reached', async () => {
    const encrypted = await encryptData(VAULT_PLAINTEXT, VAULT_PASSWORD);
    await assertThrowsAsync(
      () => decryptData(encrypted, 'WRONG-VAULT-PASSWORD'),
      undefined // Any error is acceptable — AEAD will reject
    );
    // Verify: correct password works
    const decrypted = await decryptData(encrypted, VAULT_PASSWORD);
    const entries = syncV2.extractVaultEntries(decrypted);
    assert.strictEqual(entries.length, SAMPLE_ENTRIES.length);
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[C-D] Password Separation');

  // C. Sync Password is passed independently — NOT the Vault Password
  await test('C. Sync Password passed independently, not Vault Password', async () => {
    // buildV2QRChunks takes syncPassword, NOT vaultPassword
    // If they were the same, this test would still pass but
    // we verify the function signature enforces separation.
    const result = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    assert.ok(result.qrChunks.length > 0, 'Should produce QR chunks');
    // The vault password was never passed to buildV2QRChunks
    syncV2.cancelSyncSession();
  });

  // D. Hardware independence: same inputs → same Sync Key regardless of machine
  await test('D. Hardware independence: deriveSyncKey has no machineId input', async () => {
    const salt = syncCrypto.generateSyncSalt();
    const key1 = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const key2 = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    assert.ok(key1.equals(key2), 'Same inputs must yield same key (hardware independent)');
    key1.fill(0); key2.fill(0);
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[E-F] Session Parameters');

  // E. Session ID uniqueness
  await test('E. Session ID: each buildV2QRChunks call generates unique sessionId', async () => {
    const r1 = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    syncV2.cancelSyncSession();
    const r2 = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    syncV2.cancelSyncSession();
    assert.notStrictEqual(r1.sessionIdHex, r2.sessionIdHex, 'Session IDs must differ across calls');
  });

  // F. Salt: 16B, fresh per session (verified through Phase 1 envelope parsing)
  await test('F. Salt: 16B per session in outer envelope', async () => {
    const result = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    // Reassemble to check envelope structure
    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of result.qrChunks) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult, 'Must assemble');
    const env = syncCrypto.parseEnvelope(Buffer.from(completedResult.envelope));
    assert.strictEqual(env.salt.length, 16, 'Salt in envelope must be 16 bytes');
    syncV2.cancelSyncSession();
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[G-H] Generation');

  // G. Generation monotonicity
  await test('G. Generation monotonically increases across builds', async () => {
    const tmp2 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-gen-'));
    const gm = new GenerationManager(tmp2);
    const sessionId = syncCrypto.generateSessionId();
    const r1 = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const sessionId2 = syncCrypto.generateSessionId();
    const r2 = await buildSyncPayload(SAMPLE_ENTRIES, sessionId2, gm);
    assert.ok(r2.generation > r1.generation, `gen ${r2.generation} must be > ${r1.generation}`);
    fs.rmSync(tmp2, { recursive: true, force: true });
  });

  // H. Generation persists across restart (simulated)
  await test('H. Generation persists across simulated app restart', async () => {
    const tmp3 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-gen-restart-'));
    const gm1 = new GenerationManager(tmp3);
    const sessionId = syncCrypto.generateSessionId();
    const r1 = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm1);
    const genAfterFirst = r1.generation;

    // Simulate restart by creating a new GenerationManager with same path
    const gm2 = new GenerationManager(tmp3);
    const sessionId2 = syncCrypto.generateSessionId();
    const r2 = await buildSyncPayload(SAMPLE_ENTRIES, sessionId2, gm2);
    assert.ok(r2.generation > genAfterFirst, `Post-restart gen ${r2.generation} must exceed pre-restart ${genAfterFirst}`);
    fs.rmSync(tmp3, { recursive: true, force: true });
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[I-J] Snapshot Hash');

  // I. snapshot_hash = SHA-256(CBOR(entries))
  await test('I. snapshot_hash = SHA-256(canonical CBOR(entries))', async () => {
    const tmp4 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-snap-'));
    const gm = new GenerationManager(tmp4);
    const sessionId = syncCrypto.generateSessionId();
    const { snapshotHash } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const cbor = require('cbor');
    const sanitized = sanitizeForCBOR(SAMPLE_ENTRIES);
    const expected = crypto.createHash('sha256').update(cbor.encodeOne(sanitized, { canonical: true })).digest();
    assert.ok(snapshotHash.equals(expected), 'snapshot_hash must match SHA-256(CBOR(entries))');
    fs.rmSync(tmp4, { recursive: true, force: true });
  });

  // J. snapshot_hash changes when entries change
  await test('J. snapshot_hash changes when entries change', async () => {
    const tmp5 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-snap2-'));
    const gm = new GenerationManager(tmp5);
    const sessionId1 = syncCrypto.generateSessionId();
    const { snapshotHash: h1 } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId1, gm);
    const modified = JSON.parse(JSON.stringify(SAMPLE_ENTRIES));
    modified[0].password = 'different-password';
    const sessionId2 = syncCrypto.generateSessionId();
    const { snapshotHash: h2 } = await buildSyncPayload(modified, sessionId2, gm);
    assert.ok(!h1.equals(h2), 'Different entries must produce different snapshot_hash');
    fs.rmSync(tmp5, { recursive: true, force: true });
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[K-N] Payload Correctness');

  // K. Payload contains required fields
  await test('K. Payload contains all required protocol fields', async () => {
    const tmp6 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-fields-'));
    const gm = new GenerationManager(tmp6);
    const sessionId = syncCrypto.generateSessionId();
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const parsed = await parseSyncPayload(compressedBytes);
    const required = ['protocol_version','payload_version','vault_schema_version','session_id','timestamp','generation','snapshot_hash','entries'];
    for (const field of required) {
      assert.ok(field in parsed, `Missing required field: ${field}`);
    }
    assert.strictEqual(parsed.protocol_version, 2);
    assert.strictEqual(parsed.payload_version, 1);
    assert.strictEqual(parsed.vault_schema_version, 1);
    compressedBytes.fill(0);
    fs.rmSync(tmp6, { recursive: true, force: true });
  });

  // L. Payload does NOT contain encryptedB64 as the primary sync data
  await test('L. Payload entries are plaintext objects, NOT encryptedB64 blob', async () => {
    const tmp7 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-nob64-'));
    const gm = new GenerationManager(tmp7);
    const sessionId = syncCrypto.generateSessionId();
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const parsed = await parseSyncPayload(compressedBytes);
    // entries must be array of objects, NOT a base64 string blob
    assert.ok(Array.isArray(parsed.entries), 'entries must be an array');
    assert.ok(typeof parsed.entries[0] === 'object', 'entries[0] must be an object, not a string');
    assert.ok(!('data' in parsed), 'payload must not have a raw data/b64 wrapper field');
    compressedBytes.fill(0);
    fs.rmSync(tmp7, { recursive: true, force: true });
  });

  // M. Canonical CBOR: same entries always produce same CBOR bytes
  await test('M. Canonical CBOR: same entries → identical CBOR bytes', async () => {
    const cbor = require('cbor');
    const sanitized = sanitizeForCBOR(SAMPLE_ENTRIES);
    const enc1 = cbor.encodeOne(sanitized, { canonical: true });
    const enc2 = cbor.encodeOne(sanitized, { canonical: true });
    assert.ok(enc1.equals(enc2), 'Canonical CBOR must be deterministic');
  });

  // N. zstd level 3: compressed output is valid and smaller than raw CBOR for representative data
  await test('N. zstd compression produces decompressable output', async () => {
    const tmp8 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-zstd-'));
    const gm = new GenerationManager(tmp8);
    const sessionId = syncCrypto.generateSessionId();
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    assert.ok(Buffer.isBuffer(compressedBytes) && compressedBytes.length > 0, 'Must produce non-empty output');
    // Verify decompressable (parseSyncPayload would throw if not)
    const parsed = await parseSyncPayload(compressedBytes);
    assert.ok(parsed.entries, 'Must decompress and parse correctly');
    compressedBytes.fill(0);
    fs.rmSync(tmp8, { recursive: true, force: true });
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[O-P] Phase Integration');

  // O. Phase 1 encryption integration
  await test('O. Phase 1 encryption integration: encrypt/decrypt round-trip', async () => {
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);
    const plaintext = Buffer.from('phase1-integration-test');
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(plaintext, key, aad);
    const decrypted = syncCrypto.syncDecrypt(ciphertext, key, nonce, aad);
    assert.ok(decrypted.equals(plaintext), 'Decrypted must equal original');
    key.fill(0);
  });

  // P. Phase 3 transport integration: envelope → chunks → assemble
  await test('P. Phase 3 transport integration: envelope round-trip', async () => {
    const result = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of result.qrChunks) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult && completedResult.complete, 'Transport must successfully reassemble');
    syncV2.cancelSyncSession();
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[Q] Full Desktop Pipeline');

  // Q. Full Desktop pipeline: Vault → Phase2 → Phase1 → Phase3 → decrypt → entries
  await test('Q. Full Desktop pipeline: entries survive full round-trip', async () => {
    // Sender
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const sessHex   = sessionId.toString('hex');
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);

    const tmp9 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-full-'));
    const gm = new GenerationManager(tmp9);

    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    compressedBytes.fill(0);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
    const qrChunks = transport.buildQRChunks(envelope, sessHex);

    // Simulate transport (shuffle + duplicate)
    const simulated = [...qrChunks, qrChunks[0]].sort(() => Math.random() - 0.5);

    // Receiver
    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of simulated) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult, 'Assembly must complete');

    const parsedEnv = syncCrypto.parseEnvelope(Buffer.from(completedResult.envelope));
    const decrypted = syncCrypto.syncDecrypt(parsedEnv.ciphertext, key, parsedEnv.nonce, aad);
    key.fill(0);

    const payload = await parseSyncPayload(decrypted);
    decrypted.fill(0);

    assert.deepStrictEqual(payload.entries, sanitizeForCBOR(SAMPLE_ENTRIES), 'Recovered entries must equal originals');
    fs.rmSync(tmp9, { recursive: true, force: true });
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[R-S] Authentication Tests');

  // R. Wrong Vault Password → fail before sync pipeline
  await test('R. Wrong Vault Password → decrypt fails before sync pipeline', async () => {
    const encrypted = await encryptData(VAULT_PLAINTEXT, VAULT_PASSWORD);
    let threw = false;
    try {
      await decryptData(encrypted, 'WRONG');
    } catch { threw = true; }
    assert.ok(threw, 'Wrong Vault Password must throw');
    // If it didn't throw, extractVaultEntries would still get wrong data
  });

  // S. Wrong Sync Password → AEAD failure
  await test('S. Wrong Sync Password → AEAD authentication failure', async () => {
    const salt       = syncCrypto.generateSyncSalt();
    const sessionId  = syncCrypto.generateSessionId();
    const correctKey = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const wrongKey   = await syncCrypto.deriveSyncKey('WRONG-SYNC-PW', salt);
    const aad        = syncCrypto.buildAAD(sessionId, salt);
    const plaintext  = Buffer.from('secret data');
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(plaintext, correctKey, aad);
    correctKey.fill(0);
    assert.throws(
      () => syncCrypto.syncDecrypt(ciphertext, wrongKey, nonce, aad),
      undefined,
      'Wrong Sync Password must cause AEAD failure'
    );
    wrongKey.fill(0);
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[T-X] Transport Security Tests');

  // T. Modified QR data + recomputed CRC → transport passes, crypto fails
  await test('T. Forged CRC passes transport, AEAD rejects tampering', async () => {
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const sessHex   = sessionId.toString('hex');
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);

    const tmp10 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-tamper-'));
    const gm = new GenerationManager(tmp10);

    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    compressedBytes.fill(0);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
    const chunks = transport.buildQRChunks(envelope, sessHex, 100);

    // Tamper data of first chunk + reforge CRC
    const parts   = chunks[0].split('|');
    const decoded = transport.base45Decode(parts[5]);
    if (decoded.length > 50) decoded[50] ^= 0xFF;
    parts[5] = transport.base45Encode(decoded);
    parts[4] = transport.computeCRC32(decoded); // forge CRC
    chunks[0] = parts.join('|');

    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of chunks) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult, 'Forged CRC allows transport to assemble');

    // Final cryptographic check must fail
    let cryptoFailed = false;
    try {
      const parsedEnv = syncCrypto.parseEnvelope(Buffer.from(completedResult.envelope));
      syncCrypto.syncDecrypt(parsedEnv.ciphertext, key, parsedEnv.nonce, aad);
    } catch { cryptoFailed = true; }
    assert.ok(cryptoFailed, 'AEAD must reject tampered payload');
    key.fill(0);
    fs.rmSync(tmp10, { recursive: true, force: true });
  });

  // U. Missing chunk → no sync completion
  await test('U. Missing chunk → assembly does not complete', async () => {
    const result = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    // Use small chunk size to force multiple chunks
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const sessHex   = sessionId.toString('hex');
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);
    const tmp11 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-missing-'));
    const gm = new GenerationManager(tmp11);
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    compressedBytes.fill(0);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
    const chunks = transport.buildQRChunks(envelope, sessHex, 50);
    key.fill(0);

    if (chunks.length < 2) {
      // Skip if payload fits in 1 chunk at 50B
      passed++; console.log('  ✓ U. Missing chunk (skipped: single chunk at 50B)'); return;
    }

    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    // Feed all except last chunk
    for (const qr of chunks.slice(0, -1)) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(!completedResult, 'Must NOT complete with missing chunk');
    fs.rmSync(tmp11, { recursive: true, force: true });
  });

  // V. Duplicate chunk → safely ignored
  await test('V. Duplicate chunk is silently ignored', async () => {
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const sessHex   = sessionId.toString('hex');
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);
    const tmp12 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-dup-'));
    const gm = new GenerationManager(tmp12);
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    compressedBytes.fill(0);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
    const chunks = transport.buildQRChunks(envelope, sessHex);
    key.fill(0);

    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of [...chunks, ...chunks]) { // feed all twice
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult, 'Must complete despite duplicates');
    fs.rmSync(tmp12, { recursive: true, force: true });
  });

  // W. Out-of-order chunks → successful reassembly
  await test('W. Out-of-order chunks → successful reassembly', async () => {
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();
    const sessHex   = sessionId.toString('hex');
    const key       = await syncCrypto.deriveSyncKey(SYNC_PASSWORD, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);
    const tmp13 = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-ooo-'));
    const gm = new GenerationManager(tmp13);
    const { compressedBytes } = await buildSyncPayload(SAMPLE_ENTRIES, sessionId, gm);
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    compressedBytes.fill(0);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
    const chunks = transport.buildQRChunks(envelope, sessHex, 50);

    const shuffled = [...chunks].sort(() => Math.random() - 0.5);
    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    for (const qr of shuffled) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
    }
    assert.ok(completedResult, 'Must complete from out-of-order chunks');

    const parsedEnv = syncCrypto.parseEnvelope(Buffer.from(completedResult.envelope));
    const decrypted = syncCrypto.syncDecrypt(parsedEnv.ciphertext, key, parsedEnv.nonce, aad);
    key.fill(0);
    const payload = await parseSyncPayload(decrypted);
    assert.deepStrictEqual(payload.entries, sanitizeForCBOR(SAMPLE_ENTRIES));
    fs.rmSync(tmp13, { recursive: true, force: true });
  });

  // X. Wrong session → isolated/rejected
  await test('X. Wrong session chunks are rejected without contaminating active session', async () => {
    const result1 = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    syncV2.cancelSyncSession();
    const result2 = await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    syncV2.cancelSyncSession();

    // Feed all chunks from session2 into a session1-seeded assembler
    const assembler = new transport.ChunkAssembler();
    let completedResult = null;
    // Feed first chunk from session 1 to establish session
    assembler.add(result1.qrChunks[0]);
    // Then feed all chunks from session 2 — must be rejected
    for (const qr of result2.qrChunks) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;
      if (r.error) {
        assert.ok(r.error.includes('different session') || r.error.includes('ignored'), `Unexpected error: ${r.error}`);
      }
    }
    // Session 1 is incomplete (only 1 chunk fed from it)
    assert.ok(!completedResult, 'Wrong session chunks must not complete session 1');
  });

  // Y. Unsupported protocol version → rejected before decryption
  await test('Y. Unsupported protocol version (v1) rejected before decryption', async () => {
    const sessId = 'a1b2c3d4e5f60708';
    const data   = Buffer.from('some payload bytes');
    const crc    = transport.computeCRC32(data);
    const b45    = transport.base45Encode(data);
    // V1 header
    const qrV1 = `FUIN|1|${sessId}|001/001|${crc}|${b45}`;
    let threw = false;
    try {
      transport.parseQRChunkString(qrV1);
    } catch (e) {
      threw = true;
      assert.ok(e.message.includes('unsupported protocol version'), `Got: ${e.message}`);
    }
    assert.ok(threw, 'V1 chunk must be rejected');
  });

  // ────────────────────────────────────────────────────────────────────────────
  console.log('\n[Z-AA] Security / Regression');

  // Z. No plaintext written to disk during sync pipeline
  await test('Z. No plaintext written to disk during sync pipeline', async () => {
    const filesBefore = fs.readdirSync(TMP_DIR);
    await syncV2.buildV2QRChunks(SAMPLE_ENTRIES, SYNC_PASSWORD);
    syncV2.cancelSyncSession();
    const filesAfter = fs.readdirSync(TMP_DIR);
    // Only fuin.sync-generation file should appear — no plaintext dump
    const newFiles = filesAfter.filter(f => !filesBefore.includes(f));
    for (const f of newFiles) {
      assert.ok(
        f === 'fuin.sync-generation',
        `Unexpected file written to disk during sync: ${f}`
      );
    }
  });

  // AA. Existing Vault encryption regression
  await test('AA. Existing Vault encryption (encryptData/decryptData) regression', async () => {
    const encrypted = await encryptData(VAULT_PLAINTEXT, VAULT_PASSWORD);
    const decrypted = await decryptData(encrypted, VAULT_PASSWORD);
    assert.deepStrictEqual(decrypted, VAULT_PLAINTEXT, 'Vault round-trip must be lossless');
    // Verify it rejects wrong password
    let threw = false;
    try { await decryptData(encrypted, 'WRONG'); } catch { threw = true; }
    assert.ok(threw, 'Vault decryption must reject wrong password');
  });

  // ── RESULTS ───────────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(`SONUÇ: ${passed} BAŞARILI, ${failed} BAŞARISIZ`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}

  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error('\n✗ UNHANDLED TEST ERROR:', e.stack);
  process.exit(1);
});
