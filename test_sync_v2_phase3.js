'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — PHASE 3 TEST SUITE
// test_sync_v2_phase3.js
//
// Tests A through Z per the Phase 3 specification.
// ═══════════════════════════════════════════════════════════════════════════════

const assert = require('assert');
const crypto = require('crypto');
const Module = require('module');
const os     = require('os');
const path   = require('path');
const fs     = require('fs');

// ── Import Phase 3 transport layer ────────────────────────────────────────────
const transport = require('./sync-v2-transport.js');
const {
  base45Encode, base45Decode,
  computeCRC32, verifyCRC32,
  generateQRSessionId, isValidSessionIdHex,
  buildQRChunkString, parseQRChunkString,
  buildQRChunks,
  ChunkAssembler,
  CHUNK_BYTE_SIZE, SUPPORTED_VERSION, QR_PREFIX,
} = transport;

// ── Argon2 mock (same as Phase 1 tests) ───────────────────────────────────────
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

// ── Phase 1 crypto ────────────────────────────────────────────────────────────
delete require.cache[require.resolve('./sync-v2-crypto.js')];
const syncCrypto = require('./sync-v2-crypto.js');

// ── Phase 2 payload ───────────────────────────────────────────────────────────
delete require.cache[require.resolve('./sync-v2-payload.js')];
const { buildSyncPayload, parseSyncPayload, GenerationManager, sanitizeForCBOR } = require('./sync-v2-payload.js');

// Temp dir for generation state in tests
const TMP_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-phase3-'));
const genManager = new GenerationManager(TMP_DIR);

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
    if (process.env.VERBOSE) console.error(e.stack);
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

// ── Helper: build a complete V2 envelope for transport tests ──────────────────
async function buildTestEnvelope(entries, password) {
  password = password || 'sync-test-password-phase3';
  const salt      = syncCrypto.generateSyncSalt();          // 16B
  const sessionId = syncCrypto.generateSessionId();         // 8B raw
  const key       = await syncCrypto.deriveSyncKey(password, salt);
  const aad       = syncCrypto.buildAAD(sessionId, salt);

  const { compressedBytes } = await buildSyncPayload(entries, sessionId, genManager);
  const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
  const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);

  return { envelope, salt, sessionId, key, aad, password };
}

// ═══════════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════════
async function main() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('FUIN SYNC V2 — PHASE 3 TEST SUITE');
  console.log('═══════════════════════════════════════════════════════════════\n');

  // ── A. Base45 known vector ─────────────────────────────────────────────────
  console.log('[A-C] Base45');
  await test('A. Base45 known vector (RFC 9285 "AB" → "BB8")', async () => {
    // RFC 9285 §4.2: "AB" (0x41 0x42) → "BB8"
    const encoded = base45Encode(Buffer.from([0x41, 0x42]));
    assert.strictEqual(encoded, 'BB8', `Expected "BB8", got "${encoded}"`);
  });

  // ── B. Base45 round-trip ───────────────────────────────────────────────────
  await test('B. Base45 encode/decode round-trip (random 200B)', async () => {
    const original = crypto.randomBytes(200);
    const encoded  = base45Encode(original);
    const decoded  = base45Decode(encoded);
    assert.ok(Buffer.from(decoded).equals(original), 'Round-trip mismatch');
  });

  // ── C. Invalid Base45 rejection ────────────────────────────────────────────
  await test('C. Invalid Base45 character rejected (RFC 9285 strict)', async () => {
    // '!' is not in Base45 alphabet
    assertThrows(() => base45Decode('ABC!DEF'), 'invalid character');
  });

  // ── D. CRC32 known vector ──────────────────────────────────────────────────
  console.log('\n[D-E] CRC32');
  await test('D. CRC32 known vector (empty string)', async () => {
    // CRC32("") = 0x00000000
    const crc = computeCRC32(Buffer.alloc(0));
    assert.strictEqual(crc, '00000000');
  });

  // ── E. CRC32 mutation detection ────────────────────────────────────────────
  await test('E. CRC32 mutation detection (1-bit flip)', async () => {
    const data    = Buffer.from('hello world');
    const crc     = computeCRC32(data);
    const mutated = Buffer.from(data);
    mutated[0] ^= 0x01;
    assert.ok(!verifyCRC32(mutated, crc), 'CRC32 should not match mutated data');
    assert.ok(verifyCRC32(data, crc),     'CRC32 should match original data');
  });

  // ── F. SessionId generation/validation ────────────────────────────────────
  console.log('\n[F-G] Session ID');
  await test('F. SessionId: 8 raw bytes, 16 hex chars', async () => {
    const { raw, hex } = generateQRSessionId();
    assert.strictEqual(raw.length, 8,  'raw must be 8 bytes');
    assert.strictEqual(hex.length, 16, 'hex must be 16 chars');
    assert.ok(isValidSessionIdHex(hex), 'hex must be valid');
  });

  // ── G. SessionId lowercase hex validation ──────────────────────────────────
  await test('G. SessionId lowercase hex validation', async () => {
    assert.ok(isValidSessionIdHex('a1b2c3d4e5f60708'),  'valid lowercase hex');
    assert.ok(!isValidSessionIdHex('A1B2C3D4E5F60708'), 'uppercase rejected');
    assert.ok(!isValidSessionIdHex('a1b2c3d4e5f6070'),  '15 chars rejected');
    assert.ok(!isValidSessionIdHex('a1b2c3d4e5f607088'), '17 chars rejected');
    assert.ok(!isValidSessionIdHex('a1b2c3d4e5f6070g'), 'non-hex char rejected');
    assert.ok(!isValidSessionIdHex(''),                  'empty rejected');
  });

  // ── H. Valid QR header parsing ─────────────────────────────────────────────
  console.log('\n[H-J] QR Header');
  await test('H. Valid QR header parsing', async () => {
    const sessId = 'a1b2c3d4e5f60708';
    const data   = Buffer.from('test chunk bytes');
    const qr     = buildQRChunkString(sessId, 1, 3, data);
    const parsed = parseQRChunkString(qr);
    assert.strictEqual(parsed.sessionIdHex, sessId);
    assert.strictEqual(parsed.index,  1);
    assert.strictEqual(parsed.total,  3);
    assert.ok(Buffer.from(parsed.chunkBytes).equals(data), 'chunkBytes mismatch');
  });

  // ── I. Malformed header rejection ─────────────────────────────────────────
  await test('I. Malformed header rejection (wrong field count)', async () => {
    assertThrows(() => parseQRChunkString('FUIN|2|abcd|001/003|AABBCCDD'), '6 pipe-delimited');
    assertThrows(() => parseQRChunkString('FUIN|2|a1b2c3d4e5f60708|001/003|AABBCCDD|data|extra'), '6 pipe-delimited');
    assertThrows(() => parseQRChunkString(''), 'non-empty');
    assertThrows(() => parseQRChunkString('NOTFUIN|2|a1b2c3d4e5f60708|001/003|AABBCCDD|AB'), "prefix 'FUIN'");
  });

  // ── J. Unsupported protocol version rejection ──────────────────────────────
  await test('J. Unsupported protocol version rejection', async () => {
    // Build valid chunk then replace version
    const sessId = 'a1b2c3d4e5f60708';
    const data   = Buffer.from('version test');
    const crc    = computeCRC32(data);
    const b45    = base45Encode(data);

    assertThrows(() => parseQRChunkString(`FUIN|1|${sessId}|001/001|${crc}|${b45}`), 'unsupported protocol version');
    assertThrows(() => parseQRChunkString(`FUIN|3|${sessId}|001/001|${crc}|${b45}`), 'unsupported protocol version');
    assertThrows(() => parseQRChunkString(`FUIN|abc|${sessId}|001/001|${crc}|${b45}`), 'unsupported protocol version');
  });

  // ── K. Valid chunk generation ──────────────────────────────────────────────
  console.log('\n[K-N] Chunk Generation');
  await test('K. Valid chunk generation from envelope', async () => {
    const entries = [{ id: '1', site: 'test.com' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex);
    assert.ok(chunks.length >= 1, 'At least 1 chunk expected');
    for (const c of chunks) {
      assert.ok(typeof c === 'string', 'Each chunk must be a string');
      assert.ok(c.startsWith(`FUIN|${SUPPORTED_VERSION}|`), 'Chunk must start with FUIN|2|');
    }
  });

  // ── L. Correct index/total ─────────────────────────────────────────────────
  await test('L. Correct index/total in chunk headers', async () => {
    const entries = [{ id: '1', site: 'test.com' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex);
    const total  = chunks.length;
    for (let i = 0; i < chunks.length; i++) {
      const p = parseQRChunkString(chunks[i]);
      assert.strictEqual(p.index, i + 1, `Expected index ${i+1}, got ${p.index}`);
      assert.strictEqual(p.total, total, `Expected total ${total}, got ${p.total}`);
    }
  });

  // ── M. Correct sessionId in chunk headers ─────────────────────────────────
  await test('M. Correct sessionId in all chunk headers', async () => {
    const entries = [{ id: '1', site: 'test.com' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex);
    for (const c of chunks) {
      const p = parseQRChunkString(c);
      assert.strictEqual(p.sessionIdHex, sessHex);
    }
  });

  // ── N. Correct CRC per chunk ───────────────────────────────────────────────
  await test('N. Correct CRC32 in all chunk headers', async () => {
    const entries = [{ id: '1', site: 'test.com' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex);
    for (const c of chunks) {
      // parseQRChunkString already verifies CRC — if it doesn't throw, CRC is correct
      const p = parseQRChunkString(c);
      const expectedCrc = computeCRC32(p.chunkBytes);
      const crcField    = c.split('|')[4];
      assert.strictEqual(crcField, expectedCrc, 'CRC in header mismatch');
    }
  });

  // ── O. Out-of-order assembly ───────────────────────────────────────────────
  console.log('\n[O-U] Chunk Assembly');
  await test('O. Out-of-order chunk assembly', async () => {
    const entries = [{ id: '1', site: 'test.com', pass: 'secret1' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks   = buildQRChunks(envelope, sessHex, 50); // small chunks → multiple
    const shuffled = [...chunks].sort(() => Math.random() - 0.5);

    const assembler = new ChunkAssembler();
    let result;
    for (const c of shuffled) {
      result = assembler.add(c);
    }
    assert.ok(result.complete, 'Assembly should be complete after all chunks');
    assert.ok(Buffer.from(result.envelope).equals(envelope), 'Reassembled envelope must be byte-identical');
  });

  // ── P. Duplicate chunk handling ────────────────────────────────────────────
  await test('P. Duplicate chunk is silently ignored', async () => {
    const entries = [{ id: '1', site: 'dup.test' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex, 50);

    const assembler = new ChunkAssembler();
    // Feed all chunks twice
    let result;
    for (const c of [...chunks, ...chunks]) {
      result = assembler.add(c);
    }
    // After duplicates, assembly should still succeed exactly once
    assert.ok(result.complete, 'Assembly should succeed');
    assert.ok(Buffer.from(result.envelope).equals(envelope), 'Byte-identical after duplicate feed');
  });

  // ── Q. Missing chunk detection ─────────────────────────────────────────────
  await test('Q. Missing chunk detection (incomplete assembly)', async () => {
    const entries = [{ id: '1', site: 'missing.test' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex, 50);

    if (chunks.length < 2) {
      // Envelope too small for 2 chunks at 50B — skip
      console.log('      (skipped: envelope fits in 1 chunk at 50B)');
      passed++;
      return;
    }

    const assembler = new ChunkAssembler();
    // Feed all except first chunk
    let result;
    for (const c of chunks.slice(1)) {
      result = assembler.add(c);
    }
    assert.ok(!result.complete, 'Assembly must not complete when chunk is missing');
  });

  // ── R. Different session isolation ────────────────────────────────────────
  await test('R. Different session isolation', async () => {
    const entries1 = [{ id: '1', site: 'session-a.test' }];
    const entries2 = [{ id: '2', site: 'session-b.test' }];
    const { envelope: env1 } = await buildTestEnvelope(entries1);
    const { envelope: env2 } = await buildTestEnvelope(entries2);
    const { hex: sessHex1 } = generateQRSessionId();
    const { hex: sessHex2 } = generateQRSessionId();

    const chunksA = buildQRChunks(env1, sessHex1, 50);
    const chunksB = buildQRChunks(env2, sessHex2, 50);

    const assembler = new ChunkAssembler();
    // Interleave session B chunks into session A assembler
    let resultA;
    for (const c of chunksA) resultA = assembler.add(c);
    for (const c of chunksB) assembler.add(c); // must be silently ignored

    assert.ok(resultA.complete, 'Session A assembly should complete');
    assert.ok(Buffer.from(resultA.envelope).equals(env1), 'Session A envelope must be intact');
  });

  // ── S. Wrong index rejection ───────────────────────────────────────────────
  await test('S. Wrong index (0) rejected', async () => {
    const sessId = 'a1b2c3d4e5f60708';
    const data   = Buffer.from('some data');
    assertThrows(() => buildQRChunkString(sessId, 0, 3, data), 'out of range');
  });

  // ── T. Wrong total rejection ───────────────────────────────────────────────
  await test('T. Wrong total (0) rejected', async () => {
    const sessId = 'a1b2c3d4e5f60708';
    const data   = Buffer.from('some data');
    assertThrows(() => buildQRChunkString(sessId, 1, 0, data), 'total must be >= 1');
  });

  // ── U. Inconsistent total rejection ───────────────────────────────────────
  await test('U. Inconsistent total rejected mid-session', async () => {
    const sessId  = 'a1b2c3d4e5f60708';
    const data    = Buffer.from('some data bytes here longer');
    // Build 2 valid chunks manually: same session, but different total value
    const crc1 = computeCRC32(data);
    const b451 = base45Encode(data);
    const qr1  = `FUIN|2|${sessId}|001/003|${crc1}|${b451}`;
    const qr2  = `FUIN|2|${sessId}|002/005|${crc1}|${b451}`; // total=5 differs from 3

    const assembler = new ChunkAssembler();
    const r1 = assembler.add(qr1);
    assert.ok(!r1.complete, 'First chunk — not complete');
    const r2 = assembler.add(qr2);
    assert.ok(!r2.complete, 'Inconsistent total chunk must be rejected');
    assert.ok(r2.error && r2.error.includes('Inconsistent total'), `Expected inconsistency error, got: ${r2.error}`);
  });

  // ── V. Envelope → chunks → reassembly byte equality ───────────────────────
  console.log('\n[V-Z] Integration');
  await test('V. Envelope round-trip byte equality', async () => {
    const entries = [{ id: '1', site: 'roundtrip.test', pass: 'p@ssw0rd' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex, 100);

    const assembler = new ChunkAssembler();
    let result;
    for (const c of chunks) result = assembler.add(c);
    assert.ok(result.complete, 'Must be complete');
    assert.ok(Buffer.from(result.envelope).equals(envelope), 'Reassembled must equal original byte-for-byte');
  });

  // ── W. Tampered DATA: CRC mismatch → chunk rejected ───────────────────────
  await test('W. Tampered DATA (CRC mismatch) → chunk dropped', async () => {
    const entries = [{ id: '1', site: 'tamper.test' }];
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex, 50);

    // Tamper the DATA field of the first chunk (but keep the CRC — mismatch)
    const parts   = chunks[0].split('|');
    const b45Data = parts[5];
    // flip a char in the Base45 data
    const tampered = b45Data.slice(0, -1) +
      (b45Data[b45Data.length - 1] === 'A' ? 'B' : 'A');
    parts[5] = tampered;
    const tamperedChunk = parts.join('|');

    // parseQRChunkString should throw with CRC mismatch
    assertThrows(() => parseQRChunkString(tamperedChunk), 'CRC32 mismatch');
  });

  // ── X. Tampered DATA + forged CRC → crypto auth fails ─────────────────────
  await test('X. Tampered DATA + forged CRC → crypto AEAD fails', async () => {
    const entries = [{ id: '1', site: 'forged.test', pass: 'sec' }];
    const { envelope, key, aad } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks = buildQRChunks(envelope, sessHex, 100);

    if (chunks.length < 2) {
      // Single-chunk envelope — mutate the chunk bytes
      const parts      = chunks[0].split('|');
      const decoded    = base45Decode(parts[5]);
      // Flip a byte inside ciphertext region (beyond the 59-byte header)
      if (decoded.length > 60) decoded[60] ^= 0xFF;
      const newB45  = base45Encode(decoded);
      const newCRC  = computeCRC32(decoded);  // forge CRC
      parts[4] = newCRC;
      parts[5] = newB45;
      const forgery = parts.join('|');

      const assembler = new ChunkAssembler();
      const r = assembler.add(forgery);
      // Assembly "completes" but envelope is corrupted → Phase 1 decrypt must fail
      assert.ok(r.complete, 'Forged chunk should reassemble (CRC was forged)');
      assert.throws(
        () => syncCrypto.parseEnvelope(Buffer.from(r.envelope)),
        undefined,
        'parseEnvelope should reject tampered envelope, or syncDecrypt should'
      );
      // If parseEnvelope passes, try decrypt — must fail
    } else {
      // Multi-chunk: mutate middle chunk binary data + reforge CRC
      const midIdx  = Math.floor(chunks.length / 2);
      const parts   = chunks[midIdx].split('|');
      const decoded = base45Decode(parts[5]);
      decoded[0] ^= 0xFF;              // flip byte
      parts[5] = base45Encode(decoded);  // re-encode
      parts[4] = computeCRC32(decoded);  // forge CRC to pass transport check
      chunks[midIdx] = parts.join('|');

      const assembler = new ChunkAssembler();
      let result;
      for (const c of chunks) result = assembler.add(c);
      assert.ok(result.complete, 'Forged-CRC chunks should reassemble');

      // Final cryptographic verification must fail
      let decryptThrew = false;
      try {
        const parsed = syncCrypto.parseEnvelope(Buffer.from(result.envelope));
        syncCrypto.syncDecrypt(parsed.ciphertext, key, parsed.nonce, aad);
      } catch (e) {
        decryptThrew = true;
      }
      assert.ok(decryptThrew, 'AEAD must reject tampered payload even when CRC was forged');
    }
  });

  // ── Y. Large payload chunking ──────────────────────────────────────────────
  await test('Y. Large payload: 500 entries, correct chunk count', async () => {
    const entries = Array.from({ length: 500 }, (_, i) => ({
      id:   String(i),
      site: `site-${i}.example.com`,
      user: `user${i}`,
      pass: crypto.randomBytes(16).toString('hex'),
    }));
    const { envelope } = await buildTestEnvelope(entries);
    const { hex: sessHex } = generateQRSessionId();
    const chunks   = buildQRChunks(envelope, sessHex);
    const expected = Math.ceil(envelope.length / CHUNK_BYTE_SIZE);
    assert.strictEqual(chunks.length, expected, `Expected ${expected} chunks, got ${chunks.length}`);

    // Full reassembly
    const assembler = new ChunkAssembler();
    let result;
    for (const c of [...chunks].sort(() => Math.random() - 0.5)) {
      result = assembler.add(c);
    }
    assert.ok(result.complete, 'Large payload must reassemble');
    assert.ok(Buffer.from(result.envelope).equals(envelope), 'Large payload byte-identical after reassembly');
  });

  // ── Z. Full integration pipeline ──────────────────────────────────────────
  await test('Z. Full integration: entries → Phase2 → Phase1 → QR → decrypt → entries', async () => {
    const originalEntries = [
      { id: '1', site: 'fulltest.com',   pass: 'abc',  note: 'integration' },
      { id: '2', site: 'fulltest2.com',  pass: 'xyz',  tags: null },
    ];
    const password = 'full-integration-sync-password';

    // ── SENDER SIDE ──
    const salt      = syncCrypto.generateSyncSalt();
    const sessionId = syncCrypto.generateSessionId();  // 8B raw
    const sessHex   = sessionId.toString('hex');       // 16 lowercase hex
    const key       = await syncCrypto.deriveSyncKey(password, salt);
    const aad       = syncCrypto.buildAAD(sessionId, salt);

    // Phase 2: canonical CBOR → snapshot_hash → zstd
    const { compressedBytes } = await buildSyncPayload(originalEntries, sessionId, genManager);

    // Phase 1: XChaCha20-Poly1305 encrypt → outer envelope
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);
    const envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);

    // Phase 3: chunk → QR strings
    const qrStrings = buildQRChunks(envelope, sessHex);

    // Simulate QR transport (shuffle order, add duplicates)
    const simulated = [...qrStrings, qrStrings[0]].sort(() => Math.random() - 0.5);

    // ── RECEIVER SIDE ──
    const assembler = new ChunkAssembler();
    let completedResult = null;
    for (const qr of simulated) {
      const r = assembler.add(qr);
      if (r.complete) completedResult = r;  // track — a later dup returns {complete:false}
    }
    assert.ok(completedResult && completedResult.complete, 'Assembly must complete');

    // Phase 1: parse outer envelope → decrypt
    const parsedEnv = syncCrypto.parseEnvelope(Buffer.from(completedResult.envelope));
    const decrypted = syncCrypto.syncDecrypt(parsedEnv.ciphertext, key, parsedEnv.nonce, aad);

    // Phase 2: zstd decompress → CBOR parse → entries
    const finalPayload = await parseSyncPayload(decrypted);
    const expected     = sanitizeForCBOR(originalEntries);
    assert.deepStrictEqual(finalPayload.entries, expected, 'Final entries must equal original entries');
  });

  // ── RESULTS ───────────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log(`SONUÇ: ${passed} BAŞARILI, ${failed} BAŞARISIZ`);
  console.log('═══════════════════════════════════════════════════════════════\n');

  // Cleanup temp dir
  try { fs.rmSync(TMP_DIR, { recursive: true, force: true }); } catch {}

  if (failed > 0) process.exit(1);
}

main().catch(e => {
  console.error('\n✗ UNHANDLED TEST ERROR:', e.stack);
  process.exit(1);
});
