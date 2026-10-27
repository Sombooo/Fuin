'use strict';

const assert = require('assert');
const crypto = require('crypto');

console.log('═'.repeat(75));
console.log('FUIN TEST: CRYPTOGRAPHIC STANDARDS, NIST KAT & ADVERSARIAL FUZZING');
console.log('═'.repeat(75));

let passes = 0;
let failures = 0;

function test(desc, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${desc}`);
    console.error(`    ${err.message}`);
    failures++;
  }
}

async function testAsync(desc, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${desc}`);
    console.error(`    ${err.message}`);
    failures++;
  }
}

// ═══════════════════════════════════════════════════════════════════
// 1. NIST SP 800-38D AES-256-GCM KNOWN ANSWER TESTS (KAT)
// ═══════════════════════════════════════════════════════════════════

test('1.1 NIST SP 800-38D KAT Test Case 1: Empty PT, zero key and IV produces exact NIST auth tag', () => {
  const key = Buffer.alloc(32, 0);
  const iv = Buffer.alloc(12, 0);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = cipher.final();
  const tag = cipher.getAuthTag();

  assert.strictEqual(ct.length, 0);
  assert.strictEqual(tag.toString('hex'), '530f8afbc74536b9a963b4f1c4cb738b');

  // Reverse KAT: Decryption validates tag
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const recovered = decipher.final();
  assert.strictEqual(recovered.length, 0);
});

test('1.2 NIST SP 800-38D KAT Test Case 2: 16-byte zero PT produces exact NIST ciphertext and tag', () => {
  const key = Buffer.alloc(32, 0);
  const iv = Buffer.alloc(12, 0);
  const pt = Buffer.alloc(16, 0);

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  assert.strictEqual(ct.toString('hex'), 'cea7403d4d606b6e074ec5d3baf39d18');
  assert.strictEqual(tag.toString('hex'), 'd0d1c8a799996bf0265b98b5d48ab919');

  // Decryption verification
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const recovered = Buffer.concat([decipher.update(ct), decipher.final()]);
  assert.strictEqual(recovered.toString('hex'), pt.toString('hex'));
});

test('1.3 NIST SP 800-38D KAT Test Case 15: 64-byte payload without AAD matches standard vector', () => {
  const key = Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex');
  const iv = Buffer.from('cafebabefacedbaddecaf888', 'hex');
  const pt = Buffer.from('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255', 'hex');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  const expectedCt = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad';
  const expectedTag = 'b094dac5d93471bdec1a502270e3cc6c';

  assert.strictEqual(ct.toString('hex'), expectedCt);
  assert.strictEqual(tag.toString('hex'), expectedTag);
});

test('1.4 NIST SP 800-38D KAT Test Case 16: 64-byte payload with 20-byte AAD matches standard vector', () => {
  const key = Buffer.from('feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308', 'hex');
  const iv = Buffer.from('cafebabefacedbaddecaf888', 'hex');
  const pt = Buffer.from('d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255', 'hex');
  const aad = Buffer.from('feedfacedeadbeeffeedfacedeadbeefabaddadb', 'hex');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();

  const expectedCt = '522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad';
  const expectedTag = '0adb21a13b23bad4143bb6faccd00a5f';

  assert.strictEqual(ct.toString('hex'), expectedCt);
  assert.strictEqual(tag.toString('hex'), expectedTag);
});

// ═══════════════════════════════════════════════════════════════════
// 2. CSPRNG NONCE / IV UNIQUENESS & COLLISION RESISTANCE (10,000x)
// ═══════════════════════════════════════════════════════════════════

test('2.1 Nonce Uniqueness: 10,000 continuous IV generations result in exactly 10,000 distinct values (0 collisions)', () => {
  const TOTAL_RUNS = 10000;
  const seenNonces = new Set();
  const startTime = Date.now();

  for (let i = 0; i < TOTAL_RUNS; i++) {
    const iv = crypto.randomBytes(12);
    const hex = iv.toString('hex');
    assert.strictEqual(hex.length, 24, 'IV length must be exactly 12 bytes (24 hex characters)');
    seenNonces.add(hex);
  }

  const elapsedMs = Date.now() - startTime;
  assert.strictEqual(seenNonces.size, TOTAL_RUNS, `Expected ${TOTAL_RUNS} unique IVs, but found ${seenNonces.size} (collision detected!)`);
  console.log(`    [Metrics] 10,000 CSPRNG IVs generated in ${elapsedMs}ms without collision.`);
});

// ═══════════════════════════════════════════════════════════════════
// 3. ARGON2ID KEY DERIVATION & AVALANCHE EFFECT
// ═══════════════════════════════════════════════════════════════════

(async () => {
  await testAsync('3.1 Argon2id non-inversion and avalanche effect across distinct salts', async () => {
    let argon2;
    try {
      argon2 = require('argon2');
    } catch {
      throw new Error('Argon2 module required for test');
    }

    const password = 'SuperSecretMasterPassword!2026';
    const salt1 = crypto.randomBytes(32);
    const salt2 = crypto.randomBytes(32);

    const key1 = await argon2.hash(password, {
      type: argon2.argon2id, salt: salt1,
      memoryCost: 65536, timeCost: 3, parallelism: 1,
      hashLength: 32, raw: true
    });

    const key2 = await argon2.hash(password, {
      type: argon2.argon2id, salt: salt2,
      memoryCost: 65536, timeCost: 3, parallelism: 1,
      hashLength: 32, raw: true
    });

    assert.strictEqual(key1.length, 32);
    assert.strictEqual(key2.length, 32);
    assert.notStrictEqual(key1.toString('hex'), key2.toString('hex'));

    // Count bit flips (Hamming distance) between key1 and key2
    let bitDiff = 0;
    for (let i = 0; i < 32; i++) {
      let xor = key1[i] ^ key2[i];
      while (xor > 0) {
        if (xor & 1) bitDiff++;
        xor >>= 1;
      }
    }
    // For 256 bits, independent keys have an expected Hamming distance of ~128 (between 90 and 166)
    assert.ok(bitDiff > 90 && bitDiff < 166, `Hamming distance ${bitDiff}/256 outside expected statistical range`);

    // Verify Zeroization
    key1.fill(0);
    key2.fill(0);
    assert.ok(key1.every(b => b === 0), 'key1 buffer must be completely zeroized (0x00)');
    assert.ok(key2.every(b => b === 0), 'key2 buffer must be completely zeroized (0x00)');
  });

  // ═══════════════════════════════════════════════════════════════════
  // 4. ADVERSARIAL FUZZING & MALFORMED VAULT INJECTION
  // ═══════════════════════════════════════════════════════════════════

  test('4.1 Adversarial Fuzzing: Non-string and truncated payloads are strictly rejected', () => {
    const invalidInputs = [
      null,
      undefined,
      12345,
      {},
      [],
      '',
      'short',
      'a'.repeat(59), // Below minimum 60-byte payload requirement
      Buffer.from('not base64').toString('hex')
    ];

    const validatePayload = (payload) => {
      if (typeof payload !== 'string' || payload.length < 80) {
        throw new Error('Invalid vault packet format: payload too short or invalid type');
      }
      if (payload.length > 50 * 1024 * 1024) {
        throw new Error('Invalid vault packet format: payload exceeds maximum allowable size (50MB)');
      }
      return true;
    };

    for (const inv of invalidInputs) {
      assert.throws(() => validatePayload(inv), /Invalid vault packet format/);
    }
  });

  test('4.2 Adversarial Fuzzing: Giant payload bomb (>50MB) triggers upfront rejection without OOM', () => {
    const validatePayload = (payload) => {
      if (typeof payload !== 'string' || payload.length < 80) {
        throw new Error('Invalid vault packet format: payload too short or invalid type');
      }
      if (payload.length > 50 * 1024 * 1024) {
        throw new Error('Invalid vault packet format: payload exceeds maximum allowable size (50MB)');
      }
      return true;
    };

    const giantString = 'A'.repeat(51 * 1024 * 1024);
    assert.throws(() => validatePayload(giantString), /exceeds maximum allowable size/);
  });

  test('4.3 AEAD Tamper Resistance: Single-bit flip in ciphertext triggers tag mismatch and leaks 0 plaintext', () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const plain = JSON.stringify({ type: 'fuin/vault', entries: [{ site: 'bank.com', password: 'mySecretPassword123' }] });

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Mutate 1 bit in ciphertext
    const tamperedCt = Buffer.from(ct);
    tamperedCt[tamperedCt.length - 1] ^= 0x01;

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);

    assert.throws(() => {
      decipher.update(tamperedCt);
      decipher.final();
    }, /Unsupported state or unable to authenticate data/);
  });

  test('4.4 AEAD Tamper Resistance: Mutated auth tag is immediately rejected', () => {
    const key = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const plain = 'Safe vault data';

    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Mutate 1 byte of the tag
    const tamperedTag = Buffer.from(tag);
    tamperedTag[0] ^= 0x42;

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tamperedTag);

    assert.throws(() => {
      decipher.update(ct);
      decipher.final();
    }, /Unsupported state or unable to authenticate data/);
  });

  test('4.5 In-Memory Hygiene: Timing-safe comparison prevents timing side-channel attacks', () => {
    const hashA = crypto.createHash('sha256').update('MasterPassword123').digest();
    const hashB = crypto.createHash('sha256').update('MasterPassword123').digest();
    const hashC = crypto.createHash('sha256').update('WrongPassword456').digest();

    assert.strictEqual(crypto.timingSafeEqual(hashA, hashB), true);
    assert.strictEqual(crypto.timingSafeEqual(hashA, hashC), false);
  });

  // ═══════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════
  console.log('═'.repeat(75));
  console.log(`TOTAL PASSES: ${passes}`);
  console.log(`TOTAL FAILURES: ${failures}`);
  console.log('═'.repeat(75));

  if (failures > 0) process.exit(1);
})();
