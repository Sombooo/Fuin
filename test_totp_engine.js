'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST SUITE: test_totp_engine.js
 *
 * Verifies RFC 4648 Base32 and RFC 6238 TOTP Engine Specification:
 *   1. RFC 4648 Base32 decoding, encoding, padding, and tolerant parsing
 *   2. RFC 6238 standard test vectors (6-digit, 8-digit, 32-bit & 64-bit timestamps)
 *   3. Dual-crypto backend parity (Web Crypto subtle vs Node crypto)
 *   4. Timing ticker lifecycle, interval countdown, and UI percentage
 *   5. TOTP verification with window drift (+-1 step)
 *   6. Error handling, invalid characters, and otpauth:// URI extraction
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const totp = require('./services/totpEngine.js');

console.log('═'.repeat(75));
console.log('FUIN TEST: TOTP ENGINE & BASE32 DOMAIN SERVICE');
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

(async () => {
  // ── 1. RFC 4648 BASE32 ENCODING & DECODING TEST VECTORS ──────────────────
  console.log('\n[Section 1: RFC 4648 Base32 Standard Vectors]');

  const rfc4648Vectors = [
    { raw: '', b32: '' },
    { raw: 'f', b32: 'MY======' },
    { raw: 'fo', b32: 'MZXQ====' },
    { raw: 'foo', b32: 'MZXW6===' },
    { raw: 'foob', b32: 'MZXW6YQ=' },
    { raw: 'fooba', b32: 'MZXW6YTB' },
    { raw: 'foobar', b32: 'MZXW6YTBOI======' },
  ];

  test('RFC 4648: base32Encode encodes standard vectors', () => {
    for (const v of rfc4648Vectors) {
      const enc = totp.base32Encode(Buffer.from(v.raw, 'utf8'));
      assert.strictEqual(enc, v.b32, `Encode failed for "${v.raw}"`);
    }
  });

  test('RFC 4648: base32Decode decodes standard padded vectors', () => {
    for (const v of rfc4648Vectors) {
      const dec = Buffer.from(totp.base32Decode(v.b32)).toString('utf8');
      assert.strictEqual(dec, v.raw, `Decode failed for "${v.b32}"`);
    }
  });

  test('RFC 4648: base32Decode decodes unpadded vectors', () => {
    for (const v of rfc4648Vectors) {
      const unpadded = v.b32.replace(/=/g, '');
      const dec = Buffer.from(totp.base32Decode(unpadded)).toString('utf8');
      assert.strictEqual(dec, v.raw, `Decode unpadded failed for "${unpadded}"`);
    }
  });

  test('Base32: Strips whitespace, hyphens, and ignores case', () => {
    const raw = 'foobar';
    const variations = [
      'mzxw6ytboi======',
      'MZXW6YTBOI',
      'MZXW-6YTB-OI',
      'M Z X W 6 Y T B O I = = = = = =',
      '  mzxw 6ytb oi \n\t',
    ];
    for (const variant of variations) {
      const dec = Buffer.from(totp.base32Decode(variant)).toString('utf8');
      assert.strictEqual(dec, raw, `Failed variant "${variant}"`);
    }
  });

  test('Base32: Extracts secret from otpauth:// URI', () => {
    const uri = 'otpauth://totp/Fuin:alice@fuin.org?secret=MZXW6YTBOI&issuer=Fuin';
    const dec = Buffer.from(totp.base32Decode(uri)).toString('utf8');
    assert.strictEqual(dec, 'foobar');
  });

  test('Base32: Throws Error on invalid characters in strict mode', () => {
    assert.throws(() => totp.base32Decode('MZXW8==='), /Invalid Base32 character/);
    assert.throws(() => totp.base32Decode('MZXW9==='), /Invalid Base32 character/);
    assert.throws(() => totp.base32Decode('MZXW#==='), /Invalid Base32 character/);
    assert.throws(() => totp.base32Decode(null), /must be a string/);
  });

  test('Base32: Loose mode tolerates invalid characters', () => {
    const dec = totp.base32Decode('MZXW86===', { loose: true });
    assert.strictEqual(Buffer.from(dec).toString('utf8'), 'foo');
  });

  // ── 2. RFC 6238 HMAC-SHA1 STANDARD TEST VECTORS ─────────────────────────
  console.log('\n[Section 2: RFC 6238 HMAC-SHA1 Standard Test Vectors]');

  // RFC 6238 Appendix B: Key is ASCII "12345678901234567890" (20 bytes)
  // Base32 representation: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

  const rfcVectors = [
    { t: 59, d8: '94287082', d6: '287082' },
    { t: 1111111109, d8: '07081804', d6: '081804' }, // Leading zero test
    { t: 1111111111, d8: '14050471', d6: '050471' },
    { t: 1234567890, d8: '89005924', d6: '005924' }, // Double leading zero test
    { t: 2000000000, d8: '69279037', d6: '279037' },
    { t: 20000000000, d8: '65353130', d6: '353130' }, // 64-bit timestamp test
  ];

  for (const v of rfcVectors) {
    await asyncTest(`RFC 6238 async generateTOTP: t=${v.t} (8-digit = ${v.d8}, 6-digit = ${v.d6})`, async () => {
      const code8 = await totp.generateTOTP(rfcSecret, { timestamp: v.t, digits: 8 });
      const code6 = await totp.generateTOTP(rfcSecret, { timestamp: v.t, digits: 6 });
      assert.strictEqual(code8, v.d8, `8-digit mismatch at t=${v.t}`);
      assert.strictEqual(code6, v.d6, `6-digit mismatch at t=${v.t}`);
    });

    test(`RFC 6238 sync generateTOTPSync: t=${v.t} (8-digit = ${v.d8}, 6-digit = ${v.d6})`, () => {
      const code8 = totp.generateTOTPSync(rfcSecret, { timestamp: v.t, digits: 8 });
      const code6 = totp.generateTOTPSync(rfcSecret, { timestamp: v.t, digits: 6 });
      assert.strictEqual(code8, v.d8, `8-digit sync mismatch at t=${v.t}`);
      assert.strictEqual(code6, v.d6, `6-digit sync mismatch at t=${v.t}`);
    });
  }

  // ── 3. DUAL-CRYPTO BACKEND PARITY (WEB CRYPTO VS NODE CRYPTO) ────────────
  console.log('\n[Section 3: Dual-Crypto Backend Equivalence]');

  await asyncTest('Web Crypto and Node.js Crypto produce bit-identical results', async () => {
    for (const v of rfcVectors) {
      const nodeCode = await totp.generateTOTP(rfcSecret, {
        timestamp: v.t,
        digits: 6,
        cryptoBackend: 'node'
      });
      const webCode = await totp.generateTOTP(rfcSecret, {
        timestamp: v.t,
        digits: 6,
        cryptoBackend: 'web'
      });
      assert.strictEqual(nodeCode, webCode, `Backend mismatch at t=${v.t}`);
      assert.strictEqual(nodeCode, v.d6);
    }
  });

  // ── 4. CALCULATE TOTP & FORMATTING ───────────────────────────────────────
  console.log('\n[Section 4: calculateTOTP and Token Formatting]');

  await asyncTest('calculateTOTP computes secondsRemaining and progressPercent accurately', async () => {
    // At t=59, 59 % 30 = 29 elapsed. Remaining = 30 - 29 = 1 second. Progress = round(1/30*100) = 3%
    const res59 = await totp.calculateTOTP(rfcSecret, 59);
    assert.strictEqual(res59.token, '287082');
    assert.strictEqual(res59.formattedToken, '287 082');
    assert.strictEqual(res59.secondsRemaining, 1);
    assert.strictEqual(res59.progressPercent, 3);
    assert.strictEqual(res59.valid, true);

    // At t=60, 60 % 30 = 0 elapsed. Remaining = 30 - 0 = 30 seconds. Progress = 100%
    const res60 = await totp.calculateTOTP(rfcSecret, 60);
    assert.strictEqual(res60.secondsRemaining, 30);
    assert.strictEqual(res60.progressPercent, 100);
    assert.strictEqual(res60.valid, true);

    // At t=75, 75 % 30 = 15 elapsed. Remaining = 15 seconds. Progress = 50%
    const res75 = await totp.calculateTOTP(rfcSecret, 75);
    assert.strictEqual(res75.secondsRemaining, 15);
    assert.strictEqual(res75.progressPercent, 50);
  });

  await asyncTest('calculateTOTP handles millisecond timestamps', async () => {
    // Modern timestamp: 1700000000 sec vs 1700000000000 ms
    const resSec = await totp.calculateTOTP(rfcSecret, 1700000000);
    const resMs = await totp.calculateTOTP(rfcSecret, 1700000000000);
    const resDate = await totp.calculateTOTP(rfcSecret, new Date(1700000000000));
    assert.strictEqual(resMs.token, resSec.token);
    assert.strictEqual(resDate.token, resSec.token);
    assert.strictEqual(resMs.secondsRemaining, resSec.secondsRemaining);

    // Explicit isMilliseconds option for small timestamps
    const resSmallMs = await totp.calculateTOTP(rfcSecret, 59000, { isMilliseconds: true });
    assert.strictEqual(resSmallMs.token, '287082');
  });

  await asyncTest('calculateTOTP returns graceful fallback on invalid secret', async () => {
    const invalidRes = await totp.calculateTOTP('INVALID_CHARS_8989');
    assert.strictEqual(invalidRes.valid, false);
    assert.strictEqual(invalidRes.token, '------');
    assert.strictEqual(invalidRes.formattedToken, '--- ---');
    assert.strictEqual(invalidRes.secondsRemaining, 0);
    assert.strictEqual(invalidRes.progressPercent, 0);
    assert.ok(invalidRes.error);
  });

  test('formatToken formats 6-digit and 8-digit codes with visual spacing', () => {
    assert.strictEqual(totp.formatToken('123456'), '123 456');
    assert.strictEqual(totp.formatToken('12345678'), '1234 5678');
    assert.strictEqual(totp.formatToken('123'), '123');
    assert.strictEqual(totp.formatToken(''), '');
  });

  // ── 5. TOTP VERIFICATION & DRIFT WINDOW ───────────────────────────────────
  console.log('\n[Section 5: TOTP Verification and Drift Window]');

  await asyncTest('verifyTOTP confirms valid token at exact step (delta=0)', async () => {
    const token = await totp.generateTOTP(rfcSecret, { timestamp: 59 });
    const verify = await totp.verifyTOTP(token, rfcSecret, { timestamp: 59 });
    assert.strictEqual(verify.valid, true);
    assert.strictEqual(verify.delta, 0);
  });

  await asyncTest('verifyTOTP tolerates clock drift by -1 step (delta=-1)', async () => {
    const token = await totp.generateTOTP(rfcSecret, { timestamp: 59 }); // generated at t=59 (step 1)
    // Server is at t=89 (step 2). Token was generated 1 step in past.
    const verify = await totp.verifyTOTP(token, rfcSecret, { timestamp: 89, window: 1 });
    assert.strictEqual(verify.valid, true);
    assert.strictEqual(verify.delta, -1);
  });

  await asyncTest('verifyTOTP tolerates clock drift by +1 step (delta=+1)', async () => {
    const token = await totp.generateTOTP(rfcSecret, { timestamp: 89 }); // generated at step 2
    // Server is at t=59 (step 1). Token from client running ahead.
    const verify = await totp.verifyTOTP(token, rfcSecret, { timestamp: 59, window: 1 });
    assert.strictEqual(verify.valid, true);
    assert.strictEqual(verify.delta, 1);
  });

  await asyncTest('verifyTOTP rejects token outside drift window', async () => {
    const token = await totp.generateTOTP(rfcSecret, { timestamp: 59 });
    // Server is 3 steps ahead (90 seconds later at t=149)
    const verify = await totp.verifyTOTP(token, rfcSecret, { timestamp: 149, window: 1 });
    assert.strictEqual(verify.valid, false);
    assert.strictEqual(verify.delta, null);
  });

  // ── 6. INTERVAL TICKER MANAGER ───────────────────────────────────────────
  console.log('\n[Section 6: Interval Ticker Manager]');

  await asyncTest('startTOTPTicker starts, ticks immediately, updates, and stops cleanly', async () => {
    let tickCount = 0;
    let lastState = null;

    const ticker = totp.startTOTPTicker(rfcSecret, (state) => {
      tickCount++;
      lastState = state;
    }, { intervalMs: 50 });

    assert.strictEqual(ticker.isRunning(), true);

    // Wait 120ms to allow immediate tick + 2 interval ticks
    await new Promise((r) => setTimeout(r, 120));

    assert.ok(tickCount >= 2, `Expected at least 2 ticks, got ${tickCount}`);
    assert.ok(lastState.valid);
    assert.strictEqual(lastState.token.length, 6);

    // Stop ticker
    ticker.stop();
    assert.strictEqual(ticker.isRunning(), false);

    const countAtStop = tickCount;
    await new Promise((r) => setTimeout(r, 100));
    assert.strictEqual(tickCount, countAtStop, 'Ticker fired callback after stop()');
  });

  // ── 7. BACKWARDS COMPATIBILITY WITH RENDERER APP.JS ──────────────────────
  console.log('\n[Section 7: Backwards Compatibility]');

  await asyncTest('getTOTP matches legacy renderer signature and fallback', async () => {
    const code = await totp.getTOTP(rfcSecret);
    assert.strictEqual(typeof code, 'string');
    assert.strictEqual(code.length, 6);

    const fallback = await totp.getTOTP('INVALID_SECRET');
    assert.strictEqual(fallback, '------');
  });

  test('b32dec alias decodes correctly matching legacy name', () => {
    const dec = totp.b32dec('MY======');
    assert.strictEqual(Buffer.from(dec).toString('utf8'), 'f');
  });

  // ── SUMMARY REPORT ───────────────────────────────────────────────────────
  console.log('\n' + '═'.repeat(75));
  console.log(`TOTAL ASSERTION SUITES: ${passes + failures} | PASSED: ${passes} | FAILED: ${failures}`);
  console.log('═'.repeat(75));

  if (failures > 0) {
    process.exit(1);
  }
})();
