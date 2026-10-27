'use strict';

const assert = require('assert');
const crypto = require('crypto');

const {
  generatePassword,
  calculatePasswordStrength,
  getCharset,
  CHARSETS,
  DEFAULT_OPTIONS,
  SCORE_LABELS,
  SCORE_LEVELS,
  SCORE_PERCENTS
} = require('./services/passwordGenerator');

console.log('═'.repeat(75));
console.log('FUIN TEST: CSPRNG PASSWORD GENERATOR & STRENGTH ENGINE');
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
    console.error(`    ${err.stack || err.message}`);
    failures++;
  }
}

// ── 1. MODULE & API EXPORTS ─────────────────────────────────────────
console.log('\n[Suite 1: Module Exports & API Signatures]');

test('Exported methods and constants exist and have correct types', () => {
  assert.strictEqual(typeof generatePassword, 'function');
  assert.strictEqual(typeof calculatePasswordStrength, 'function');
  assert.strictEqual(typeof getCharset, 'function');
  assert.strictEqual(typeof CHARSETS, 'object');
  assert.strictEqual(typeof DEFAULT_OPTIONS, 'object');
  assert.strictEqual(Array.isArray(SCORE_LABELS), true);
  assert.strictEqual(SCORE_LABELS.length, 5);
  assert.strictEqual(SCORE_LEVELS.length, 5);
});

// ── 2. CHARSET CONSTRUCTOR & FILTERING ──────────────────────────────
console.log('\n[Suite 2: Charset Construction & Exclusion]');

test('Default options produce 84 unique characters with similar excluded', () => {
  const charset = getCharset();
  assert.strictEqual(charset.length, 84);
  const similarChars = 'il1Lo0O'.split('');
  for (const c of similarChars) {
    assert.strictEqual(charset.includes(c), false, `Charset should not include similar char '${c}'`);
  }
});

test('excludeSimilar: false produces full 91-character pool', () => {
  const charset = getCharset({ excludeSimilar: false });
  assert.strictEqual(charset.length, 91);
  const similarChars = 'il1Lo0O'.split('');
  for (const c of similarChars) {
    assert.strictEqual(charset.includes(c), true, `Charset should include similar char '${c}'`);
  }
});

test('Individual pool selections work as expected', () => {
  const upperOnly = getCharset({ includeUpper: true, includeLower: false, includeDigits: false, includeSymbols: false, excludeSimilar: false });
  assert.strictEqual(upperOnly, CHARSETS.upper);
  assert.strictEqual(upperOnly.length, 26);

  const digitsOnly = getCharset({ includeUpper: false, includeLower: false, includeDigits: true, includeSymbols: false, excludeSimilar: true });
  assert.strictEqual(digitsOnly.length, 8);
  assert.strictEqual(digitsOnly.includes('1'), false);
  assert.strictEqual(digitsOnly.includes('0'), false);

  const symsOnly = getCharset({ includeUpper: false, includeLower: false, includeDigits: false, includeSymbols: true });
  assert.strictEqual(symsOnly, CHARSETS.symbols);
  assert.strictEqual(symsOnly.length, 29);
});

test('Custom charset is deduplicated and respected', () => {
  const customOnly = getCharset({
    includeUpper: false,
    includeLower: false,
    includeDigits: false,
    includeSymbols: false,
    customCharset: 'ABCABC123!@#!@#'
  });
  assert.strictEqual(customOnly, 'ABC23!@#');

  const customNoFilter = getCharset({
    includeUpper: false,
    includeLower: false,
    includeDigits: false,
    includeSymbols: false,
    excludeSimilar: false,
    customCharset: 'ABCABC123!@#'
  });
  assert.strictEqual(customNoFilter, 'ABC123!@#');
});

test('All pools disabled returns empty string', () => {
  const empty = getCharset({
    includeUpper: false,
    includeLower: false,
    includeDigits: false,
    includeSymbols: false
  });
  assert.strictEqual(empty, '');
});

// ── 3. REJECTION SAMPLING & MATHEMATICAL UNIFORMITY ─────────────────
console.log('\n[Suite 3: Rejection Sampling & Modulo Bias Verification]');

test('Rejection threshold maxValid is an exact multiple of charset.length', () => {
  for (let N = 2; N <= 128; N++) {
    const totalSpace = 0x100000000; // 4294967296
    const maxValid = totalSpace - (totalSpace % N);
    assert.strictEqual(maxValid % N, 0, `maxValid must be exact multiple of ${N}`);
    assert.strictEqual(maxValid <= totalSpace, true);
    assert.strictEqual(totalSpace - maxValid < N, true, `Discarded range must be strictly < ${N}`);
  }
});

test('Empirical Chi-Square Goodness-of-Fit uniformity test (N=10, 50,000 samples)', () => {
  const N = 10;
  const SAMPLES = 50000;
  const expectedPerBucket = SAMPLES / N;

  const counts = new Array(N).fill(0);
  const genResult = generatePassword({
    length: SAMPLES,
    includeUpper: false,
    includeLower: false,
    includeDigits: true,
    includeSymbols: false,
    excludeSimilar: false
  });

  const pwd = genResult.password;
  assert.strictEqual(pwd.length, SAMPLES);

  for (let i = 0; i < SAMPLES; i++) {
    const digit = parseInt(pwd[i], 10);
    counts[digit]++;
  }

  let chiSquare = 0;
  for (let i = 0; i < N; i++) {
    const diff = counts[i] - expectedPerBucket;
    chiSquare += (diff * diff) / expectedPerBucket;
  }

  console.log(`    Chi-Square stat: ${chiSquare.toFixed(2)} (critical threshold at p=0.001 is 27.88)`);
  assert.strictEqual(chiSquare < 27.88, true, `Chi-square value ${chiSquare} exceeds critical threshold`);
});

// ── 4. DUAL CRYPTO SUPPORT ──────────────────────────────────────────
console.log('\n[Suite 4: Dual Crypto Provider Abstraction]');

test('Default crypto uses Node crypto or Web Crypto successfully', () => {
  const res = generatePassword(20);
  assert.strictEqual(res.password.length, 20);
  assert.strictEqual(typeof res.password, 'string');
});

test('Mock Web Crypto (getRandomValues) works seamlessly', () => {
  let webCryptoCalled = false;
  const mockWebCrypto = {
    getRandomValues: function (arr) {
      webCryptoCalled = true;
      crypto.getRandomValues(arr);
      return arr;
    }
  };

  const res = generatePassword({ length: 16, crypto: mockWebCrypto });
  assert.strictEqual(webCryptoCalled, true);
  assert.strictEqual(res.password.length, 16);
});

test('Deterministic mock crypto generates predictable output', () => {
  const cannedBytes = Buffer.alloc(256);
  for (let i = 0; i < 256; i++) cannedBytes[i] = i % 256;

  const mockCrypto = {
    randomBytes: (n) => Buffer.from(cannedBytes.subarray(0, n))
  };

  const res1 = generatePassword({ length: 8, crypto: mockCrypto });
  const res2 = generatePassword({ length: 8, crypto: mockCrypto });
  assert.strictEqual(res1.password, res2.password, 'Identical crypto stream must produce identical password');
});

// ── 5. BOUNDARY CONDITIONS & ALIASES ────────────────────────────────
console.log('\n[Suite 5: Boundary Conditions & Option Aliases]');

test('Length 0 or negative returns empty password object', () => {
  const zero = generatePassword(0);
  assert.strictEqual(zero.password, '');
  assert.strictEqual(zero.score, 0);

  const neg = generatePassword(-5);
  assert.strictEqual(neg.password, '');
});

test('No charsets selected returns empty password object', () => {
  const empty = generatePassword({
    includeUpper: false,
    includeLower: false,
    includeDigits: false,
    includeSymbols: false
  });
  assert.strictEqual(empty.password, '');
  assert.strictEqual(empty.score, 0);
});

test('Desktop option aliases (len, useUpper, useNum, useSym, exc) are recognized', () => {
  const res = generatePassword({
    len: 24,
    useUpper: false,
    useLower: true,
    useNum: false,
    useSym: false,
    exc: false
  });
  assert.strictEqual(res.password.length, 24);
  assert.strictEqual(/^[a-z]+$/.test(res.password), true);
});

test('Mobile option aliases (useNumbers, useSymbols, excludeSimilar) are recognized', () => {
  const res = generatePassword({
    length: 18,
    useUpper: true,
    useLower: false,
    useNumbers: true,
    useSymbols: false,
    excludeSimilar: true
  });
  assert.strictEqual(res.password.length, 18);
  assert.strictEqual(/^[A-Z0-9]+$/.test(res.password), true);
  assert.strictEqual(res.password.includes('1'), false);
  assert.strictEqual(res.password.includes('0'), false);
});

test('toString() method allows direct string coercion', () => {
  const res = generatePassword(12);
  assert.strictEqual(`${res}`, res.password);
  assert.strictEqual(String(res), res.password);
});

test('Diversity enforcement (ensureDiversity) guarantees character from each active pool', () => {
  for (let run = 0; run < 20; run++) {
    const res = generatePassword({
      length: 8,
      includeUpper: true,
      includeLower: true,
      includeDigits: true,
      includeSymbols: true,
      ensureDiversity: true
    });
    const pwd = res.password;
    assert.strictEqual(/[A-Z]/.test(pwd), true);
    assert.strictEqual(/[a-z]/.test(pwd), true);
    assert.strictEqual(/[0-9]/.test(pwd), true);
    assert.strictEqual(/[^A-Za-z0-9]/.test(pwd), true);
  }
});

// ── 6. PASSWORD STRENGTH CALCULATION ────────────────────────────────
console.log('\n[Suite 6: Multi-Factor Strength Scoring]');

test('Empty or null password evaluates to score 0', () => {
  const empty = calculatePasswordStrength('');
  assert.strictEqual(empty.score, 0);
  assert.strictEqual(empty.entropy, 0);
  assert.strictEqual(empty.level, 'veryWeak');
});

test('Short or single-class passwords are scored low', () => {
  const short = calculatePasswordStrength('Ab1!');
  assert.strictEqual(short.score, 0);

  const digits = calculatePasswordStrength('1234567890');
  assert.strictEqual(digits.score <= 1, true);
  assert.strictEqual(digits.warning, 'Digits only');

  const rep = calculatePasswordStrength('aaaaaaaaaaaaaaaa');
  assert.strictEqual(rep.score, 0);
  assert.strictEqual(rep.warning, 'Repeated identical characters');
});

test('Standard strong passwords reach score 4 (veryStrong, 100%)', () => {
  const strong = calculatePasswordStrength('k!9#vB7$mZ2@qP4%');
  assert.strictEqual(strong.score, 4);
  assert.strictEqual(strong.percent, 100);
  assert.strictEqual(strong.level, 'veryStrong');
  assert.strictEqual(strong.label, 'Very Strong');
  assert.strictEqual(strong.entropy > 85, true);
});

test('Strength levels match 5-tier thresholds', () => {
  const weak = calculatePasswordStrength('abc123');
  assert.strictEqual(weak.score <= 1, true);

  const medium = calculatePasswordStrength('Elephant42');
  assert.strictEqual(medium.score >= 1 && medium.score <= 3, true);

  const veryStrong = calculatePasswordStrength('X#9mK$2vL@8qZ*4w');
  assert.strictEqual(veryStrong.score, 4);
});

test('Bitwarden / zxcvbn pattern deductions penalize keyboard walks, sequences, and dictionary stems', () => {
  const random12 = calculatePasswordStrength('v9#mK2$pQ7!z');
  const walk12 = calculatePasswordStrength('qwerty123456');
  const leetDict = calculatePasswordStrength('P@ssw0rd2024!');

  assert.strictEqual(walk12.entropy < random12.entropy, true, 'Keyboard/sequential walk must have lower effective entropy than random string');
  assert.strictEqual(walk12.score <= 2, true, 'qwerty123456 should not be scored strong');
  assert.strictEqual(leetDict.entropy < random12.entropy, true, 'L33t dictionary + year pattern must be penalized');
  assert.strictEqual(typeof random12.crackTime, 'string');
  assert.strictEqual(typeof random12.crackTimeTr, 'string');
  assert.strictEqual(typeof random12.guessesLog10, 'number');
});

test('Long single-class random passphrases are not falsely capped at Weak/Medium', () => {
  const longLower = calculatePasswordStrength('correcthorsebatterystaple');
  assert.strictEqual(longLower.entropy > 80, true);
  assert.strictEqual(longLower.score >= 3, true);
});

console.log('\n' + '═'.repeat(75));
console.log(`TOTAL PASSES: ${passes}`);
console.log(`TOTAL FAILURES: ${failures}`);
console.log('═'.repeat(75));

if (failures > 0) {
  process.exit(1);
}
