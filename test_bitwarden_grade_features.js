'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

console.log('═'.repeat(75));
console.log('FUIN TEST: BITWARDEN-GRADE SECURITY HARDENING FEATURES');
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

// ── 1. Constant-Time Reprompt Verification ─────────────────────────
function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const charA = i < a.length ? a.charCodeAt(i) : 0;
    const charB = i < b.length ? b.charCodeAt(i) : 0;
    diff |= charA ^ charB;
  }
  return diff === 0;
}

test('1. Constant-time reprompt comparison matches exact master password', () => {
  assert.strictEqual(constantTimeEqual('MyMasterPass123!', 'MyMasterPass123!'), true);
  assert.strictEqual(constantTimeEqual('', ''), true);
  assert.strictEqual(constantTimeEqual('Short', 'Shorter'), false);
  assert.strictEqual(constantTimeEqual('MyMasterPass123!', 'MyMasterPass123?'), false);
  assert.strictEqual(constantTimeEqual('Pass', null), false);
  assert.strictEqual(constantTimeEqual(undefined, 'Pass'), false);
  assert.strictEqual(constantTimeEqual('Password123', 'password123'), false);
});

// ── 2. Password Revision History Mechanics ────────────────────────
test('2. Password revision history records up to 5 previous passwords', () => {
  let entry = {
    id: 'entry-1',
    site: 'GitHub',
    password: 'v1-InitialPassword',
    history: []
  };

  function updatePassword(entryObj, newPassword) {
    let history = Array.isArray(entryObj.history) ? [...entryObj.history] : [];
    if (entryObj.password && entryObj.password !== newPassword) {
      history.unshift({
        password: entryObj.password,
        date: Date.now()
      });
      if (history.length > 5) history = history.slice(0, 5);
    }
    return {
      ...entryObj,
      password: newPassword,
      history
    };
  }

  // Same password -> no history entry added
  entry = updatePassword(entry, 'v1-InitialPassword');
  assert.strictEqual(entry.history.length, 0);

  // Password update 1
  entry = updatePassword(entry, 'v2-SecondPassword');
  assert.strictEqual(entry.history.length, 1);
  assert.strictEqual(entry.history[0].password, 'v1-InitialPassword');

  // Password update 2..6 (exceeding 5)
  entry = updatePassword(entry, 'v3-ThirdPassword');
  entry = updatePassword(entry, 'v4-FourthPassword');
  entry = updatePassword(entry, 'v5-FifthPassword');
  entry = updatePassword(entry, 'v6-SixthPassword');
  assert.strictEqual(entry.history.length, 5);
  assert.strictEqual(entry.history[0].password, 'v5-FifthPassword');

  entry = updatePassword(entry, 'v7-SeventhPassword');
  assert.strictEqual(entry.history.length, 5, 'History must be capped at 5');
  assert.strictEqual(entry.history[0].password, 'v6-SixthPassword');
  assert.strictEqual(entry.history[4].password, 'v2-SecondPassword');
  // v1 was pushed out
  assert.strictEqual(entry.history.some(h => h.password === 'v1-InitialPassword'), false);
});

// ── 3. Insecure HTTP URL Detection ─────────────────────────────────
test('3. Insecure HTTP connection detector accurately identifies plain-text URLs', () => {
  const isInsecureHttp = (url) => typeof url === 'string' && /^http:\/\//i.test(url.trim());

  assert.strictEqual(isInsecureHttp('http://example.com'), true);
  assert.strictEqual(isInsecureHttp('HTTP://INSECURE-BANK.COM/LOGIN'), true);
  assert.strictEqual(isInsecureHttp('  http://spaced.org  '), true);
  assert.strictEqual(isInsecureHttp('http://192.168.1.1:8080'), true);

  assert.strictEqual(isInsecureHttp('https://secure.com'), false);
  assert.strictEqual(isInsecureHttp('HTTPS://SECURE-BANK.COM'), false);
  assert.strictEqual(isInsecureHttp('ftp://ftp.example.com'), false);
  assert.strictEqual(isInsecureHttp('example.com'), false);
  assert.strictEqual(isInsecureHttp(''), false);
  assert.strictEqual(isInsecureHttp(null), false);
  assert.strictEqual(isInsecureHttp(undefined), false);
});

// ── 4. Emergency Kit HTML Generator ────────────────────────────────
test('4. Emergency Kit HTML generator creates offline-ready, print-friendly disaster kit', () => {
  const appJsPath = path.join(__dirname, 'renderer', 'app.js');
  const appJsContent = fs.readFileSync(appJsPath, 'utf8');

  // Verify generateEmergencyKitHtml function is present in app.js
  assert.ok(appJsContent.includes('function generateEmergencyKitHtml'), 'generateEmergencyKitHtml must exist in app.js');
  assert.ok(appJsContent.includes('exportEmergencyKit'), 'exportEmergencyKit must exist in app.js');

  // Extract and execute generateEmergencyKitHtml logic
  const match = appJsContent.match(/function generateEmergencyKitHtml\([^)]*\)\s*\{[\s\S]*?\n\}/);
  assert.ok(match, 'Must match generateEmergencyKitHtml implementation');

  const recoveryKey = 'A1B2C3D4-E5F67890-12345678-ABCDEF01-23456789-ABCDEF12-34567890-ABCDEF12';
  const dateStr = '2026-10-26 11:20:00';

  // Test generator directly
  const fn = new Function('recoveryKey', 'dateStr', `
    const document = { documentElement: { lang: 'tr' } };
    ${match[0]}
    return generateEmergencyKitHtml(recoveryKey, dateStr);
  `);

  const html = fn(recoveryKey, dateStr);
  assert.ok(html.includes('<!DOCTYPE html>'), 'Must produce standard DOCTYPE');
  assert.ok(html.includes(recoveryKey), 'Must contain recovery key');
  assert.ok(html.includes(dateStr), 'Must contain export date');
  assert.ok(html.includes('@media print'), 'Must include print media stylesheet');
  assert.ok(html.includes('FUIN'), 'Must include Fuin branding');
  assert.ok(html.includes('ANA ŞİFRE'), 'Must include Master Password handwriting section');
  assert.ok(!html.includes('http://'), 'Must not link unencrypted external resources');
  assert.ok(!html.includes('<script src='), 'Must be zero external scripts (offline-safe)');
});

// ── 5. UI Markup & Translation Integrity ───────────────────────────
test('5. Translation files contain all required Bitwarden-grade security keys in TR and EN', () => {
  const i18nDesktop = fs.readFileSync(path.join(__dirname, 'renderer', 'i18n.js'), 'utf8');
  const i18nMobile = fs.readFileSync(path.join(__dirname, '..', 'FuinMobile', 'src', 'i18n.js'), 'utf8');

  const requiredKeys = [
    'toggleRepromptLabel',
    'toggleRepromptSub',
    'badgeReprompt',
    'warnInsecureHttp',
    'btnPwHistory',
    'pwHistoryTitle',
    'pwHistoryEmpty',
    'pwHistoryCopied',
    'btnCopy'
  ];

  for (const k of requiredKeys) {
    assert.ok(i18nDesktop.includes(k), `Desktop i18n must include ${k}`);
    assert.ok(i18nMobile.includes(k), `Mobile i18n must include ${k}`);
  }
});

// ── 6. HTML & CSS Integration ──────────────────────────────────────
test('6. Desktop index.html and style.css contain reprompt and history UI structures', () => {
  const html = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, 'renderer', 'style.css'), 'utf8');

  assert.ok(html.includes('id="repromptOverlay"'), 'index.html must have repromptOverlay');
  assert.ok(html.includes('id="pwHistoryOverlay"'), 'index.html must have pwHistoryOverlay');
  assert.ok(html.includes('id="f-reprompt"'), 'index.html must have f-reprompt toggle');
  assert.ok(html.includes('id="btnDownloadEmergencyKit"'), 'index.html must have btnDownloadEmergencyKit');

  assert.ok(css.includes('.reprompt-badge'), 'style.css must have .reprompt-badge');
  assert.ok(css.includes('.insecure-http-badge'), 'style.css must have .insecure-http-badge');
  assert.ok(css.includes('.pw-history-item'), 'style.css must have .pw-history-item');
});

console.log('═'.repeat(75));
console.log(`TOTAL PASSES: ${passes}`);
console.log(`TOTAL FAILURES: ${failures}`);
console.log('═'.repeat(75));

if (failures > 0) process.exit(1);
