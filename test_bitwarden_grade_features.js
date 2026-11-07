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

test('1.1. verifyReprompt executes callback when master password matches and clears action', () => {
  let master = 'correct-password';
  let repromptPendingAction = null;
  let actionExecuted = false;
  let modalClosed = false;

  function closeRepromptModal() {
    modalClosed = true;
  }

  function verifyReprompt(inputVal) {
    if (constantTimeEqual(inputVal, master)) {
      const action = repromptPendingAction;
      repromptPendingAction = null;
      closeRepromptModal();
      if (typeof action === 'function') {
        action();
      }
    }
  }

  // Set action
  repromptPendingAction = () => { actionExecuted = true; };

  // Wrong password -> should not execute
  verifyReprompt('wrong-password');
  assert.strictEqual(actionExecuted, false);
  assert.strictEqual(modalClosed, false);
  assert.ok(repromptPendingAction !== null);

  // Correct password -> should execute and clear
  verifyReprompt('correct-password');
  assert.strictEqual(actionExecuted, true);
  assert.strictEqual(modalClosed, true);
  assert.strictEqual(repromptPendingAction, null);
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
  const i18nMobilePath = path.join(__dirname, '..', 'FuinMobile', 'src', 'i18n.js');
  const hasMobile = fs.existsSync(i18nMobilePath);
  const i18nMobile = hasMobile ? fs.readFileSync(i18nMobilePath, 'utf8') : null;

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
    if (hasMobile) {
      assert.ok(i18nMobile.includes(k), `Mobile i18n must include ${k}`);
    }
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

// ── 7. API, Reprompt, XSS & Pipe Security Regression Guard ─────────
test('7. API boundaries, TOTP reprompt, Emergency Kit escaping, and extension pipe hardening', () => {
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');
  const updateMgr = fs.readFileSync(path.join(__dirname, 'renderer', 'modules', 'updateManager.js'), 'utf8');
  const healthScan = fs.readFileSync(path.join(__dirname, 'renderer', 'modules', 'healthScanner.js'), 'utf8');
  const extBridge = fs.readFileSync(path.join(__dirname, 'main', 'extensionBridge.js'), 'utf8');
  const nativeHost = fs.readFileSync(path.join(__dirname, 'native-host', 'host.js'), 'utf8');

  // Emergency Kit XSS escaping check
  const match = appJs.match(/function generateEmergencyKitHtml\([^)]*\)\s*\{[\s\S]*?\n\}/);
  const fn = new Function('recoveryKey', 'dateStr', `
    const document = { documentElement: { lang: 'tr' } };
    ${match[0]}
    return generateEmergencyKitHtml(recoveryKey, dateStr);
  `);
  const xssHtml = fn('<img src=x onerror=alert(1)>', '<script>evil()</script>');
  assert.ok(!xssHtml.includes('<img src=x'), 'Emergency Kit must escape HTML tags in recoveryKey');
  assert.ok(!xssHtml.includes('<script>evil()'), 'Emergency Kit must escape HTML tags in dateStr');

  // TOTP reprompt & secure generator copy check
  assert.ok(
    /async function showTOTP\(id,\s*force\s*=\s*false\)[\s\S]{0,220}requireReprompt/.test(appJs),
    'showTOTP must enforce requireReprompt on reprompt-protected entries'
  );
  assert.ok(!appJs.includes('copyToClipboard('), 'app.js must use copySecure instead of non-existent copyToClipboard');

  // External API hardening (GitHub Releases & HIBP k-Anonymity)
  assert.ok(updateMgr.includes("redirect: 'error'"), 'updateManager must disallow HTTP redirects');
  assert.ok(updateMgr.includes('AbortController'), 'updateManager must enforce fetch timeout');
  assert.ok(updateMgr.includes("parsed.hostname === 'github.com'") && updateMgr.includes("parsed.pathname.startsWith('/Sombooo/Fuin/')"), 'updateManager must strictly validate Sombooo/Fuin release URLs');
  assert.ok(healthScan.includes("redirect: 'error'"), 'healthScanner must disallow HTTP redirects');
  assert.ok(healthScan.includes('HIBP_MAX_RESPONSE_CHARS'), 'healthScanner must bound HIBP response size');

  // Extension bridge & native host pipe anti-squatting parity
  assert.ok(extBridge.includes('fuin-win32-pipe-v1'), 'extensionBridge must derive per-token HMAC Windows pipe name');
  assert.ok(nativeHost.includes('fuin-win32-pipe-v1'), 'native-host must derive matching HMAC Windows pipe name');
  assert.ok(extBridge.includes('getKnownExtensionIds(app)'), 'autoInstallNativeMessagingHosts must pass app to getKnownExtensionIds');
});

// ── 8. In-App Updates, Setting Controls & Clean UI Branding Verification ─────────
test('8. In-app update settings, asset resolver, download validation & clean UI', () => {
  const i18nJs = fs.readFileSync(path.join(__dirname, 'renderer', 'i18n.js'), 'utf8');
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const updateMgr = require('./renderer/modules/updateManager.js');
  const mainJs = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

  // 8.1 No third-party corporate mentions in autofill UI
  assert.ok(!indexHtml.includes('Bitwarden gibi'), 'index.html must not mention Bitwarden in autofill settings');
  assert.ok(!i18nJs.includes('Bitwarden gibi'), 'i18n.js must not mention Bitwarden in autofill translations');
  assert.ok(indexHtml.includes('kesintisiz doldurur'), 'index.html must use seamless autofill wording');

  // 8.2 In-app update setting toggle presence
  assert.ok(indexHtml.includes('id="toggleAutoUpdateCheck"'), 'index.html must include toggleAutoUpdateCheck');
  assert.ok(typeof updateMgr.isAutoUpdateCheckEnabled === 'function', 'updateManager must export isAutoUpdateCheckEnabled');

  // 8.3 Download URL validation strictly enforces official GitHub release origin
  assert.ok(updateMgr.isTrustedFuinDownloadUrl('https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-1.0.0.dmg'));
  assert.ok(!updateMgr.isTrustedFuinDownloadUrl('https://evil.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin.dmg'));
  assert.ok(!updateMgr.isTrustedFuinDownloadUrl('http://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin.dmg'));
  assert.ok(!updateMgr.isTrustedFuinDownloadUrl('https://github.com/OtherUser/Fuin/releases/download/v1.0.0/Fuin.dmg'));

  // 8.4 Platform asset finder
  const dummyRelease = {
    assets: [
      { name: 'Fuin-1.0.0.dmg', browser_download_url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-1.0.0.dmg' },
      { name: 'Fuin-Setup-1.0.0.exe', browser_download_url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-Setup-1.0.0.exe' },
      { name: 'Fuin-1.0.0.AppImage', browser_download_url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0/Fuin-1.0.0.AppImage' }
    ]
  };
  const matchedAsset = updateMgr.findPlatformAsset(dummyRelease);
  assert.ok(matchedAsset, 'findPlatformAsset must locate an installer asset');
  assert.ok(matchedAsset.browser_download_url.startsWith('https://github.com/Sombooo/Fuin/releases/download/'));

  // 8.5 Security hardening in main.js
  assert.ok(mainJs.includes('setPermissionRequestHandler'), 'main.js must handle session permission requests');
  assert.ok(mainJs.includes('setPermissionCheckHandler'), 'main.js must deny session permission checks');
  assert.ok(mainJs.includes('will-attach-webview'), 'main.js must prevent unauthorized webview attachment');
  assert.ok(mainJs.includes("ipcMain.handle('download-update'"), 'main.js must provide secure download-update IPC');
  assert.ok(mainJs.includes("ipcMain.handle('install-update'"), 'main.js must provide secure install-update IPC');
  assert.ok(mainJs.includes("finalUrl.hostname.endsWith('.githubusercontent.com')"), 'main.js must permit GitHub release assets CDN');
  assert.ok(mainJs.includes("finalUrl.hostname.endsWith('.blob.core.windows.net')"), 'main.js must permit GitHub Azure blob backend');
});

// ── 9. Recovery Key Self-Test & Backup History DOM/IPC Parity ───────────────
test('9. Recovery Key Self-Test & Backup History DOM IDs and IPC response keys match across HTML, renderer, and main', () => {
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');
  const mainJs = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

  // Verify Recovery Key modal DOM IDs exist in index.html and are referenced in app.js
  for (const id of ['verifyRecoveryOverlay', 'verifyRecoveryInp', 'verifyRecoveryMsg', 'btnConfirmVerifyRecovery']) {
    assert.ok(indexHtml.includes(`id="${id}"`), `index.html must include #${id}`);
    assert.ok(appJs.includes(`'${id}'`), `app.js must reference #${id}`);
  }

  // Verify Backup History modal DOM IDs exist in index.html and are referenced in app.js
  for (const id of ['backupHistoryOverlay', 'backupHistoryList', 'backupAutoHealBanner', 'backupSummaryBadge', 'btnCreateBackupNow', 'btnOpenBackupHistory']) {
    assert.ok(indexHtml.includes(`id="${id}"`), `index.html must include #${id}`);
    assert.ok(appJs.includes(`'${id}'`), `app.js must reference #${id}`);
  }

  // Verify main.js listVaultBackups returns both backups and snapshots arrays and file/filename properties
  assert.ok(mainJs.includes('backups: files') && mainJs.includes('snapshots: files'), 'main.js listVaultBackups must provide backups and snapshots arrays');
  assert.ok(appJs.includes('extractSnapshotsFromResponse'), 'app.js must extract snapshots from getBackupList response');
});

console.log('═'.repeat(75));
console.log(`TOTAL PASSES: ${passes}`);
console.log(`TOTAL FAILURES: ${failures}`);
console.log('═'.repeat(75));

if (failures > 0) process.exit(1);
