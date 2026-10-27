'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST: AUTOFILL PHASE 1 HEURISTICS, SHORTCUTS & EXTENSION MANAGER
 * test_autofill_heuristics_and_shortcuts.js
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const vm = require('vm');

let passed = 0;
let failed = 0;

function report(name, ok, details = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ [PASS] ${name}${details ? ` (${details})` : ''}`);
  } else {
    failed++;
    console.error(`  ✗ [FAIL] ${name} ${details}`);
  }
}

console.log('═══════════════════════════════════════════════════════════════════════════');
console.log('FUIN TEST: AUTOFILL PHASE 1 (SPLIT LOGIN, SHORTCUTS & IN-APP REGISTRATION)');
console.log('═══════════════════════════════════════════════════════════════════════════\n');

// ── 1. MANIFEST & KEYBOARD SHORTCUT AUDIT ─────────────────────────────────────
console.log('[1. Manifest & Keyboard Shortcut Audit]');

const manifestPath = path.join(__dirname, 'browser-extension/manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

report('1.1 Manifest defines commands.autofill-credential', Boolean(manifest.commands?.['autofill-credential']));
report('1.2 Default shortcut is Ctrl+Shift+L', manifest.commands?.['autofill-credential']?.suggested_key?.default === 'Ctrl+Shift+L');
report('1.3 macOS shortcut is Command+Shift+L', manifest.commands?.['autofill-credential']?.suggested_key?.mac === 'Command+Shift+L');

const bgJs = fs.readFileSync(path.join(__dirname, 'browser-extension/background.js'), 'utf8');
report('1.4 background.js binds chrome.commands listener to fuin-trigger-fill',
  bgJs.includes("command === 'autofill-credential'") && bgJs.includes("{ type: 'fuin-trigger-fill' }"));

// ── 2. SPLIT LOGIN HEURISTICS & SHADOW DOM ───────────────────────────────────
console.log('\n[2. Split Login Heuristics & Shadow DOM Encapsulation]');

const contentJs = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');

report('2.1 content.js implements split-login detection (findStandaloneUsernameFields)',
  contentJs.includes('findStandaloneUsernameFields()'));

report('2.2 content.js inspects username, email, identifier, login attributes',
  contentJs.includes('autocomplete.includes(\'username\')') && contentJs.includes('idNameRegex.test'));

report('2.3 content.js applies Fuin Warm Dark palette tokens (#222019, #3d3830, #5a9a6e)',
  contentJs.includes('#222019') && contentJs.includes('#3d3830') && contentJs.includes('#5a9a6e'));

report('2.4 content.js strictly maintains closed Shadow DOM boundary',
  contentJs.includes("attachShadow({ mode: 'closed' })") && !contentJs.includes("attachShadow({ mode: 'open' })"));

// ── 3. IN-APP CHROME EXTENSION REGISTRATION ──────────────────────────────────
console.log('\n[3. Desktop In-App Extension Manager & Origin Registration]');

const extBridge = require('./main/extensionBridge.js');

// Mock electron app for testing in isolated os.tmpdir
const os = require('os');
const mockSandboxDir = path.join(os.tmpdir(), `fuin-autofill-test-${Date.now()}`);
if (!fs.existsSync(mockSandboxDir)) fs.mkdirSync(mockSandboxDir, { recursive: true });

const mockApp = {
  getPath: (name) => path.join(mockSandboxDir, name),
};

try {
  // Test invalid extension ID formats
  const inv1 = extBridge.registerChromeOrigin(mockApp, '');
  report('3.1 Rejects empty extension ID', inv1.ok === false && inv1.error === 'invalid-id');

  const inv2 = extBridge.registerChromeOrigin(mockApp, 'ABCDEF');
  report('3.2 Rejects short or uppercase extension ID', inv2.ok === false && inv2.error === 'invalid-format');

  const inv3 = extBridge.registerChromeOrigin(mockApp, '12345678901234567890123456789012');
  report('3.3 Rejects non-alphabetic characters (outside a-p)', inv3.ok === false && inv3.error === 'invalid-format');

  // Test valid 32-char extension ID
  const validId = 'abcdefghijklmnopabcdefghijklmnop';
  const regRes = extBridge.registerChromeOrigin(mockApp, validId);
  report('3.4 Successfully registers valid 32-char extension ID', regRes.ok === true && regRes.origin === `chrome-extension://${validId}/`);

  const known = extBridge.getKnownExtensionIds(mockApp);
  report('3.5 getKnownExtensionIds loads persistent registered origin', known.chromeOrigins.includes(`chrome-extension://${validId}/`));
} finally {
  try {
    fs.rmSync(mockSandboxDir, { recursive: true, force: true });
  } catch {}
}

console.log('\n═══════════════════════════════════════════════════════════════════════════');
console.log(`TOTAL AUDIT CHECKS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
console.log('═══════════════════════════════════════════════════════════════════════════');

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\nALL AUTOFILL PHASE 1 SPECIFICATION CHECKS PASSED CLEANLY!\n');
  process.exit(0);
}
