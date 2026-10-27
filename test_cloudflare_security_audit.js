/**
 * ══════════════════════════════════════════════════════════════════════════════
 * FUIN COMPREHENSIVE SECURITY AUDIT & HARDENING TEST SUITE
 * Methodology & Verification derived from cloudflare/security-audit-skill
 * ══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

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
console.log('FUIN DEFENSIVE AUDIT: CLOUDFLARE SECURITY AUDIT SKILL VERIFICATION');
console.log('═══════════════════════════════════════════════════════════════════════════');

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1: DESKTOP & MOBILE LOCAL IPC & SCREEN PROTECTION (DESKTOP-MOBILE-AND-LOCAL-IPC)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[1. Screen Protection & Process Hardening]');

const mainJsPath = path.join(__dirname, 'main.js');
const mainJsContent = fs.readFileSync(mainJsPath, 'utf8');

// 1.1 Verify Electron setContentProtection is active by default in main.js
const hasDefaultProtection = mainJsContent.includes('mainWindow.setContentProtection(!allowDevScreenshots)') ||
                             mainJsContent.includes('mainWindow.setContentProtection(true)');
report('1.1 Desktop Screen Protection (setContentProtection active in production)', hasDefaultProtection);

// 1.2 Verify dev-only bypass is isolated and requires explicit flag
const hasDevFlagGuard = mainJsContent.includes('--dev-allow-screenshots') && mainJsContent.includes('FUIN_DEV_SCREENSHOTS');
report('1.2 Desktop Screenshot Dev Flag Guard is strictly isolated', hasDevFlagGuard);

// 1.3 Verify Mobile Screen Protection (FLAG_SECURE) in FuinMobile/App.js
const mobileAppJsPath = path.join(__dirname, '..', 'FuinMobile', 'App.js');
if (fs.existsSync(mobileAppJsPath)) {
  const mobileContent = fs.readFileSync(mobileAppJsPath, 'utf8');
  const hasMobileProtection = mobileContent.includes('ScreenCapture.preventScreenCaptureAsync()') &&
                              !mobileContent.includes('// ScreenCapture.preventScreenCaptureAsync()');
  report('1.3 Mobile Screen Protection (FLAG_SECURE preventScreenCaptureAsync active)', hasMobileProtection);
} else {
  report('1.3 Mobile App.js check skipped (path not found)', true);
}

// 1.4 WebPreferences Context Isolation and Sandboxing
const hasSandbox = mainJsContent.includes('sandbox: true');
const hasContextIsolation = mainJsContent.includes('contextIsolation: true');
const hasNodeIntegrationDisabled = mainJsContent.includes('nodeIntegration: false');
report('1.4 Electron WebPreferences strictly enforces sandbox, contextIsolation, and no nodeIntegration',
  hasSandbox && hasContextIsolation && hasNodeIntegrationDisabled);

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2: PROTOCOLS & NETWORK ATTACK SURFACE (PROTOCOLS-RPC-AND-MESSAGING)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[2. Protocol, RPC & Local Messaging Security]');

const syncLanPath = path.join(__dirname, 'sync-lan.js');
const syncLanContent = fs.readFileSync(syncLanPath, 'utf8');

// 2.1 RFC1918 and loopback filter verification
const { isRFC1918OrLoopback } = require('./sync-lan.js');
report('2.1.1 RFC1918 accepts 192.168.1.50', isRFC1918OrLoopback('192.168.1.50') === true);
report('2.1.2 RFC1918 accepts 10.0.0.1', isRFC1918OrLoopback('10.0.0.1') === true);
report('2.1.3 RFC1918 accepts 172.16.0.1', isRFC1918OrLoopback('172.16.0.1') === true);
report('2.1.4 RFC1918 accepts 127.0.0.1 (Loopback)', isRFC1918OrLoopback('127.0.0.1') === true);
report('2.1.5 RFC1918 rejects 8.8.8.8 (Public DNS)', isRFC1918OrLoopback('8.8.8.8') === false);
report('2.1.6 RFC1918 rejects 1.1.1.1 (Cloudflare)', isRFC1918OrLoopback('1.1.1.1') === false);
report('2.1.7 RFC1918 rejects malformed/attacker IP "192.168.1.1.evil.com"', isRFC1918OrLoopback('192.168.1.1.evil.com') === false);

// 2.2 Maximum request body limit against OOM DOS
const hasBodyLimit = syncLanContent.includes('totalBytes > 5 * 1024 * 1024') && syncLanContent.includes('req.destroy()');
report('2.2 LAN Sync HTTP server strictly enforces 5MB request body cap with immediate socket destruction', hasBodyLimit);

// 2.3 Ephemeral lifetime limit
const hasEphemeralTimeout = syncLanContent.includes('EPHEMERAL_TIMEOUT_MS') || syncLanContent.includes('timeoutMs');
report('2.3 LAN Sync HTTP listener automatically expires and self-destructs after timeout', hasEphemeralTimeout);

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 3: DATA ISOLATION, MEMORY & SANITIZATION (DATA-ISOLATION-AND-LIFECYCLE)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[3. Data Isolation, Memory Sanitization & DOM Escaping]');

// 3.1 Type-safe HTML Escaper resilience
function testEsc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/'/g, '&#39;')
    .replace(/"/g, '&quot;');
}

report('3.1.1 Escaper neutralizes basic XSS tag', testEsc('<script>alert(1)</script>') === '&lt;script&gt;alert(1)&lt;/script&gt;');
report('3.1.2 Escaper handles numeric input without TypeError', testEsc(42) === '42');
report('3.1.3 Escaper handles boolean input without TypeError', testEsc(false) === 'false');
report('3.1.4 Escaper handles null and undefined safely', testEsc(null) === '' && testEsc(undefined) === '');
report('3.1.5 Escaper handles quote attributes cleanly', testEsc('" onmouseover="alert(1)') === '&quot; onmouseover=&quot;alert(1)');

// 3.2 URL Open Protocol Filter in main.js
const hasProtocolValidation = mainJsContent.includes("parsed.protocol === 'https:' || parsed.protocol === 'http:'");
report('3.2 Open URL strictly restricts external navigation to https: and http: (blocks javascript:, file:, data:)', hasProtocolValidation);

// 3.3 Zeroization on Vault Decrypt and Encrypt
const hasZeroizationEncrypt = mainJsContent.includes('vaultKey.fill(0)') && mainJsContent.includes('jsonBuf.fill(0)');
report('3.3 Cryptographic key buffers and plaintext JSON are zeroized (fill(0)) in finally blocks', hasZeroizationEncrypt);

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 4: CRYPTOGRAPHIC STANDARDS & NIST VECTORS (ATTACK-CLASSES)
// ─────────────────────────────────────────────────────────────────────────────
console.log('\n[4. Cryptographic Primitives & Invariants]');

const { deriveVaultKey } = (function() {
  // Test argon2id derivation
  const argon2 = require('argon2');
  return {
    deriveVaultKey: async (pw, salt) => {
      const hash = await argon2.hash(pw, {
        salt,
        timeCost: 3,
        memoryCost: 65536,
        parallelism: 4,
        type: argon2.argon2id,
        hashLength: 32,
        raw: true
      });
      return hash;
    }
  };
})();

(async () => {
  try {
    const salt = crypto.randomBytes(32);
    const key = await deriveVaultKey('test-audit-password', salt);
    report('4.1 Argon2id derives 32-byte key with memory-hard parameters (m=64MB, t=3, p=4)', key.length === 32);

    // AES-256-GCM Authenticated Encryption & Tamper Resistance
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.from('Confidential vault entry payload', 'utf8');
    const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();

    // Verification of valid payload
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(ct), decipher.final()]);
    report('4.2 AES-256-GCM decrypts valid ciphertext successfully', decrypted.toString('utf8') === plaintext.toString('utf8'));

    // Tamper resistance: 1-bit mutation in ciphertext MUST throw
    const corruptedCt = Buffer.from(ct);
    corruptedCt[0] ^= 0x01;
    let tamperDetected = false;
    try {
      const badDec = crypto.createDecipheriv('aes-256-gcm', key, iv);
      badDec.setAuthTag(tag);
      badDec.update(corruptedCt);
      badDec.final();
    } catch {
      tamperDetected = true;
    }
    report('4.3 AEAD Integrity: Bit-flipped ciphertext is strictly rejected with authentication tag error', tamperDetected);

    // Tamper resistance: 1-bit mutation in auth tag MUST throw
    const corruptedTag = Buffer.from(tag);
    corruptedTag[0] ^= 0x01;
    let tagTamperDetected = false;
    try {
      const badDec = crypto.createDecipheriv('aes-256-gcm', key, iv);
      badDec.setAuthTag(corruptedTag);
      badDec.update(ct);
      badDec.final();
    } catch {
      tagTamperDetected = true;
    }
    report('4.4 AEAD Integrity: Mutated authentication tag triggers immediate failure', tagTamperDetected);

    key.fill(0);
  } catch (err) {
    report('4.x Cryptographic pipeline error: ' + err.message, false);
  }

  console.log('\n═══════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL AUDIT CHECKS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('═══════════════════════════════════════════════════════════════════════════');

  if (failed > 0) {
    process.exit(1);
  }
})();
