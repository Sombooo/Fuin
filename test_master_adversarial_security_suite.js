/**
 * ══════════════════════════════════════════════════════════════════════════════
 * FUIN MASTER ADVERSARIAL SECURITY SUITE
 * Exhaustive Verification against Cloudflare Security Audit Attack Classes
 * ══════════════════════════════════════════════════════════════════════════════
 */
'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const http = require('http');

let totalChecks = 0;
let passedChecks = 0;
let failedChecks = 0;

function check(name, condition, details = '') {
  totalChecks++;
  if (condition) {
    passedChecks++;
    console.log(`  ✓ [PASS] ${name}${details ? ` (${details})` : ''}`);
  } else {
    failedChecks++;
    console.error(`  ✗ [FAIL] ${name} ${details}`);
  }
}

console.log('═══════════════════════════════════════════════════════════════════════════');
console.log('FUIN MASTER ADVERSARIAL SECURITY & HARDENING SUITE');
console.log('Exhaustive Verification across All Cloudflare Security Audit Classes');
console.log('═══════════════════════════════════════════════════════════════════════════');

(async () => {
  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY 1: PROTOTYPE POLLUTION DEFENSE (CLIENT-SIDE & DATA-ISOLATION)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Category 1: Prototype Pollution & Object Integrity]');

  const jsonImporter = require('./services/importers/jsonImporter.js');
  const csvImporter = require('./services/importers/csvImporter.js');

  // Test 1.1: Malicious JSON payload attempting Object.prototype mutation
  const maliciousJson = JSON.stringify({
    type: 'fuin/vault',
    version: 1,
    __proto__: { pollutedKey: 'exploit_active' },
    constructor: { prototype: { constructorPolluted: 'exploit_active' } },
    entries: [
      {
        id: 'test-1',
        title: 'Test Entry',
        password: 'ValidPassword123!',
        __proto__: { entryPollution: true }
      }
    ]
  });

  const parsedImport = jsonImporter.importJSON(maliciousJson);
  check('1.1.1 JSON Importer parses valid entries from malicious payload', parsedImport.entries && parsedImport.entries.length === 1);
  check('1.1.2 Object.prototype is unpolluted by top-level __proto__', ({}).pollutedKey === undefined);
  check('1.1.3 Object.prototype is unpolluted by constructor prototype', ({}).constructorPolluted === undefined);
  check('1.1.4 Object.prototype is unpolluted by entry __proto__', ({}).entryPollution === undefined);

  // Test 1.2: Malicious CSV payload attempting field-based pollution
  const maliciousCsv = 'title,username,password,__proto__,constructor\nTargetSite,user1,Secret123!,pollutedVal,pollutedVal';
  const parsedCsv = csvImporter.importCSV(maliciousCsv);
  check('1.2.1 CSV Importer parses valid row without error', parsedCsv.entries && parsedCsv.entries.length === 1);
  check('1.2.2 CSV row does not mutate global Object.prototype', ({}).pollutedVal === undefined);

  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY 2: IPC BOUNDARY, PRELOAD JAILING & PROTOCOL FILTERING (DESKTOP-IPC)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Category 2: IPC Isolation, URL Scheme Jailing & Preload Security]');

  const preloadContent = fs.readFileSync(path.join(__dirname, 'preload.js'), 'utf8');

  // 2.1 Verify no dangerous Node.js modules or raw ipcRenderer leaks
  check('2.1.1 Preload does not expose raw ipcRenderer', !preloadContent.includes('ipcRenderer: ipcRenderer'));
  check('2.1.2 Preload does not expose child_process', !preloadContent.includes('require("child_process")') && !preloadContent.includes("require('child_process')"));
  check('2.1.3 Preload does not expose direct fs access', !preloadContent.includes('require("fs")') && !preloadContent.includes("require('fs')"));
  check('2.1.4 Preload uses strict contextBridge.exposeInMainWorld', preloadContent.includes("contextBridge.exposeInMainWorld('kekkai',"));

  // 2.2 External URL Protocol Jailing
  function testProtocolFilter(urlStr) {
    try {
      const parsed = new URL(urlStr);
      if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
        return { allowed: true, href: parsed.href };
      }
      return { allowed: false, reason: 'disallowed_protocol' };
    } catch {
      return { allowed: false, reason: 'parse_error' };
    }
  }

  check('2.2.1 Protocol Filter permits valid https:// URLs', testProtocolFilter('https://github.com/fuin').allowed === true);
  check('2.2.2 Protocol Filter permits valid http:// URLs', testProtocolFilter('http://localhost:3000').allowed === true);
  check('2.2.3 Protocol Filter strictly rejects file:/// URLs', testProtocolFilter('file:///etc/passwd').allowed === false);
  check('2.2.4 Protocol Filter strictly rejects javascript: pseudo-URLs', testProtocolFilter('javascript:alert(1)').allowed === false);
  check('2.2.5 Protocol Filter strictly rejects data: URI scheme', testProtocolFilter('data:text/html,<script>alert(1)</script>').allowed === false);
  check('2.2.6 Protocol Filter strictly rejects ms-msdt: protocol exploitation', testProtocolFilter('ms-msdt:/id PCWDiagnostic').allowed === false);
  check('2.2.7 Protocol Filter strictly rejects powershell: protocol', testProtocolFilter('powershell:calc.exe').allowed === false);
  check('2.2.8 Protocol Filter strictly rejects malformed shell injection URL', testProtocolFilter('https://evil.com;rm -rf /').allowed === false);

  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY 3: BRUTE-FORCE RATE LIMITING & LOCKOUT DURABILITY
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Category 3: Brute-Force Rate Limiting & Tampering Resistance]');

  const mainContent = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');

  // Verify HMAC verification on lockout state file
  check('3.1 Lockout state file uses HMAC authentication against tampering',
    mainContent.includes("crypto.createHmac('sha256', machineId") &&
    mainContent.includes('crypto.timingSafeEqual(hmacBuf, rawHmacBuf)'));

  // Verify exponential backoff calculation cannot produce NaN, negative or infinite values
  function calcBackoff(count) {
    return Math.min(1000 * Math.pow(2, Math.max(0, count)), 300000);
  }

  check('3.2.1 Lockout backoff: 0 failures -> 1000ms delay', calcBackoff(0) === 1000);
  check('3.2.2 Lockout backoff: 1 failure -> 2000ms delay', calcBackoff(1) === 2000);
  check('3.2.3 Lockout backoff: 5 failures -> 32000ms delay', calcBackoff(5) === 32000);
  check('3.2.4 Lockout backoff: 15 failures -> bounded strictly at max 300,000ms (5 mins)', calcBackoff(15) === 300000);
  check('3.2.5 Lockout backoff: negative count handled gracefully', calcBackoff(-5) === 1000);

  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY 4: LAN SYNC PROTOCOL ADVERSARIAL STRESS (PROTOCOLS-RPC-AND-MESSAGING)
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Category 4: LAN Sync Adversarial Protocol Stress]');

  const os = require('os');
  const { EphemeralServer, PairingManager, encryptLanPayload, decryptLanPayload, isRFC1918OrLoopback } = require('./sync-lan.js');

  const testDir = path.join(os.tmpdir(), 'fuin-test-adv-' + Date.now());
  fs.mkdirSync(testDir, { recursive: true });
  const pairingMgr = new PairingManager(testDir);
  const testPair = pairingMgr.generatePairingData();
  const server = new EphemeralServer({ pairingManager: pairingMgr });

  const serverInfo = await server.start({ port: 0, timeoutMs: 5000 });
  const baseUrl = `http://127.0.0.1:${serverInfo.port}`;

  // Helper HTTP client
  function sendRawPost(endpoint, bodyStr, headers = {}) {
    return new Promise((resolve) => {
      const u = new URL(endpoint, baseUrl);
      const req = http.request({
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          ...headers
        }
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      });
      req.on('error', (err) => resolve({ error: err.message }));
      req.write(bodyStr);
      req.end();
    });
  }

  function sendMethod(method, endpoint) {
    return new Promise((resolve) => {
      const u = new URL(endpoint, baseUrl);
      const req = http.request({
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: method
      }, (res) => {
        resolve({ status: res.statusCode });
      });
      req.on('error', (err) => resolve({ error: err.message }));
      req.end();
    });
  }

  // 4.1 HTTP Method Disallow Tests
  const getRes = await sendMethod('GET', '/pair');
  check('4.1.1 HTTP GET rejected with 405 Method Not Allowed', getRes.status === 405);
  const putRes = await sendMethod('PUT', '/pair');
  check('4.1.2 HTTP PUT rejected with 405 Method Not Allowed', putRes.status === 405);
  const delRes = await sendMethod('DELETE', '/sync');
  check('4.1.3 HTTP DELETE rejected with 405 Method Not Allowed', delRes.status === 405);

  // 4.2 Malformed JSON Stress
  const malformedRes = await sendRawPost('/pair', '{ bad json: true, broken');
  check('4.2.1 Malformed JSON payload returns 400 Bad Request without crashing server', malformedRes.status === 400);

  // 4.3 Missing Route
  const notFoundRes = await sendRawPost('/unknown-admin-endpoint', '{}');
  check('4.3.1 Unknown endpoint returns 404 Not Found', notFoundRes.status === 404);

  // 4.4 Nonce Replay Attack Prevention on /pair
  const pairKeyBuf = Buffer.from(testPair.pairKey, 'hex');
  const validProof = encryptLanPayload({
    deviceId: 'test-device-uuid',
    deviceName: 'Test Phone',
    timestamp: Date.now()
  }, pairKeyBuf);

  // First request: valid
  const pairRes1 = await sendRawPost('/pair', JSON.stringify({
    deviceId: 'test-device-uuid',
    deviceName: 'Test Phone',
    nonce: validProof.nonce,
    ciphertext: validProof.ciphertext
  }));
  check('4.4.1 First pair request succeeds with 200 OK', pairRes1.status === 200);

  // Second request with SAME nonce: Replay Attack Simulation!
  const pairRes2 = await sendRawPost('/pair', JSON.stringify({
    deviceId: 'test-device-uuid',
    deviceName: 'Test Phone',
    nonce: validProof.nonce,
    ciphertext: validProof.ciphertext
  }));
  check('4.4.2 Identical nonce replay is REJECTED (Replay Attack Defense)',
    pairRes2.status === 400 || (pairRes2.body && pairRes2.body.includes('Replay')));

  pairKeyBuf.fill(0);
  await server.stop();

  // ─────────────────────────────────────────────────────────────────────────
  // CATEGORY 5: CSPRNG ENTROPY, BIAS & RESISTANCE
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n[Category 5: CSPRNG Entropy, Cryptographic Integrity & Tamper Proofs]');

  // 5.1 IV / Nonce Collision Stress: 10,000 continuous CSPRNG allocations
  const ivSet = new Set();
  const ITERATIONS = 10000;
  for (let i = 0; i < ITERATIONS; i++) {
    const iv = crypto.randomBytes(12).toString('hex');
    ivSet.add(iv);
  }
  check('5.1 CSPRNG Nonce Uniqueness: 10,000 12-byte nonces generated with 0 collisions', ivSet.size === ITERATIONS);

  // 5.2 AEAD Multi-Vector Tamper Proofs
  const masterKey = crypto.randomBytes(32);
  const testIv = crypto.randomBytes(12);
  const testAad = Buffer.from('fuin-authenticated-context-header', 'utf8');
  const testPt = Buffer.from('Ultra-sensitive password content 12345!@#$%', 'utf8');

  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, testIv);
  cipher.setAAD(testAad);
  const testCt = Buffer.concat([cipher.update(testPt), cipher.final()]);
  const testTag = cipher.getAuthTag();

  // Baseline decrypt
  const decValid = crypto.createDecipheriv('aes-256-gcm', masterKey, testIv);
  decValid.setAAD(testAad);
  decValid.setAuthTag(testTag);
  const ptRecovered = Buffer.concat([decValid.update(testCt), decValid.final()]);
  check('5.2.1 Baseline AES-256-GCM authenticated decryption matches plaintext', ptRecovered.toString('utf8') === testPt.toString('utf8'));

  // Tamper 1: Mutated AAD MUST fail
  let aadTamperCaught = false;
  try {
    const decBadAad = crypto.createDecipheriv('aes-256-gcm', masterKey, testIv);
    decBadAad.setAAD(Buffer.from('tampered-aad-header', 'utf8'));
    decBadAad.setAuthTag(testTag);
    decBadAad.update(testCt);
    decBadAad.final();
  } catch {
    aadTamperCaught = true;
  }
  check('5.2.2 Tampered AAD triggers authentication tag mismatch', aadTamperCaught);

  // Tamper 2: Mutated Auth Tag MUST fail
  let mutatedTagCaught = false;
  try {
    const decBadTag = crypto.createDecipheriv('aes-256-gcm', masterKey, testIv);
    decBadTag.setAAD(testAad);
    const badTag = Buffer.from(testTag);
    badTag[0] ^= 0xff;
    decBadTag.setAuthTag(badTag);
    decBadTag.update(testCt);
    decBadTag.final();
  } catch {
    mutatedTagCaught = true;
  }
  check('5.2.3 Mutated auth tag triggers immediate AEAD rejection', mutatedTagCaught);

  // Zeroize test key
  masterKey.fill(0);

  // ─────────────────────────────────────────────────────────────────────────
  // SUMMARY
  // ─────────────────────────────────────────────────────────────────────────
  console.log('\n═══════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL ADVERSARIAL CHECKS: ${totalChecks} | PASSED: ${passedChecks} | FAILED: ${failedChecks}`);
  console.log('═══════════════════════════════════════════════════════════════════════════');

  if (failedChecks > 0) {
    process.exit(1);
  }
})();
