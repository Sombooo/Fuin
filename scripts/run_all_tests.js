#!/usr/bin/env node
'use strict';

/**
 * FUIN - Unified Test Runner
 * Executes all static, adversarial, cryptographic, sync, and storage suites.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

const TEST_FILES = [
  'test_master_adversarial_security_suite.js',
  'test_cloudflare_security_audit.js',
  'test_cryptographic_standards_and_kat.js',
  'test_sync_lan_pairing.js',
  'test_sync_lan_merge.js',
  'test_importers_adversarial.js',
  'test_importers.js',
  'test_totp_engine.js',
  'test_password_generator.js',
  'test_bitwarden_grade_features.js',
  'test_browser_extension_security_deep.js',
  'test_browser_extension_remediations.js',
  'test_remediation_suite.js',
  'test_challenger_durability_wal.js',
  'test_recovery_atomicity.js',
  'test_native_host_and_storage.js',
  'test_challenger_storage_kdf.js',
  'test_challenger_ui_polish.js',
  'test_adversarial_challenger_1.js',
  'test_adversarial_remediation_challenge.js'
];

let totalPassedSuites = 0;
let failedSuites = [];

console.log('═══════════════════════════════════════════════════════════════════');
console.log('FUIN TEST RUNNER: EXHAUSTIVE SUITE VERIFICATION');
console.log('═══════════════════════════════════════════════════════════════════\n');

for (const testFile of TEST_FILES) {
  const filePath = path.join(ROOT, testFile);
  if (!fs.existsSync(filePath)) {
    console.warn(`[SKIP] Missing test file: ${testFile}`);
    continue;
  }

  process.stdout.write(`► Running ${testFile}... `);
  const start = Date.now();
  const res = spawnSync(process.execPath, [filePath], {
    cwd: ROOT,
    stdio: 'pipe',
    encoding: 'utf8'
  });
  const duration = Date.now() - start;

  if (res.status === 0) {
    console.log(`✓ PASS (${duration}ms)`);
    totalPassedSuites++;
  } else {
    console.log(`✗ FAIL (${duration}ms)`);
    console.error(`\n--- [Output from ${testFile}] ---`);
    if (res.stdout) console.error(res.stdout);
    if (res.stderr) console.error(res.stderr);
    console.error(`--------------------------------\n`);
    failedSuites.push(testFile);
  }
}

console.log('\n═══════════════════════════════════════════════════════════════════');
console.log(`TOTAL SUITES: ${TEST_FILES.length} | PASSED: ${totalPassedSuites} | FAILED: ${failedSuites.length}`);
console.log('═══════════════════════════════════════════════════════════════════');

if (failedSuites.length > 0) {
  console.error(`\nFailed suites: ${failedSuites.join(', ')}`);
  process.exit(1);
} else {
  console.log('\nAll suites passed cleanly. Zero regressions detected.');
  process.exit(0);
}
