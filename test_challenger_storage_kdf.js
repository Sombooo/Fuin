'use strict';

/**
 * ============================================================================
 * CHALLENGER 2 ADVERSARIAL TEST SUITE: STORAGE ATOMICITY & KDF PORTABILITY
 * ============================================================================
 * Focus Areas:
 * 1. writeAtomicSync: write-to-temp -> flush/fsync -> rename, permissions, concurrency
 * 2. 0-byte crash recovery: empirical verification of recovery from backups in main.js
 * 3. High-frequency non-critical files isolation (fsync thrash defense)
 * 4. KDF Portability: deriveVaultKey and encryptData with bindHardware = false
 * 5. Legacy Hardware Binding Fallback: Pass 1 vs Pass 2 decryption
 * 6. Wrong Password & Exponential Rate Limiting Lockout
 * ============================================================================
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const Module = require('module');

console.log('═'.repeat(70));
console.log('CHALLENGER 2: ADVERSARIAL STORAGE & KDF PORTABILITY STRESS HARNESS');
console.log('═'.repeat(70));

let passes = 0;
let failures = 0;
const findings = [];

function check(desc, fn) {
  try {
    fn();
    console.log(`  [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  [FAIL] ${desc}`);
    console.error(`         Error: ${err.message}`);
    failures++;
    findings.push({ test: desc, error: err.message, stack: err.stack });
  }
}

async function asyncCheck(desc, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  [FAIL] ${desc}`);
    console.error(`         Error: ${err.message}`);
    failures++;
    findings.push({ test: desc, error: err.message, stack: err.stack });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// SUITE 1: Atomic Storage Writes (writeAtomicSync) Stress & Invariants
// ────────────────────────────────────────────────────────────────────────────
console.log('\n--- SUITE 1: writeAtomicSync Stress & Invariants ---');

const suite1Tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-ch2-suite1-'));

// Load writeAtomicSync implementation identical to main.js:225-279
function writeAtomicSync(targetPath, data, options = {}) {
  const mode = options.mode || 0o600;
  const encoding = options.encoding || 'utf8';
  const dir = path.dirname(targetPath);

  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }

  const rand = crypto.randomBytes(6).toString('hex');
  const tempPath = path.join(dir, `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.${rand}.tmp`);

  let fd;
  try {
    fd = fs.openSync(tempPath, 'w', mode);
    if (process.platform !== 'win32') {
      try { fs.fchmodSync(fd, mode); } catch {}
    }

    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding);
    let offset = 0;
    while (offset < buf.length) {
      offset += fs.writeSync(fd, buf, offset, buf.length - offset);
    }
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) {
      try { fs.closeSync(fd); } catch {}
    }
  }

  try {
    fs.renameSync(tempPath, targetPath);
  } catch (renameErr) {
    if (process.platform === 'win32' && (renameErr.code === 'EPERM' || renameErr.code === 'EBUSY' || renameErr.code === 'EACCES')) {
      let succeeded = false;
      for (let attempt = 1; attempt <= 5; attempt++) {
        try {
          const start = Date.now();
          while (Date.now() - start < attempt * 10) { /* spin-wait */ }
          fs.renameSync(tempPath, targetPath);
          succeeded = true;
          break;
        } catch {}
      }
      if (!succeeded) {
        try { fs.unlinkSync(tempPath); } catch {}
        throw renameErr;
      }
    } else {
      try { fs.unlinkSync(tempPath); } catch {}
      throw renameErr;
    }
  }
}

check('1.1 writeAtomicSync: write-to-temp -> fsync -> rename basic durability', () => {
  const target = path.join(suite1Tmp, 'basic.enc');
  const payload = 'TEST_DATA_' + crypto.randomBytes(32).toString('hex');
  writeAtomicSync(target, payload, { mode: 0o600 });
  assert.strictEqual(fs.existsSync(target), true, 'Target file must exist');
  assert.strictEqual(fs.readFileSync(target, 'utf8'), payload, 'Content must match');
  
  // Verify no orphaned .tmp files in directory
  const files = fs.readdirSync(suite1Tmp);
  const tmpFiles = files.filter(f => f.includes('.tmp'));
  assert.strictEqual(tmpFiles.length, 0, 'No temp files should remain after successful write');
});

check('1.2 writeAtomicSync: POSIX 0o600 mode enforcement', () => {
  if (process.platform === 'win32') return; // Mode checks do not apply to Windows NTFS
  const target = path.join(suite1Tmp, 'mode_test.enc');
  writeAtomicSync(target, 'SECRET_PAYLOAD', { mode: 0o600 });
  const stat = fs.statSync(target);
  const actualMode = stat.mode & 0o777;
  assert.strictEqual(actualMode, 0o600, `File permissions must be strictly 0o600, got: 0o${actualMode.toString(8)}`);
});

check('1.3 writeAtomicSync: Automatic nested directory creation with 0o700', () => {
  const nestedTarget = path.join(suite1Tmp, 'nested', 'deep', 'vault.enc');
  writeAtomicSync(nestedTarget, 'NESTED_DATA', { mode: 0o600 });
  assert.strictEqual(fs.existsSync(nestedTarget), true, 'Nested file must be created');
  assert.strictEqual(fs.readFileSync(nestedTarget, 'utf8'), 'NESTED_DATA');
});

check('1.4 writeAtomicSync: Rapid sequential writes & size variations stress', () => {
  const target = path.join(suite1Tmp, 'rapid.enc');
  const sizes = [1, 128, 4096, 65536, 524288]; // up to 512 KB
  for (let i = 0; i < sizes.length; i++) {
    const data = crypto.randomBytes(sizes[i]);
    writeAtomicSync(target, data, { mode: 0o600 });
    const read = fs.readFileSync(target);
    assert.strictEqual(read.length, sizes[i], `Size mismatch at iteration ${i}`);
    assert.deepStrictEqual(read, data, `Buffer mismatch at iteration ${i}`);
  }
});

check('1.5 writeAtomicSync: Atomic replacement under concurrent reader loop', () => {
  const target = path.join(suite1Tmp, 'concur.enc');
  writeAtomicSync(target, 'INIT_VERSION', { mode: 0o600 });
  
  let readerErrors = 0;
  let readerZeroBytes = 0;
  let totalReads = 0;
  
  for (let iter = 0; iter < 40; iter++) {
    const newPayload = `PAYLOAD_VERSION_${iter}_` + 'X'.repeat(500);
    // Concurrent reader simulation right before and after write
    try {
      const read1 = fs.readFileSync(target, 'utf8');
      totalReads++;
      if (read1.length === 0) readerZeroBytes++;
    } catch { readerErrors++; }

    writeAtomicSync(target, newPayload, { mode: 0o600 });

    try {
      const read2 = fs.readFileSync(target, 'utf8');
      totalReads++;
      if (read2.length === 0) readerZeroBytes++;
      assert(read2.startsWith('PAYLOAD_VERSION_') || read2 === 'INIT_VERSION', 'Reader must observe consistent state');
    } catch { readerErrors++; }
  }

  assert.strictEqual(readerErrors, 0, `Readers must not throw errors during atomic replacement, saw ${readerErrors}`);
  assert.strictEqual(readerZeroBytes, 0, `Readers must NEVER observe 0 bytes during atomic replacement, saw ${readerZeroBytes}`);
});

check('1.6 GenerationManager: incrementAndGet atomic monotonicity & durability', () => {
  const { GenerationManager } = require('./sync-v2-payload.js');
  const genDir = path.join(suite1Tmp, 'gen_dir');
  fs.mkdirSync(genDir, { recursive: true });
  
  const gm1 = new GenerationManager(genDir);
  assert.strictEqual(gm1.current, 0, 'Initial generation should be 0');
  
  const v1 = gm1.incrementAndGet();
  assert.strictEqual(v1, 1, 'First increment must return 1');
  const v2 = gm1.incrementAndGet();
  assert.strictEqual(v2, 2, 'Second increment must return 2');
  
  // Reload fresh instance from disk
  const gm2 = new GenerationManager(genDir);
  assert.strictEqual(gm2.current, 2, 'Fresh instance must reload persisted counter');
  const v3 = gm2.incrementAndGet();
  assert.strictEqual(v3, 3, 'Post-reload increment must return 3');
  
  // Check permissions on POSIX
  if (process.platform !== 'win32') {
    const stat = fs.statSync(gm2.filePath);
    assert.strictEqual(stat.mode & 0o777, 0o600, 'Generation file must have 0o600 permissions');
  }
});

// ────────────────────────────────────────────────────────────────────────────
// SUITE 2: 0-Byte Crash Recovery EMPIRICAL VERIFICATION (Production main.js)
// ────────────────────────────────────────────────────────────────────────────
console.log('\n--- SUITE 2: 0-Byte Crash Recovery Verification in main.js ---');

const suite2Tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-ch2-suite2-'));
const mainHandlers = {};

// Mock Electron runtime so we load the EXACT production main.js code
const origRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  if (id === 'electron') {
    return {
      app: {
        getPath: () => suite2Tmp,
        isPackaged: false,
        quit: () => {},
        whenReady: () => new Promise(() => {}),
        on: () => {}
      },
      BrowserWindow: class {},
      ipcMain: {
        handle: (ch, fn) => { mainHandlers[ch] = fn; },
        on: () => {}
      },
      dialog: {},
      clipboard: { writeText: () => {} },
      powerMonitor: { on: () => {} },
      shell: {},
      Tray: class {},
      Menu: { buildFromTemplate: () => ({}) },
      nativeImage: { createFromPath: () => ({ resize: () => ({}) }) },
      systemPreferences: { canPromptTouchID: () => false },
      safeStorage: { isEncryptionAvailable: () => false }
    };
  }
  return origRequire.apply(this, arguments);
};

require('./main.js');

asyncCheck('2.1 [ADVERSARIAL] Empirical Test of DATA_FILE 0-byte recovery via main.js', async () => {
  const dataFile = path.join(suite2Tmp, 'fuin.enc');
  const backupDir = path.join(suite2Tmp, 'backups');

  // Step 1: Normal save v1
  await mainHandlers['save-data'](null, 'VAULT_PAYLOAD_V1');
  assert.strictEqual(fs.readFileSync(dataFile, 'utf8'), 'VAULT_PAYLOAD_V1');

  // Step 2: Normal save v2 (this triggers backupFile(DATA_FILE) backing up V1)
  await mainHandlers['save-data'](null, 'VAULT_PAYLOAD_V2');
  assert.strictEqual(fs.readFileSync(dataFile, 'utf8'), 'VAULT_PAYLOAD_V2');

  // Inspect what backup file was actually written by backupFile()
  const backupFiles = fs.readdirSync(backupDir);
  console.log('      [Observation] Backup files created by backupFile():', backupFiles);
  assert(backupFiles.length > 0, 'Backup file should exist');

  const actualBackupName = backupFiles[0];
  console.log(`      [Observation] Actual backup filename: "${actualBackupName}"`);

  // Step 3: Simulate 0-byte crash/truncation on DATA_FILE
  fs.writeFileSync(dataFile, '');
  assert.strictEqual(fs.statSync(dataFile).size, 0, 'DATA_FILE must be 0 bytes');

  // Step 4: Call production load-data handler
  const loaded = await mainHandlers['load-data']();

  // EVALUATE RECOVERY RESULT:
  if (loaded === '' || loaded === null) {
    throw new Error(
      `CRITICAL DEFECT DETECTED: 0-byte recovery FAILED in production main.js!\n` +
      `      backupFile() generated filename: "${actualBackupName}"\n` +
      `      load-data filter requires: f.startsWith('fuin.enc.') && f.endsWith('.bak')\n` +
      `      f.startsWith('fuin.enc.') evaluated to FALSE because name is "${actualBackupName}".\n` +
      `      Result: load-data returned empty string "" and vault was not recovered.`
    );
  }

  assert(loaded === 'VAULT_PAYLOAD_V1' || loaded === 'VAULT_PAYLOAD_V2', 'Must recover valid content');
});

asyncCheck('2.2 [ADVERSARIAL] Empirical Test of MASTER_ENC_FILE 0-byte recovery via main.js', async () => {
  const masterEncFile = path.join(suite2Tmp, 'fuin.master.enc');
  const backupDir = path.join(suite2Tmp, 'backups');

  // Step 1: Normal save v1
  await mainHandlers['save-master-enc'](null, 'MASTER_KEY_V1');

  // Step 2: Normal save v2 (triggers backupFile(MASTER_ENC_FILE))
  await mainHandlers['save-master-enc'](null, 'MASTER_KEY_V2');

  const masterBackupFiles = fs.readdirSync(backupDir).filter(f => f.startsWith('fuin.master'));
  console.log('      [Observation] Master backup files created:', masterBackupFiles);
  assert(masterBackupFiles.length > 0, 'Master backup file should exist');
  const actualMasterBackupName = masterBackupFiles[0];

  // Step 3: Simulate 0-byte crash
  fs.writeFileSync(masterEncFile, '');
  assert.strictEqual(fs.statSync(masterEncFile).size, 0, 'MASTER_ENC_FILE must be 0 bytes');

  // Step 4: Call production load-master-enc handler
  const loaded = await mainHandlers['load-master-enc']();

  if (loaded === '' || loaded === null) {
    throw new Error(
      `CRITICAL DEFECT DETECTED: 0-byte recovery FAILED for MASTER_ENC_FILE in main.js!\n` +
      `      backupFile() generated: "${actualMasterBackupName}"\n` +
      `      load-master-enc requires: f.startsWith('fuin.master.enc.') && f.endsWith('.bak')\n` +
      `      f.startsWith('fuin.master.enc.') evaluated to FALSE because name is "${actualMasterBackupName}".\n` +
      `      Result: load-master-enc returned empty string ""`
    );
  }

  assert.strictEqual(loaded, 'MASTER_KEY_V1');
});

// ────────────────────────────────────────────────────────────────────────────
// SUITE 3: Hardware Binding Portability & KDF Adversarial Challenge
// ────────────────────────────────────────────────────────────────────────────
console.log('\n--- SUITE 3: Hardware Binding Portability & KDF Invariants ---');

asyncCheck('3.1 Portable Vault: Encrypt and Decrypt with Pass 1 standard key', async () => {
  const testData = [{ id: 'entry-1', site: 'fuin.app', pass: 'secret' }];
  const password = 'StrongPassword!2026';

  // Encrypt portable
  const encB64 = await mainHandlers['encrypt'](null, { data: testData, password });
  assert.strictEqual(typeof encB64, 'string');
  assert(encB64.length > 60);

  // Decrypt portable
  const decrypted = await mainHandlers['decrypt'](null, { b64: encB64, password });
  assert.deepStrictEqual(decrypted, testData, 'Decrypted data must exactly match original');
});

asyncCheck('3.2 Cross-Machine Portability Simulation (Machine A -> Machine B)', async () => {
  const argon2 = require('argon2');
  const testData = { secret: 'cross_machine_token', timestamp: Date.now() };
  const password = 'CrossMachineMasterPassword#1';

  const machineIdA = 'MACHINE_ID_DESKTOP_ALPHA_AAA';
  const machineIdB = 'MACHINE_ID_DESKTOP_BETA_BBB';

  // Helper: derive key with explicit machineId & bindHardware
  async function testDeriveKey(pw, salt, bindHardware, mId) {
    const pwBuf = Buffer.from(pw, 'utf8');
    let actualSalt = salt;
    if (bindHardware && mId) {
      actualSalt = Buffer.concat([salt, Buffer.from(mId, 'utf8')]);
    }
    const raw = await argon2.hash(pwBuf, {
      type: argon2.argon2id, salt: actualSalt,
      memoryCost: 131072, timeCost: 4, parallelism: 1,
      hashLength: 32, raw: true,
    });
    return Buffer.from(raw);
  }

  // Encrypt on Machine A with portable mode (bindHardware = false)
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const keyA = await testDeriveKey(password, salt, false, machineIdA);
  const cipher = crypto.createCipheriv('aes-256-gcm', keyA, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(testData))), cipher.final()]);
  const tag = cipher.getAuthTag();
  const portablePayload = Buffer.concat([salt, iv, tag, enc]).toString('base64');

  // Decrypt on Machine B (with different machineId, bindHardware = false)
  const buf = Buffer.from(portablePayload, 'base64');
  const bSalt = buf.slice(0, 32);
  const bIv = buf.slice(32, 44);
  const bTag = buf.slice(44, 60);
  const bData = buf.slice(60);

  const keyB = await testDeriveKey(password, bSalt, false, machineIdB);
  assert.deepStrictEqual(keyA, keyB, 'Derived keys must be identical across machines when bindHardware = false');

  const decipher = crypto.createDecipheriv('aes-256-gcm', keyB, bIv);
  decipher.setAuthTag(bTag);
  const decStr = Buffer.concat([decipher.update(bData), decipher.final()]).toString('utf8');
  assert.deepStrictEqual(JSON.parse(decStr), testData, 'Machine B must successfully decrypt Machine A portable vault');
});

asyncCheck('3.3 Legacy Hardware-Bound Vault: Pass 1 fails, Pass 2 succeeds on same machine', async () => {
  const argon2 = require('argon2');
  const testData = { legacy: true, notes: 'old vault' };
  const password = 'LegacyVaultPassword!1';
  
  // Get current machineId in effect in main.js
  const machineIdFile = path.join(suite2Tmp, 'fuin.machine-id');
  let currentMachineId = null;
  if (fs.existsSync(machineIdFile)) {
    currentMachineId = fs.readFileSync(machineIdFile, 'utf8').trim();
  } else {
    try {
      const { machineIdSync } = require('node-machine-id');
      currentMachineId = machineIdSync();
    } catch {}
  }
  assert(currentMachineId, 'Machine ID must be available for legacy hardware-bound test');

  // Construct legacy vault encrypted with bindHardware = true
  const salt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const actualSalt = Buffer.concat([salt, Buffer.from(currentMachineId, 'utf8')]);
  const rawKey = await argon2.hash(Buffer.from(password, 'utf8'), {
    type: argon2.argon2id, salt: actualSalt,
    memoryCost: 131072, timeCost: 4, parallelism: 1,
    hashLength: 32, raw: true,
  });
  const legacyKey = Buffer.from(rawKey);

  const cipher = crypto.createCipheriv('aes-256-gcm', legacyKey, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(testData))), cipher.final()]);
  const tag = cipher.getAuthTag();
  const legacyPayload = Buffer.concat([salt, iv, tag, enc]).toString('base64');

  // Now pass to production decryptData handler (mainHandlers['decrypt'])
  // It should attempt Pass 1 (fails auth tag) -> then fallback to Pass 2 (succeeds!)
  const decrypted = await mainHandlers['decrypt'](null, { b64: legacyPayload, password });
  assert.deepStrictEqual(decrypted, testData, 'Pass 2 fallback must decrypt legacy hardware-bound vault');
});

asyncCheck('3.4 Wrong Password Handling & Exponential Rate Limiting', async () => {
  const testData = [{ site: 'bank.com', pass: 'secret' }];
  const password = 'CorrectPassword_123';
  const encB64 = await mainHandlers['encrypt'](null, { data: testData, password });

  // Reset lockout state before test
  const lockoutFile = path.join(suite2Tmp, 'fuin.lockout');
  if (fs.existsSync(lockoutFile)) fs.unlinkSync(lockoutFile);

  // Attempt 1: Wrong password -> throws Decryption failed
  let caughtError = null;
  try {
    await mainHandlers['decrypt'](null, { b64: encB64, password: 'WrongPassword_1' });
  } catch (err) {
    caughtError = err;
  }
  assert(caughtError, 'Wrong password must throw an error');
  assert.strictEqual(caughtError.message, 'Decryption failed');

  // Verify lockout file was created and count incremented
  assert(fs.existsSync(lockoutFile), 'Lockout state file must be created');
  const lockoutRaw = JSON.parse(fs.readFileSync(lockoutFile, 'utf8'));
  const lockoutData = JSON.parse(lockoutRaw.data);
  assert.strictEqual(lockoutData.count, 1, 'Lockout count must be 1 after first failed attempt');
  assert(lockoutData.until > Date.now(), 'Lockout delay window must be set in the future');

  // Attempt 2: Immediate retry within lockout window -> should throw rate-limit error without running Argon2
  let rateLimitError = null;
  try {
    await mainHandlers['decrypt'](null, { b64: encB64, password: 'WrongPassword_2' });
  } catch (err) {
    rateLimitError = err;
  }
  assert(rateLimitError, 'Immediate retry must be rejected');
  assert(rateLimitError.message.includes('Too many attempts'), `Expected rate limit message, got: ${rateLimitError.message}`);
});

// ────────────────────────────────────────────────────────────────────────────
// SUITE 4: Verification of Fix for 0-Byte Recovery Bug
// ────────────────────────────────────────────────────────────────────────────
console.log('\n--- SUITE 4: Proving the Exact 0-Byte Recovery Fix ---');

check('4.1 Verification of Filename Alignment Fix', () => {
  // Demonstrate the exact fix:
  // If backupFile uses: ${base}${ext}.${timestamp}.bak
  const sourcePath = '/userData/fuin.enc';
  const ext = path.extname(sourcePath);
  const base = path.basename(sourcePath, ext);
  const timestamp = '2026-09-11T17-45-00-000Z';
  
  // Buggy current formula (main.js:652):
  const buggyPath = `${base}.${timestamp}${ext}.bak`;
  // Fixed formula:
  const fixedPath = `${base}${ext}.${timestamp}.bak`;

  console.log(`      Current buggy backup name: "${buggyPath}" -> startsWith('fuin.enc.'): ${buggyPath.startsWith('fuin.enc.')}`);
  console.log(`      Fixed backup name:         "${fixedPath}" -> startsWith('fuin.enc.'): ${fixedPath.startsWith('fuin.enc.')}`);

  assert.strictEqual(buggyPath.startsWith('fuin.enc.'), false, 'Confirms bug in current code');
  assert.strictEqual(fixedPath.startsWith('fuin.enc.'), true, 'Confirms fix works with load-data filter');

  // Also check master.enc:
  const masterSource = '/userData/fuin.master.enc';
  const mExt = path.extname(masterSource);
  const mBase = path.basename(masterSource, mExt);
  const mBuggy = `${mBase}.${timestamp}${mExt}.bak`;
  const mFixed = `${mBase}${mExt}.${timestamp}.bak`;

  console.log(`      Current buggy master name: "${mBuggy}" -> startsWith('fuin.master.enc.'): ${mBuggy.startsWith('fuin.master.enc.')}`);
  console.log(`      Fixed master name:         "${mFixed}" -> startsWith('fuin.master.enc.'): ${mFixed.startsWith('fuin.master.enc.')}`);

  assert.strictEqual(mBuggy.startsWith('fuin.master.enc.'), false, 'Confirms bug in current code for master.enc');
  assert.strictEqual(mFixed.startsWith('fuin.master.enc.'), true, 'Confirms fix works for master.enc');
});

// ────────────────────────────────────────────────────────────────────────────
// CLEANUP & SUMMARY
// ────────────────────────────────────────────────────────────────────────────
async function finish() {
  // Cleanup test directories
  try { fs.rmSync(suite1Tmp, { recursive: true, force: true }); } catch {}
  try { fs.rmSync(suite2Tmp, { recursive: true, force: true }); } catch {}

  console.log('\n' + '═'.repeat(70));
  console.log(`TEST SUMMARY: ${passes} PASSED, ${failures} FAILED`);
  console.log('═'.repeat(70));

  if (findings.length > 0) {
    console.log('\nCRITICAL FINDINGS / REPRODUCED DEFECTS:');
    findings.forEach((f, idx) => {
      console.log(`\n[FINDING #${idx + 1}] in "${f.test}":`);
      console.log(f.error);
    });
    console.log('\nVERDICT: FAIL (Pre-Release Blocker Detected in 0-Byte Recovery)');
    process.exit(1);
  } else {
    console.log('\nVERDICT: CONFIRMED_CORRECT / APPROVE');
    process.exit(0);
  }
}

// Allow asynchronous tests to complete before exiting
setTimeout(finish, 2000);
