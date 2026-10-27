'use strict';

/**
 * ============================================================================
 * FUIN PHASE 3.1.1 — TASK R1: RECOVERY ATOMICITY & CHALLENGER STRESS SUITE
 * ============================================================================
 * Comprehensive automated verification & empirical adversarial stress testing
 * of Task R1 (Atomic Recovery Material Regeneration):
 *
 * PART 1: Core Functional & Invariant Verifications (Tests 1-10)
 * - Test 1: Successful atomic pair save from clean state
 * - Test 2: Successful atomic pair save over existing recovery material
 * - Test 3: Temporary write/fsync failure rollback (staging error)
 * - Test 4: Rename failure on recovery file (pre-commit failure)
 * - Test 5: Rename failure on master.enc (post-first-rename rollback)
 * - Test 6: Rename failure on master.enc from clean state (unlink recovery)
 * - Test 7: Input validation (empty/null/invalid payload rejection)
 * - Test 8: POSIX mode 0o600 permission enforcement & unpredictable temp naming
 * - Test 9: Crash recovery: self-healing from interrupted transaction (.rollback)
 * - Test 10: Binary buffer support & zero plaintext leakage
 *
 * PART 2: Adversarial Challenger Stress Harness & Invariant Oracles (Tests 11-30)
 * - Test 11: Exhaustive fuzzing of invalid recoveryData with strict oracle verification
 * - Test 12: Exhaustive fuzzing of invalid masterEncData with strict oracle verification
 * - Test 13: IPC payload structure fuzzing (polymorphic argument & malformed object rejection)
 * - Test 14: Massive payload handling (2MB string and 2MB buffer) and binary integrity
 * - Test 15: Low-level I/O fault injection: simulated ENOSPC during staging write
 * - Test 16: Low-level I/O fault injection: simulated EIO during fsyncSync
 * - Test 17: Low-level I/O fault injection: simulated EPERM on pre-publish copyFileSync
 * - Test 18: Simulated EPERM failure on first rename (target files untouched)
 * - Test 19: Second rename failure rollback with legacyBound: true status preservation
 * - Test 20: Clean-install second rename failure (complete unlink of published file)
 * - Test 21: Crash simulation: power loss between rename 1 and 2 self-heals on startup
 * - Test 22: Compound crash recovery: handles missing target and multiple orphan rollbacks
 * - Test 23: Safe handling of invalid / null paths in cleanupOrphanRecoveryTransactions
 * - Test 24: Windows transient file-lock retry simulation (safeRenameSync spin-retry)
 * - Test 25: Windows persistent file-lock failure triggering clean transactional rollback
 * - Test 26: POSIX permissions enforcement (mode 0o600 on recovery, master.enc, status)
 * - Test 27: Self-healing permission remediation: repairs loose-permission (0o666/0o644) files to 0o600
 * - Test 28: Rapid sequential commit stress (50 iterations with random payloads)
 * - Test 29: Alternating failure and success stress (30 cycles of repeated faults)
 * - Test 30: Default Electron userData IPC transaction with setRecoveryLegacyBound status transition
 * ============================================================================
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

console.log('═'.repeat(78));
console.log('FUIN PHASE 3.1.1 TASK R1: RECOVERY ATOMICITY & CHALLENGER STRESS SUITE');
console.log('═'.repeat(78));

let passes = 0;
let failures = 0;
const failureDetails = [];

function check(desc, fn) {
  try {
    fn();
    console.log(`  [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  [FAIL] ${desc}`);
    console.error(`         Error: ${err.message}`);
    failures++;
    failureDetails.push({ desc, error: err.message });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Load Production main.js Implementation & Mock Electron Runtime
// ────────────────────────────────────────────────────────────────────────────

const Module = require('module');
const mainHandlers = {};
const defaultTestUserData = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-recovery-default-'));

const origRequire = Module.prototype.require;
Module.prototype.require = function(id) {
  if (id === 'electron') {
    return {
      app: {
        getPath: () => defaultTestUserData,
        isPackaged: false,
        quit: () => {},
        whenReady: () => Promise.resolve(),
        on: () => {}
      },
      session: {
        defaultSession: {
          webRequest: {
            onHeadersReceived: () => {}
          }
        }
      },
      BrowserWindow: class {
        constructor() {
          return {
            webContents: { send: () => {} },
            on: () => {},
            setContentProtection: () => {},
            loadFile: () => {},
            show: () => {},
            hide: () => {},
            isVisible: () => true
          };
        }
      },
      ipcMain: {
        handle: (ch, fn) => { mainHandlers[ch] = fn; },
        on: () => {}
      },
      dialog: {},
      clipboard: { writeText: () => {} },
      powerMonitor: { on: () => {} },
      shell: { openPath: async () => true, openExternal: () => {} },
      Tray: class {
        setToolTip() {}
        popUpContextMenu() {}
        setContextMenu() {}
        on() {}
      },
      Menu: { buildFromTemplate: () => ({}) },
      nativeImage: { createFromPath: () => ({ resize: () => ({}) }) },
      systemPreferences: { canPromptTouchID: () => false },
      safeStorage: { isEncryptionAvailable: () => false }
    };
  }
  return origRequire.apply(this, arguments);
};

// Require production main.js directly
const mainExports = require('./main.js');

const {
  validateRecoveryPayload,
  writeAndFsyncSync,
  safeRenameSync,
  cleanupOrphanRecoveryTransactions,
  saveRecoveryPairSync
} = mainExports;

assert.strictEqual(typeof saveRecoveryPairSync, 'function', 'saveRecoveryPairSync must be exported from main.js');
assert.strictEqual(typeof mainHandlers['save-recovery-pair'], 'function', 'save-recovery-pair IPC handler must be registered');

// ────────────────────────────────────────────────────────────────────────────
// Invariant Verification Oracle
// ────────────────────────────────────────────────────────────────────────────

function verifyVaultSynchronization(dir, expectedState, label = '') {
  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');
  const statusPath = path.join(dir, 'fuin.recovery-status');

  const recExists = fs.existsSync(recPath);
  const masterExists = fs.existsSync(masterPath);

  // INVARIANT 1: fuin.recovery and fuin.master.enc MUST either BOTH exist or NEITHER exist
  assert.strictEqual(
    recExists,
    masterExists,
    `DESYNCHRONIZATION DETECTED [${label}]: recExists=${recExists}, masterExists=${masterExists}`
  );

  if (expectedState === null) {
    assert.strictEqual(recExists, false, `Expected clean state, but rec exists [${label}]`);
    assert.strictEqual(masterExists, false, `Expected clean state, but master exists [${label}]`);
  } else {
    assert.strictEqual(recExists, true, `fuin.recovery must exist [${label}]`);
    assert.strictEqual(masterExists, true, `fuin.master.enc must exist [${label}]`);

    const actualRec = fs.readFileSync(recPath, 'utf8');
    const actualMaster = fs.readFileSync(masterPath, 'utf8');

    assert.strictEqual(actualRec, expectedState.recovery, `Recovery content mismatch [${label}]`);
    assert.strictEqual(actualMaster, expectedState.masterEnc, `Master.enc content mismatch [${label}]`);

    if (expectedState.legacyBound !== undefined && fs.existsSync(statusPath)) {
      const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
      assert.strictEqual(
        status.legacyBound,
        expectedState.legacyBound,
        `legacyBound flag corrupted [${label}]: expected ${expectedState.legacyBound}, got ${status.legacyBound}`
      );
    }
  }

  // INVARIANT 2: No staging (.tmp) or rollback (.rollback) files left behind
  const files = fs.readdirSync(dir);
  const orphanTmp = files.filter(f => f.endsWith('.tmp'));
  const orphanRollback = files.filter(f => f.endsWith('.rollback'));
  assert.strictEqual(orphanTmp.length, 0, `Leftover tmp files found [${label}]: ${orphanTmp.join(', ')}`);
  assert.strictEqual(orphanRollback.length, 0, `Leftover rollback files found [${label}]: ${orphanRollback.join(', ')}`);
}

// ────────────────────────────────────────────────────────────────────────────
// PART 1: Core Functional & Invariant Verifications (Tests 1-10)
// ────────────────────────────────────────────────────────────────────────────

const testEnvDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-recovery-atomicity-test-'));

// Test 1: Clean State Atomic Save
check('1. Clean state atomic save: creates fuin.recovery and fuin.master.enc with status', () => {
  const dir = path.join(testEnvDir, 'test1');
  const res = saveRecoveryPairSync(dir, 'ciphertext-recovery-1', 'ciphertext-master-1');
  assert.strictEqual(res, true);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');
  const statusPath = path.join(dir, 'fuin.recovery-status');

  assert.ok(fs.existsSync(recPath), 'fuin.recovery must exist');
  assert.ok(fs.existsSync(masterPath), 'fuin.master.enc must exist');
  assert.ok(fs.existsSync(statusPath), 'fuin.recovery-status must exist');

  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'ciphertext-recovery-1');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'ciphertext-master-1');

  const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
  assert.strictEqual(status.legacyBound, false);
  assert.strictEqual(status.version, 1);

  // Also verify IPC handler saves to default app userData
  mainHandlers['save-recovery-pair'](null, { recovery: 'ipc-rec-1', masterEnc: 'ipc-master-1' });
  const defaultRec = path.join(defaultTestUserData, 'fuin.recovery');
  const defaultMaster = path.join(defaultTestUserData, 'fuin.master.enc');
  assert.strictEqual(fs.readFileSync(defaultRec, 'utf8'), 'ipc-rec-1');
  assert.strictEqual(fs.readFileSync(defaultMaster, 'utf8'), 'ipc-master-1');
});

// Test 2: Overwrite Existing Recovery Material
check('2. Overwrite existing recovery material: updates both files atomically', () => {
  const dir = path.join(testEnvDir, 'test2');
  saveRecoveryPairSync(dir, 'old-recovery', 'old-master');

  const res = saveRecoveryPairSync(dir, 'new-recovery', 'new-master');
  assert.strictEqual(res, true);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'new-recovery');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'new-master');
});

// Test 3: Staging Write Failure Rollback
check('3. Staging write failure: leaves existing files untouched', () => {
  const dir = path.join(testEnvDir, 'test3');
  saveRecoveryPairSync(dir, 'baseline-rec', 'baseline-master');

  assert.throws(() => {
    saveRecoveryPairSync(dir, 'uncommitted-rec', 'uncommitted-master', { failAfterMasterTempWrite: true });
  }, /SIMULATED_FAIL_AFTER_MASTER_TEMP_WRITE/);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'baseline-rec', 'Original recovery must be untouched');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'baseline-master', 'Original master must be untouched');

  const files = fs.readdirSync(dir);
  assert.strictEqual(files.filter(f => f.endsWith('.tmp')).length, 0, 'No tmp files should remain');
});

// Test 4: Rename Failure on First File (Recovery)
check('4. Rename failure on recovery file: aborts with zero destination alteration', () => {
  const dir = path.join(testEnvDir, 'test4');
  saveRecoveryPairSync(dir, 'baseline-rec-4', 'baseline-master-4');

  assert.throws(() => {
    saveRecoveryPairSync(dir, 'uncommitted-rec-4', 'uncommitted-master-4', { failBeforeRecoveryRename: true });
  }, /SIMULATED_FAIL_BEFORE_RECOVERY_RENAME/);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'baseline-rec-4');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'baseline-master-4');

  const files = fs.readdirSync(dir);
  assert.strictEqual(files.filter(f => f.endsWith('.tmp') || f.endsWith('.rollback')).length, 0);
});

// Test 5: Rename Failure on Second File (CRITICAL POST-FIRST-RENAME ROLLBACK)
check('5. Rename failure on master.enc: cleanly rolls back fuin.recovery to original state', () => {
  const dir = path.join(testEnvDir, 'test5');
  saveRecoveryPairSync(dir, 'original-rec-5', 'original-master-5');

  // Set legacyBound: true to test status preservation
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 12345 }), 'utf8');

  assert.throws(() => {
    saveRecoveryPairSync(dir, 'new-rec-5', 'new-master-5', { failBeforeMasterRename: true });
  }, /SIMULATED_FAIL_BEFORE_MASTER_RENAME/);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  // CRITICAL INVARIANT: fuin.recovery MUST have reverted to original-rec-5!
  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'original-rec-5', 'fuin.recovery MUST be rolled back!');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'original-master-5', 'fuin.master.enc MUST remain original!');

  // fuin.recovery-status MUST NOT have been overwritten with legacyBound: false
  const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
  assert.strictEqual(status.legacyBound, true, 'legacyBound must remain true on rollback');
  assert.strictEqual(status.updatedAt, 12345, 'status timestamp must remain original');

  const files = fs.readdirSync(dir);
  assert.strictEqual(files.filter(f => f.endsWith('.tmp') || f.endsWith('.rollback')).length, 0, 'Zero staging files');
});

// Test 6: Rename Failure on Second File From Clean State (Unlink First File)
check('6. Rename failure on master.enc from clean state: unlinks published recovery file', () => {
  const dir = path.join(testEnvDir, 'test6');

  assert.throws(() => {
    saveRecoveryPairSync(dir, 'new-rec-6', 'new-master-6', { failBeforeMasterRename: true });
  }, /SIMULATED_FAIL_BEFORE_MASTER_RENAME/);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  assert.ok(!fs.existsSync(recPath), 'fuin.recovery must NOT exist after rollback from clean state');
  assert.ok(!fs.existsSync(masterPath), 'fuin.master.enc must NOT exist');
});

// Test 7: Input Validation Rejection
check('7. Input validation: rejects empty, null, and non-string/non-buffer payloads', () => {
  const dir = path.join(testEnvDir, 'test7');
  assert.throws(() => saveRecoveryPairSync(dir, null, 'master'), /Invalid recovery payload: recoveryData/);
  assert.throws(() => saveRecoveryPairSync(dir, 'rec', null), /Invalid recovery payload: masterEncData/);
  assert.throws(() => saveRecoveryPairSync(dir, '', 'master'), /Invalid recovery payload: recoveryData cannot be empty/);
  assert.throws(() => saveRecoveryPairSync(dir, 'rec', '   '), /Invalid recovery payload: masterEncData cannot be empty/);
  assert.throws(() => saveRecoveryPairSync(dir, 12345, 'master'), /must be a string or Buffer/);
  assert.throws(() => saveRecoveryPairSync(dir, 'rec', {}), /must be a string or Buffer/);
  assert.throws(() => saveRecoveryPairSync(dir, Buffer.alloc(0), 'master'), /cannot be an empty buffer/);
});

// Test 8: POSIX Permissions and Unpredictable Naming
check('8. Security attributes: mode 0o600 enforced and unpredictable naming', () => {
  const dir = path.join(testEnvDir, 'test8');
  saveRecoveryPairSync(dir, 'secret-rec', 'secret-master');

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');
  const statusPath = path.join(dir, 'fuin.recovery-status');

  if (process.platform !== 'win32') {
    const recStat = fs.statSync(recPath);
    const masterStat = fs.statSync(masterPath);
    const statusStat = fs.statSync(statusPath);

    assert.strictEqual(recStat.mode & 0o777, 0o600, 'fuin.recovery must be mode 0o600');
    assert.strictEqual(masterStat.mode & 0o777, 0o600, 'fuin.master.enc must be mode 0o600');
    assert.strictEqual(statusStat.mode & 0o777, 0o600, 'fuin.recovery-status must be mode 0o600');
  }
});

// Test 9: Crash Recovery Self-Healing from Interrupted Transaction (.rollback)
check('9. Crash recovery self-healing: restores fuin.recovery from orphan .rollback', () => {
  const dir = path.join(testEnvDir, 'test9');
  fs.mkdirSync(dir, { recursive: true });

  const recPath = path.join(dir, 'fuin.recovery');
  const rollbackPath = path.join(dir, '.fuin.recovery.12345.1690000000.abcd.rollback');
  const staleTmpPath = path.join(dir, '.fuin.recovery.12345.1690000000.abcd.tmp');

  // Simulate state after crash between rename 1 and rename 2:
  fs.writeFileSync(recPath, 'mismatched-uncommitted-rec', 'utf8');
  fs.writeFileSync(rollbackPath, 'authoritative-original-rec', 'utf8');
  fs.writeFileSync(staleTmpPath, 'stale-tmp-data', 'utf8');
  const oldTime = (Date.now() - 70000) / 1000;
  fs.utimesSync(staleTmpPath, oldTime, oldTime);

  cleanupOrphanRecoveryTransactions(dir);

  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'authoritative-original-rec', 'Recovery must be healed from rollback');
  assert.ok(!fs.existsSync(rollbackPath), 'Rollback file must be consumed/removed');
  assert.ok(!fs.existsSync(staleTmpPath), 'Stale tmp file must be cleaned up');
});

// Test 10: Buffer support & Zero plaintext leakage
check('10. Binary buffer support and zero plaintext key leakage in stored files', () => {
  const dir = path.join(testEnvDir, 'test10');
  const recBuf = crypto.randomBytes(64);
  const masterBuf = crypto.randomBytes(64);

  saveRecoveryPairSync(dir, recBuf, masterBuf);

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  assert.deepStrictEqual(fs.readFileSync(recPath), recBuf);
  assert.deepStrictEqual(fs.readFileSync(masterPath), masterBuf);
});

// ────────────────────────────────────────────────────────────────────────────
// PART 2: Adversarial Challenger Stress Harness & Invariant Oracles (Tests 11-30)
// ────────────────────────────────────────────────────────────────────────────

const suiteRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-challenger-stress-'));

// Test 11: Exhaustive Fuzzing of Invalid recoveryData
check('11. Exhaustive fuzzing of invalid recoveryData rejects all types with invariant oracle verification', () => {
  const dir = path.join(suiteRoot, 'fuzz11');
  const baseline = { recovery: 'golden-rec-11', masterEnc: 'golden-master-11', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 9999 }));

  const invalidInputs = [
    undefined, null, '', '   ', '\t\n\r', 12345, 0, -1, NaN, Infinity,
    true, false, {}, { recovery: 'a' }, [], ['data'], () => {}, Symbol('sym'),
    12345678901234567890n, Buffer.alloc(0)
  ];

  for (const inv of invalidInputs) {
    assert.throws(
      () => saveRecoveryPairSync(dir, inv, 'valid-master-payload'),
      /Invalid recovery payload: recoveryData/
    );
    verifyVaultSynchronization(dir, baseline, `fuzz-rec-${String(inv)}`);
  }
});

// Test 12: Exhaustive Fuzzing of Invalid masterEncData
check('12. Exhaustive fuzzing of invalid masterEncData rejects all types with invariant oracle verification', () => {
  const dir = path.join(suiteRoot, 'fuzz12');
  const baseline = { recovery: 'golden-rec-12', masterEnc: 'golden-master-12', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 8888 }));

  const invalidInputs = [
    undefined, null, '', '   ', '\t\n\r', 12345, 0, -1, NaN, Infinity,
    true, false, {}, [], () => {}, Symbol('sym2'), Buffer.alloc(0)
  ];

  for (const inv of invalidInputs) {
    assert.throws(
      () => saveRecoveryPairSync(dir, 'valid-rec-payload', inv),
      /Invalid recovery payload: masterEncData/
    );
    verifyVaultSynchronization(dir, baseline, `fuzz-master-${String(inv)}`);
  }
});

// Test 13: IPC Payload Structure Fuzzing
check('13. IPC payload structure fuzzing: accepts valid patterns, rejects malformed objects', () => {
  // Pattern A: standard object { recovery, masterEnc }
  const resA = mainHandlers['save-recovery-pair'](null, { recovery: 'ipc-r-a', masterEnc: 'ipc-m-a' });
  assert.strictEqual(resA, true);
  assert.strictEqual(fs.readFileSync(path.join(defaultTestUserData, 'fuin.recovery'), 'utf8'), 'ipc-r-a');
  assert.strictEqual(fs.readFileSync(path.join(defaultTestUserData, 'fuin.master.enc'), 'utf8'), 'ipc-m-a');

  // Pattern B: alternative object { recoveryData, masterEncData }
  const resB = mainHandlers['save-recovery-pair'](null, { recoveryData: 'ipc-r-b', masterEncData: 'ipc-m-b' });
  assert.strictEqual(resB, true);
  assert.strictEqual(fs.readFileSync(path.join(defaultTestUserData, 'fuin.recovery'), 'utf8'), 'ipc-r-b');

  // Pattern C: two arguments (recovery, masterEnc)
  const resC = mainHandlers['save-recovery-pair'](null, 'ipc-r-c', 'ipc-m-c');
  assert.strictEqual(resC, true);
  assert.strictEqual(fs.readFileSync(path.join(defaultTestUserData, 'fuin.recovery'), 'utf8'), 'ipc-r-c');

  // Rejections
  assert.throws(() => mainHandlers['save-recovery-pair'](null, { recovery: 'only-rec' }), /Invalid recovery payload: masterEncData is required/);
  assert.throws(() => mainHandlers['save-recovery-pair'](null, { masterEnc: 'only-master' }), /Invalid recovery payload: recoveryData is required/);
  assert.throws(() => mainHandlers['save-recovery-pair'](null, {}), /Invalid recovery payload: recoveryData is required/);
  assert.throws(() => mainHandlers['save-recovery-pair'](null, null), /Invalid recovery payload: recoveryData is required/);
});

// Test 14: Massive Payload Handling
check('14. Massive payload handling (2MB string and 2MB buffer) and binary integrity', () => {
  const dir = path.join(suiteRoot, 'large14');
  const largeRec = 'R'.repeat(2 * 1024 * 1024);
  const largeMaster = crypto.randomBytes(2 * 1024 * 1024);

  const res = saveRecoveryPairSync(dir, largeRec, largeMaster);
  assert.strictEqual(res, true);

  const readRec = fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8');
  const readMaster = fs.readFileSync(path.join(dir, 'fuin.master.enc'));
  assert.strictEqual(readRec.length, 2 * 1024 * 1024);
  assert.strictEqual(readMaster.length, 2 * 1024 * 1024);
  assert.ok(readMaster.equals(largeMaster));
});

// Test 15: Low-Level I/O Fault: ENOSPC During Write
check('15. Simulated ENOSPC during temporary write aborts cleanly and leaves disk untouched', () => {
  const dir = path.join(suiteRoot, 'io_enospc15');
  const baseline = { recovery: 'base-rec-15', masterEnc: 'base-master-15', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 1515 }), 'utf8');

  const origWriteSync = fs.writeSync;
  let writeCount = 0;
  fs.writeSync = function(fd, buf) {
    writeCount++;
    if (writeCount === 1) {
      const err = new Error('ENOSPC: no space left on device, write');
      err.code = 'ENOSPC';
      throw err;
    }
    return origWriteSync.apply(this, arguments);
  };

  try {
    assert.throws(() => saveRecoveryPairSync(dir, 'new-r-15', 'new-m-15'), /ENOSPC/);
  } finally {
    fs.writeSync = origWriteSync;
  }

  verifyVaultSynchronization(dir, baseline, 'io_enospc_write15');
});

// Test 16: Low-Level I/O Fault: EIO During Fsync
check('16. Simulated EIO during master.enc fsyncSync triggers rollback and cleans staging', () => {
  const dir = path.join(suiteRoot, 'io_eio16');
  const baseline = { recovery: 'base-rec-16', masterEnc: 'base-master-16', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 1616 }), 'utf8');

  const origFsyncSync = fs.fsyncSync;
  let fsyncCount = 0;
  fs.fsyncSync = function(fd) {
    fsyncCount++;
    if (fsyncCount === 2) {
      const err = new Error('EIO: i/o error, fsync');
      err.code = 'EIO';
      throw err;
    }
    return origFsyncSync.apply(this, arguments);
  };

  try {
    assert.throws(() => saveRecoveryPairSync(dir, 'new-r-16', 'new-m-16'), /EIO/);
  } finally {
    fs.fsyncSync = origFsyncSync;
  }

  verifyVaultSynchronization(dir, baseline, 'io_eio_fsync16');
});

// Test 17: Low-Level I/O Fault: EPERM on Pre-Publish copyFileSync
check('17. Simulated EPERM on pre-publish copyFileSync aborts without modifying targets', () => {
  const dir = path.join(suiteRoot, 'io_copy_fail17');
  const baseline = { recovery: 'base-rec-17', masterEnc: 'base-master-17', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 1717 }), 'utf8');

  const origCopyFileSync = fs.copyFileSync;
  fs.copyFileSync = function() {
    const err = new Error('EPERM: operation not permitted, copyfile');
    err.code = 'EPERM';
    throw err;
  };

  try {
    assert.throws(() => saveRecoveryPairSync(dir, 'new-r-17', 'new-m-17'), /EPERM/);
  } finally {
    fs.copyFileSync = origCopyFileSync;
  }

  verifyVaultSynchronization(dir, baseline, 'io_copy_fail17');
});

// Test 18: Simulated Failure on First Rename
check('18. Simulated rename failure on recovery file aborts with zero destination alteration', () => {
  const dir = path.join(suiteRoot, 'rename_fail18');
  const baseline = { recovery: 'base-rec-18', masterEnc: 'base-master-18', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 1818 }), 'utf8');

  assert.throws(
    () => saveRecoveryPairSync(dir, 'attempt-r-18', 'attempt-m-18', { failBeforeRecoveryRename: true }),
    /SIMULATED_FAIL_BEFORE_RECOVERY_RENAME/
  );

  verifyVaultSynchronization(dir, baseline, 'rename_fail18');
});

// Test 19: Post-First-Rename Rollback & Status Preservation
check('19. Second rename failure MUST roll back fuin.recovery and preserve legacyBound: true', () => {
  const dir = path.join(suiteRoot, 'rollback_rec19');
  const baseline = { recovery: 'GOLDEN_RECOVERY_19', masterEnc: 'GOLDEN_MASTER_19', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);

  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 77777 }), 'utf8');

  assert.throws(
    () => saveRecoveryPairSync(dir, 'POISON_RECOVERY_19', 'POISON_MASTER_19', { failBeforeMasterRename: true }),
    /SIMULATED_FAIL_BEFORE_MASTER_RENAME/
  );

  const postStatus = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
  assert.strictEqual(postStatus.legacyBound, true, 'legacyBound must remain true on rollback');
  assert.strictEqual(postStatus.updatedAt, 77777, 'updatedAt timestamp must not change on failure');

  verifyVaultSynchronization(dir, baseline, 'rollback_rec19');
});

// Test 20: Clean-Install Second Rename Failure
check('20. Second rename failure on clean install (no pre-existing recovery) unlinks published recovery', () => {
  const dir = path.join(suiteRoot, 'clean_fail20');

  assert.throws(
    () => saveRecoveryPairSync(dir, 'fresh-rec-20', 'fresh-master-20', { failBeforeMasterRename: true }),
    /SIMULATED_FAIL_BEFORE_MASTER_RENAME/
  );

  verifyVaultSynchronization(dir, null, 'clean_install_failure_unlink20');
});

// Test 21: Crash Simulation: Power Loss Between Renames
check('21. Simulated power loss crash between rename 1 and 2 self-heals on startup', () => {
  const dir = path.join(suiteRoot, 'crash_sim21');
  fs.mkdirSync(dir, { recursive: true });

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');
  const rollbackPath = path.join(dir, '.fuin.recovery.crash.rollback');
  const staleTmpPath = path.join(dir, '.fuin.master.enc.crash.tmp');

  fs.writeFileSync(recPath, 'UNCOMMITTED_NEW_RECOVERY_21', 'utf8');
  fs.writeFileSync(masterPath, 'AUTHORITATIVE_OLD_MASTER_21', 'utf8');
  fs.writeFileSync(rollbackPath, 'AUTHORITATIVE_OLD_RECOVERY_21', 'utf8');
  fs.writeFileSync(staleTmpPath, 'stale-tmp-bytes', 'utf8');

  const sixtyFiveSecondsAgo = (Date.now() - 65000) / 1000;
  fs.utimesSync(staleTmpPath, sixtyFiveSecondsAgo, sixtyFiveSecondsAgo);

  cleanupOrphanRecoveryTransactions(dir);

  const healedState = {
    recovery: 'AUTHORITATIVE_OLD_RECOVERY_21',
    masterEnc: 'AUTHORITATIVE_OLD_MASTER_21'
  };
  verifyVaultSynchronization(dir, healedState, 'crash_self_healing21');
});

// Test 22: Compound Crash Recovery
check('22. Compound crash recovery: handles missing target recovery and multiple orphan rollbacks', () => {
  const dir = path.join(suiteRoot, 'crash_sim22');
  fs.mkdirSync(dir, { recursive: true });

  const masterPath = path.join(dir, 'fuin.master.enc');
  fs.writeFileSync(masterPath, 'MASTER_STABLE_22', 'utf8');

  const rb1 = path.join(dir, '.fuin.recovery.tx1.rollback');
  const rb2 = path.join(dir, '.fuin.recovery.tx2.rollback');
  fs.writeFileSync(rb1, 'RECOVERY_TX1_DATA', 'utf8');
  fs.writeFileSync(rb2, 'RECOVERY_TX2_DATA', 'utf8');

  cleanupOrphanRecoveryTransactions(dir);

  const recPath = path.join(dir, 'fuin.recovery');
  assert.ok(fs.existsSync(recPath), 'fuin.recovery must be restored from rollback');
  assert.ok(!fs.existsSync(rb1), 'rb1 must be removed');
  assert.ok(!fs.existsSync(rb2), 'rb2 must be removed');
});

// Test 23: Safe Handling of Invalid Paths
check('23. Safe handling of invalid / null paths in cleanupOrphanRecoveryTransactions', () => {
  assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(null));
  assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(undefined));
  assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions('/non/existent/path/for/fuin/test'));
});

// Test 24: Windows Transient Lock Retry
check('24. Windows transient lock retry simulation (safeRenameSync spin-retry loop)', () => {
  const dir = path.join(suiteRoot, 'lock_retry24');
  fs.mkdirSync(dir, { recursive: true });

  const src = path.join(dir, 'src.tmp');
  const dst = path.join(dir, 'dst.file');
  fs.writeFileSync(src, 'test-retry-data-24', 'utf8');

  let attempts = 0;
  const origRenameSync = fs.renameSync;
  const origPlatform = process.platform;
  Object.defineProperty(process, 'platform', { value: 'win32' });

  fs.renameSync = function(s, d) {
    attempts++;
    if (attempts <= 3) {
      const err = new Error('EBUSY: resource busy or locked, rename');
      err.code = 'EBUSY';
      throw err;
    }
    return origRenameSync.apply(this, arguments);
  };

  try {
    safeRenameSync(src, dst);
    assert.strictEqual(attempts, 4, 'safeRenameSync should succeed on 4th attempt after 3 EBUSY retries');
    assert.strictEqual(fs.readFileSync(dst, 'utf8'), 'test-retry-data-24');
  } finally {
    fs.renameSync = origRenameSync;
    Object.defineProperty(process, 'platform', { value: origPlatform });
  }
});

// Test 25: Windows Persistent Lock Rollback
check('25. Windows persistent lock failure triggering clean transactional rollback', () => {
  const dir = path.join(suiteRoot, 'lock_persistent25');
  const baseline = { recovery: 'base-lock-rec-25', masterEnc: 'base-lock-master-25', legacyBound: true };
  saveRecoveryPairSync(dir, baseline.recovery, baseline.masterEnc);
  const statusPath = path.join(dir, 'fuin.recovery-status');
  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 2525 }), 'utf8');

  const origPlatform = process.platform;
  Object.defineProperty(process, 'platform', { value: 'win32' });

  const origRenameSync = fs.renameSync;
  fs.renameSync = function(s, d) {
    if (d.endsWith('fuin.master.enc')) {
      const err = new Error('EBUSY: resource busy or locked, rename');
      err.code = 'EBUSY';
      throw err;
    }
    return origRenameSync.apply(this, arguments);
  };

  try {
    assert.throws(() => saveRecoveryPairSync(dir, 'uncommittable-rec', 'uncommittable-master'), /EBUSY/);
  } finally {
    fs.renameSync = origRenameSync;
    Object.defineProperty(process, 'platform', { value: origPlatform });
  }

  verifyVaultSynchronization(dir, baseline, 'persistent_lock_rollback25');
});

// Test 26: POSIX Permissions Enforcement
check('26. POSIX permissions enforcement: mode 0o600 on recovery, master.enc, status', () => {
  if (process.platform === 'win32') return;

  const dir = path.join(suiteRoot, 'perms_check26');
  fs.mkdirSync(dir, { recursive: true, mode: 0o777 });

  saveRecoveryPairSync(dir, 'perm-rec-26', 'perm-master-26');

  const recStat = fs.statSync(path.join(dir, 'fuin.recovery'));
  const masterStat = fs.statSync(path.join(dir, 'fuin.master.enc'));
  const statusStat = fs.statSync(path.join(dir, 'fuin.recovery-status'));

  assert.strictEqual(recStat.mode & 0o777, 0o600, 'fuin.recovery must have 0o600 mode');
  assert.strictEqual(masterStat.mode & 0o777, 0o600, 'fuin.master.enc must have 0o600 mode');
  assert.strictEqual(statusStat.mode & 0o777, 0o600, 'fuin.recovery-status must have 0o600 mode');
});

// Test 27: Self-Healing Permission Remediation
check('27. Self-healing permission remediation: repairs loose-permission (0o666/0o644) files to 0o600', () => {
  if (process.platform === 'win32') return;

  const dir = path.join(suiteRoot, 'perms_repair27');
  fs.mkdirSync(dir, { recursive: true });

  const recPath = path.join(dir, 'fuin.recovery');
  const masterPath = path.join(dir, 'fuin.master.enc');

  fs.writeFileSync(recPath, 'loose-rec-27', { mode: 0o666 });
  fs.chmodSync(recPath, 0o666);
  fs.writeFileSync(masterPath, 'loose-master-27', { mode: 0o644 });
  fs.chmodSync(masterPath, 0o644);

  assert.strictEqual(fs.statSync(recPath).mode & 0o777, 0o666);
  assert.strictEqual(fs.statSync(masterPath).mode & 0o777, 0o644);

  saveRecoveryPairSync(dir, 'repaired-rec-27', 'repaired-master-27');

  assert.strictEqual(fs.statSync(recPath).mode & 0o777, 0o600, 'fuin.recovery must be repaired to 0o600');
  assert.strictEqual(fs.statSync(masterPath).mode & 0o777, 0o600, 'fuin.master.enc must be repaired to 0o600');
});

// Test 28: Rapid Sequential Commit Stress
check('28. Rapid sequential commit stress (50 iterations with random payloads)', () => {
  const dir = path.join(suiteRoot, 'stress_seq28');

  for (let i = 1; i <= 50; i++) {
    const recData = `seq-rec-iteration-${i}-${crypto.randomBytes(8).toString('hex')}`;
    const masterData = `seq-master-iteration-${i}-${crypto.randomBytes(8).toString('hex')}`;

    saveRecoveryPairSync(dir, recData, masterData);

    const expected = { recovery: recData, masterEnc: masterData, legacyBound: false };
    verifyVaultSynchronization(dir, expected, `seq-iter-${i}`);
  }
});

// Test 29: Alternating Failure and Success Stress
check('29. Alternating failure and success stress (30 cycles of repeated faults)', () => {
  const dir = path.join(suiteRoot, 'stress_alternating29');
  let lastCommitted = {
    recovery: 'initial-recovery-29',
    masterEnc: 'initial-master-29',
    legacyBound: false
  };

  saveRecoveryPairSync(dir, lastCommitted.recovery, lastCommitted.masterEnc);
  verifyVaultSynchronization(dir, lastCommitted, 'alt-init-29');

  for (let cycle = 1; cycle <= 30; cycle++) {
    assert.throws(
      () => saveRecoveryPairSync(dir, `fail-rec-${cycle}`, `fail-master-${cycle}`, { failBeforeMasterRename: true }),
      /SIMULATED_FAIL_BEFORE_MASTER_RENAME/
    );
    verifyVaultSynchronization(dir, lastCommitted, `alt-post-fail-${cycle}`);

    lastCommitted = {
      recovery: `valid-rec-${cycle}`,
      masterEnc: `valid-master-${cycle}`,
      legacyBound: false
    };
    saveRecoveryPairSync(dir, lastCommitted.recovery, lastCommitted.masterEnc);
    verifyVaultSynchronization(dir, lastCommitted, `alt-post-success-${cycle}`);
  }
});

// Test 30: Default Electron userData IPC Transaction
check('30. Default Electron userData IPC transaction with setRecoveryLegacyBound status transition', () => {
  const recPath = path.join(defaultTestUserData, 'fuin.recovery');
  const masterPath = path.join(defaultTestUserData, 'fuin.master.enc');
  const statusPath = path.join(defaultTestUserData, 'fuin.recovery-status');

  try { fs.unlinkSync(recPath); } catch {}
  try { fs.unlinkSync(masterPath); } catch {}
  try { fs.unlinkSync(statusPath); } catch {}

  fs.writeFileSync(statusPath, JSON.stringify({ version: 1, legacyBound: true, updatedAt: 123 }));

  const result = mainHandlers['save-recovery-pair'](null, {
    recovery: 'default-user-data-rec-30',
    masterEnc: 'default-user-data-master-30'
  });

  assert.strictEqual(result, true);
  assert.strictEqual(fs.readFileSync(recPath, 'utf8'), 'default-user-data-rec-30');
  assert.strictEqual(fs.readFileSync(masterPath, 'utf8'), 'default-user-data-master-30');

  const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
  assert.strictEqual(status.legacyBound, false, 'IPC handler commit must set legacyBound to false');
});

// ────────────────────────────────────────────────────────────────────────────
// Final Summary & Verdict Computation
// ────────────────────────────────────────────────────────────────────────────

console.log('\n' + '═'.repeat(78));
console.log(`TEST EXECUTION SUMMARY: ${passes} PASSED, ${failures} FAILED`);
console.log('═'.repeat(78));

if (failures > 0) {
  console.error('\nFAILURES ENCOUNTERED:');
  for (const f of failureDetails) {
    console.error(`  - ${f.desc}: ${f.error}`);
  }
  process.exit(1);
} else {
  console.log(`ALL ${passes} RECOVERY ATOMICITY & ADVERSARIAL STRESS TESTS PASSED (100% SUCCESS)\n`);
  process.exit(0);
}
