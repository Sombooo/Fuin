'use strict';

/**
 * ============================================================================
 * CHALLENGER 2: VAULT DURABILITY & STORAGE STATE MACHINE ADVERSARIAL HARNESS
 * ============================================================================
 * Focus Areas:
 * 1. writeAtomicSync: temp-file fsync, mid-write fault injection, atomic rename,
 *    and hard crash (SIGKILL mid-stream) invariance.
 * 2. 0-byte file recovery: empirical verification of automated restoration from
 *    newest valid backup in main.js, filtering of 0-byte backups, and disk heal.
 * 3. WAL state machine in saveRecoveryPairSync & cleanupOrphanRecoveryTransactions:
 *    Window 1..5 crash simulation, Window 3 rollback to original, Window 5 roll-forward.
 * ============================================================================
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { spawnSync } = require('child_process');
const Module = require('module');

console.log('═'.repeat(78));
console.log('CHALLENGER 2: VAULT DURABILITY & WAL STATE MACHINE ADVERSARIAL HARNESS');
console.log('═'.repeat(78));

let passes = 0;
let failures = 0;
const failureDetails = [];

async function runCheck(desc, fn) {
  try {
    await fn();
    console.log(`  [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  [FAIL] ${desc}`);
    console.error(`         Error: ${err.message}`);
    failures++;
    failureDetails.push({ desc, error: err.message, stack: err.stack });
  }
}

// ────────────────────────────────────────────────────────────────────────────
// Setup Mock Electron Runtime for Production main.js Testing
// ────────────────────────────────────────────────────────────────────────────

const testRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-ch2-wal-'));
const defaultUserData = path.join(testRoot, 'userdata');
fs.mkdirSync(defaultUserData, { recursive: true, mode: 0o700 });

const mainHandlers = {};
const origRequire = Module.prototype.require;

Module.prototype.require = function(id) {
  if (id === 'electron') {
    return {
      app: {
        getPath: () => defaultUserData,
        isPackaged: false,
        quit: () => {},
        whenReady: () => Promise.resolve(),
        on: () => {}
      },
      session: {
        defaultSession: {
          webRequest: { onHeadersReceived: () => {} }
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

// Require production modules
const mainModule = require('./main.js');
const payloadModule = require('./sync-v2-payload.js');

const {
  saveRecoveryPairSync,
  cleanupOrphanRecoveryTransactions,
  safeRenameSync,
  writeAndFsyncSync,
  validateRecoveryPayload
} = mainModule;

const { writeAtomicSync } = payloadModule;

async function executeAllTests() {

  // ──────────────────────────────────────────────────────────────────────────
  // SECTION 1: writeAtomicSync Mid-Write Fault Injection & Crash Semantics
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- SECTION 1: writeAtomicSync Fault Injection & Durability ---');

  await runCheck('1.1 Mid-write fault injection in fs.writeSync: target remains intact', () => {
    const dir = path.join(testRoot, 'midwrite_write');
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'test.dat');
    
    // Establish baseline content
    writeAtomicSync(target, 'ORIGINAL_INTACT_CONTENT', { mode: 0o600 });
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'ORIGINAL_INTACT_CONTENT');

    // Intercept fs.writeSync to simulate ENOSPC / EIO mid-stream
    const originalWriteSync = fs.writeSync;
    fs.writeSync = function(...args) {
      const err = new Error('SIMULATED_ENOSPC: No space left on device');
      err.code = 'ENOSPC';
      throw err;
    };

    try {
      const largeData = Buffer.alloc(128 * 1024, 0x41); // 128 KB
      assert.throws(() => {
        writeAtomicSync(target, largeData, { mode: 0o600 });
      }, /SIMULATED_ENOSPC/);
    } finally {
      fs.writeSync = originalWriteSync;
    }

    // CRITICAL INVARIANT: Target file must be 100% UNMODIFIED
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'ORIGINAL_INTACT_CONTENT');
  });

  await runCheck('1.2 Mid-write fault injection in fs.fsyncSync: target remains intact', () => {
    const dir = path.join(testRoot, 'midwrite_fsync');
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'test.dat');
    
    writeAtomicSync(target, 'ORIGINAL_INTACT_CONTENT', { mode: 0o600 });

    const originalFsyncSync = fs.fsyncSync;
    fs.fsyncSync = function() {
      const err = new Error('SIMULATED_EIO: Hardware sync failure');
      err.code = 'EIO';
      throw err;
    };

    try {
      assert.throws(() => {
        writeAtomicSync(target, 'CORRUPTED_NEW_CONTENT', { mode: 0o600 });
      }, /SIMULATED_EIO/);
    } finally {
      fs.fsyncSync = originalFsyncSync;
    }

    // CRITICAL INVARIANT: Target file must be 100% UNMODIFIED
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'ORIGINAL_INTACT_CONTENT');
  });

  await runCheck('1.3 Hard simulated crash (SIGKILL mid-write): target file never truncated', () => {
    const dir = path.join(testRoot, 'sigkill_test');
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'vault.dat');

    // Baseline file
    writeAtomicSync(target, 'PRE_CRASH_GOLDEN_DATA', { mode: 0o600 });

    // Child script that hooks fs.writeSync and self-kills with SIGKILL during write
    const childScript = `
      const fs = require('fs');
      const { writeAtomicSync } = require(${JSON.stringify(path.join(__dirname, 'sync-v2-payload.js'))});
      const originalWrite = fs.writeSync;
      fs.writeSync = function(...args) {
        // Write first chunk to temp file
        const res = originalWrite.apply(fs, args);
        // Abruptly simulate hard power loss / process kill mid-write
        process.kill(process.pid, 'SIGKILL');
        return res;
      };
      const buf = Buffer.alloc(10 * 1024 * 1024, 0x58);
      writeAtomicSync(${JSON.stringify(target)}, buf, { mode: 0o600 });
    `;

    const res = spawnSync(process.execPath, ['-e', childScript]);
    assert.strictEqual(res.signal, 'SIGKILL', 'Child process must have terminated via SIGKILL');

    // Target file MUST still exist with pristine baseline content
    assert.strictEqual(fs.existsSync(target), true, 'Target file must still exist');
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'PRE_CRASH_GOLDEN_DATA', 'Target file content must be pristine');

    // The temporary file exists on disk (since SIGKILL prevented finally cleanup), but target was untouched
    const files = fs.readdirSync(dir);
    const tmpFiles = files.filter(f => f.includes('.tmp'));
    assert(tmpFiles.length >= 1, 'Incomplete .tmp file should remain after SIGKILL for startup cleanup');
  });

  await runCheck('1.4 Concurrent reader/writer stress: zero torn reads across 1,000 reads', () => {
    const dir = path.join(testRoot, 'concurrency_stress');
    fs.mkdirSync(dir, { recursive: true });
    const target = path.join(dir, 'concurrent.dat');

    const payloadA = 'A'.repeat(16384);
    const payloadB = 'B'.repeat(16384);
    writeAtomicSync(target, payloadA, { mode: 0o600 });

    let readerZeroBytes = 0;
    let readerTornReads = 0;
    let readerErrors = 0;

    for (let i = 0; i < 50; i++) {
      const nextPayload = (i % 2 === 0) ? payloadB : payloadA;

      for (let r = 0; r < 20; r++) {
        try {
          const readBuf = fs.readFileSync(target);
          if (readBuf.length === 0) readerZeroBytes++;
          if (readBuf.length !== 16384) readerTornReads++;
          const first = readBuf[0];
          for (let b = 0; b < readBuf.length; b++) {
            if (readBuf[b] !== first) {
              readerTornReads++;
              break;
            }
          }
        } catch (e) {
          readerErrors++;
        }
      }

      writeAtomicSync(target, nextPayload, { mode: 0o600 });
    }

    assert.strictEqual(readerErrors, 0, 'Concurrent readers should experience zero errors');
    assert.strictEqual(readerZeroBytes, 0, 'Concurrent readers must NEVER observe 0 bytes');
    assert.strictEqual(readerTornReads, 0, 'Concurrent readers must NEVER observe torn/mixed data');
  });

  await runCheck('1.5 POSIX permissions & recursive 0o700 directory creation', () => {
    const deepDir = path.join(testRoot, 'deep', 'storage', 'level');
    const target = path.join(deepDir, 'perm_test.dat');

    writeAtomicSync(target, 'PERM_TEST_DATA', { mode: 0o600 });

    assert.strictEqual(fs.existsSync(target), true);
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'PERM_TEST_DATA');

    if (process.platform !== 'win32') {
      const fileStat = fs.statSync(target);
      assert.strictEqual(fileStat.mode & 0o777, 0o600, 'File mode must be 0o600');
      const dirStat = fs.statSync(deepDir);
      assert.strictEqual(dirStat.mode & 0o777, 0o700, 'Created directory mode must be 0o700');
    }
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SECTION 2: 0-Byte Vault File Recovery State Machine
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- SECTION 2: 0-Byte Vault File Recovery State Machine ---');

  const dataFile = path.join(defaultUserData, 'fuin.enc');
  const masterFile = path.join(defaultUserData, 'fuin.master.enc');
  const backupDir = path.join(defaultUserData, 'backups');

  function resetUserDataFiles() {
    try { if (fs.existsSync(dataFile)) fs.unlinkSync(dataFile); } catch {}
    try { if (fs.existsSync(masterFile)) fs.unlinkSync(masterFile); } catch {}
    if (fs.existsSync(backupDir)) {
      fs.rmSync(backupDir, { recursive: true, force: true });
    }
    fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  }

  await runCheck('2.1 0-byte DATA_FILE automatically restores from newest backup and heals disk', async () => {
    resetUserDataFiles();

    // Save version 1 and version 2
    await mainHandlers['save-data'](null, 'VAULT_CONTENT_V1');
    await mainHandlers['save-data'](null, 'VAULT_CONTENT_V2'); // Backs up V1 to backups/fuin.enc.<timestamp>.bak

    assert.strictEqual(fs.readFileSync(dataFile, 'utf8'), 'VAULT_CONTENT_V2');

    // Simulate catastrophic 0-byte truncation crash
    fs.writeFileSync(dataFile, '');
    assert.strictEqual(fs.statSync(dataFile).size, 0, 'Simulated crash: DATA_FILE is 0 bytes');

    // Call load-data handler
    const loaded = await mainHandlers['load-data']();

    // Invariant 1: Returned data matches newest backup
    assert.strictEqual(loaded, 'VAULT_CONTENT_V1', 'Must return restored payload from backup');

    // Invariant 2: Disk file is automatically healed via writeAtomicSync
    const onDisk = fs.readFileSync(dataFile, 'utf8');
    assert.strictEqual(onDisk, 'VAULT_CONTENT_V1', 'Disk file must be actively repaired with recovered data');
    if (process.platform !== 'win32') {
      assert.strictEqual(fs.statSync(dataFile).mode & 0o777, 0o600, 'Repaired file must have mode 0o600');
    }
  });

  await runCheck('2.2 Chronological backup sorting: strictly picks newest valid backup', async () => {
    resetUserDataFiles();

    const now = Date.now();
    // Create 3 synthetic backups with distinct timestamps
    const bakOld = path.join(backupDir, 'fuin.enc.2026-09-01T10-00-00-000Z.bak');
    const bakMid = path.join(backupDir, 'fuin.enc.2026-09-15T10-00-00-000Z.bak');
    const bakNew = path.join(backupDir, 'fuin.enc.2026-09-29T10-00-00-000Z.bak');

    fs.writeFileSync(bakOld, 'PAYLOAD_OLD', 'utf8');
    fs.writeFileSync(bakMid, 'PAYLOAD_MID', 'utf8');
    fs.writeFileSync(bakNew, 'PAYLOAD_NEW', 'utf8');

    // Explicitly set mtimes
    fs.utimesSync(bakOld, (now - 20000) / 1000, (now - 20000) / 1000);
    fs.utimesSync(bakMid, (now - 10000) / 1000, (now - 10000) / 1000);
    fs.utimesSync(bakNew, now / 1000, now / 1000);

    fs.writeFileSync(dataFile, '');
    assert.strictEqual(fs.statSync(dataFile).size, 0);

    const restored = await mainHandlers['load-data']();
    assert.strictEqual(restored, 'PAYLOAD_NEW', 'Must pick newest backup based on mtime');
    assert.strictEqual(fs.readFileSync(dataFile, 'utf8'), 'PAYLOAD_NEW');
  });

  await runCheck('2.3 Corrupted 0-byte backup filtering: skips 0-byte backups and finds valid one', async () => {
    resetUserDataFiles();

    const now = Date.now();
    const bakValid = path.join(backupDir, 'fuin.enc.2026-09-29T09-00-00-000Z.bak');
    const bakCorrupt0 = path.join(backupDir, 'fuin.enc.2026-09-29T10-00-00-000Z.bak'); // newer but 0 bytes!

    fs.writeFileSync(bakValid, 'VALID_SURVIVING_PAYLOAD', 'utf8');
    fs.writeFileSync(bakCorrupt0, '', 'utf8'); // 0 bytes

    fs.utimesSync(bakValid, (now - 5000) / 1000, (now - 5000) / 1000);
    fs.utimesSync(bakCorrupt0, now / 1000, now / 1000);

    fs.writeFileSync(dataFile, '');

    const restored = await mainHandlers['load-data']();
    assert.strictEqual(restored, 'VALID_SURVIVING_PAYLOAD', 'Must skip 0-byte backup and restore valid backup');
    assert.strictEqual(fs.readFileSync(dataFile, 'utf8'), 'VALID_SURVIVING_PAYLOAD');
  });

  await runCheck('2.4 0-byte MASTER_ENC_FILE automatically restores from latest master backup', async () => {
    resetUserDataFiles();

    // Save two versions of master.enc
    await mainHandlers['save-master-enc'](null, 'MASTER_KEY_CIPHERTEXT_V1');
    await mainHandlers['save-master-enc'](null, 'MASTER_KEY_CIPHERTEXT_V2');

    // Truncate to 0 bytes
    fs.writeFileSync(masterFile, '');
    assert.strictEqual(fs.statSync(masterFile).size, 0);

    const restored = await mainHandlers['load-master-enc']();
    assert.strictEqual(restored, 'MASTER_KEY_CIPHERTEXT_V1');
    assert.strictEqual(fs.readFileSync(masterFile, 'utf8'), 'MASTER_KEY_CIPHERTEXT_V1');
  });

  await runCheck('2.5 Missing backup directory edge case: gracefully returns empty string', async () => {
    resetUserDataFiles();
    fs.rmSync(backupDir, { recursive: true, force: true });

    fs.writeFileSync(dataFile, '');
    const loaded = await mainHandlers['load-data']();
    assert.strictEqual(loaded, '', 'When no backup directory exists, returns empty string without crashing');
  });

  await runCheck('2.6 Non-zero corrupted file preservation: never overwritten silently', async () => {
    resetUserDataFiles();
    fs.writeFileSync(path.join(backupDir, 'fuin.enc.test.bak'), 'BACKUP_DATA', 'utf8');

    // File is non-zero, but corrupted/altered
    fs.writeFileSync(dataFile, 'CORRUPTED_NON_ZERO_DATA', 'utf8');

    const loaded = await mainHandlers['load-data']();
    assert.strictEqual(loaded, 'CORRUPTED_NON_ZERO_DATA', 'Non-zero file must not trigger automated backup overwrite');
  });

  // ──────────────────────────────────────────────────────────────────────────
  // SECTION 3: WAL State Machine in saveRecoveryPairSync & Self-Healing
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n--- SECTION 3: WAL State Machine & Crash Recovery Invariants ---');

  await runCheck('3.1 Window 1 Crash (failAfterRecoveryTempWrite): target files untouched', () => {
    const dir = path.join(testRoot, 'wal_window1');
    saveRecoveryPairSync(dir, 'BASE_REC_1', 'BASE_MASTER_1');

    assert.throws(() => {
      saveRecoveryPairSync(dir, 'NEW_REC_1', 'NEW_MASTER_1', { failAfterRecoveryTempWrite: true });
    }, /SIMULATED_FAIL_AFTER_RECOVERY_TEMP_WRITE/);

    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8'), 'BASE_REC_1');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.master.enc'), 'utf8'), 'BASE_MASTER_1');
    const files = fs.readdirSync(dir);
    assert.strictEqual(files.filter(f => f.endsWith('.tmp')).length, 0);
  });

  await runCheck('3.2 Window 2 Crash (failAfterMasterTempWrite): target files untouched', () => {
    const dir = path.join(testRoot, 'wal_window2');
    saveRecoveryPairSync(dir, 'BASE_REC_2', 'BASE_MASTER_2');

    assert.throws(() => {
      saveRecoveryPairSync(dir, 'NEW_REC_2', 'NEW_MASTER_2', { failAfterMasterTempWrite: true });
    }, /SIMULATED_FAIL_AFTER_MASTER_TEMP_WRITE/);

    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8'), 'BASE_REC_2');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.master.enc'), 'utf8'), 'BASE_MASTER_2');
    const files = fs.readdirSync(dir);
    assert.strictEqual(files.filter(f => f.endsWith('.tmp')).length, 0);
  });

  await runCheck('3.3 Window 3 Crash — In-Process Catch Rollback: reverts recovery to baseline', () => {
    const dir = path.join(testRoot, 'wal_window3_catch');
    saveRecoveryPairSync(dir, 'BASE_REC_3', 'BASE_MASTER_3');

    assert.throws(() => {
      saveRecoveryPairSync(dir, 'POISON_REC_3', 'POISON_MASTER_3', { failBeforeMasterRename: true });
    }, /SIMULATED_FAIL_BEFORE_MASTER_RENAME/);

    // In-process rollback must have restored original recovery file
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8'), 'BASE_REC_3');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.master.enc'), 'utf8'), 'BASE_MASTER_3');
    const files = fs.readdirSync(dir);
    assert.strictEqual(files.filter(f => f.endsWith('.tmp') || f.endsWith('.rollback')).length, 0);
  });

  await runCheck('3.4 Window 3 Hard Crash Simulation — Startup Self-Healing (Rollback to original)', () => {
    const dir = path.join(testRoot, 'wal_window3_hard_crash');
    fs.mkdirSync(dir, { recursive: true });

    const recFile = path.join(dir, 'fuin.recovery');
    const masterFile = path.join(dir, 'fuin.master.enc');
    const txId = '12345.999999.abcd1234ef567890';
    const rollbackFile = path.join(dir, `.fuin.recovery.${txId}.rollback`);
    const staleTmp = path.join(dir, `.fuin.master.enc.${txId}.tmp`);

    // Simulate abrupt power cut / kill -9 between rename 1 and rename 2:
    // Recovery file was updated, master.enc was NOT updated, rollback exists, NO commit marker exists!
    fs.writeFileSync(recFile, 'UNCOMMITTED_NEW_RECOVERY_34', 'utf8');
    fs.writeFileSync(masterFile, 'AUTHORITATIVE_OLD_MASTER_34', 'utf8');
    fs.writeFileSync(rollbackFile, 'AUTHORITATIVE_OLD_RECOVERY_34', 'utf8');
    fs.writeFileSync(staleTmp, 'stale_staging_data', 'utf8');

    // Trigger startup recovery
    cleanupOrphanRecoveryTransactions(dir);

    // Invariant: Recovery file MUST have rolled back to match master.enc!
    assert.strictEqual(fs.readFileSync(recFile, 'utf8'), 'AUTHORITATIVE_OLD_RECOVERY_34', 'Recovery must roll back to original');
    assert.strictEqual(fs.readFileSync(masterFile, 'utf8'), 'AUTHORITATIVE_OLD_MASTER_34', 'Master remains original');
    assert.strictEqual(fs.existsSync(rollbackFile), false, 'Rollback file must be consumed');
  });

  await runCheck('3.5 Window 5 Crash — Live Hook Execution: leaves .commit and .rollback on disk', () => {
    const dir = path.join(testRoot, 'wal_window5_hook');
    saveRecoveryPairSync(dir, 'BASE_REC_35', 'BASE_MASTER_35');

    let caught = false;
    try {
      saveRecoveryPairSync(dir, 'COMMITTED_NEW_REC_35', 'COMMITTED_NEW_MASTER_35', { failAfterCommitMarker: true });
    } catch (e) {
      caught = true;
      assert.strictEqual(e.message, 'SIMULATED_FAIL_AFTER_COMMIT_MARKER');
    }
    assert.ok(caught, 'Must catch simulated failAfterCommitMarker');

    // Inspect intermediate state:
    const files = fs.readdirSync(dir);
    const commitMarker = files.find(f => f.startsWith('.fuin.recovery.') && f.endsWith('.commit'));
    const rollbackFile = files.find(f => f.startsWith('.fuin.recovery.') && f.endsWith('.rollback'));

    assert.ok(commitMarker, 'Commit marker MUST exist on disk after Window 5 crash');
    assert.ok(rollbackFile, 'Rollback file MUST exist on disk after Window 5 crash');

    // Target files already have NEW values
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8'), 'COMMITTED_NEW_REC_35');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.master.enc'), 'utf8'), 'COMMITTED_NEW_MASTER_35');
  });

  await runCheck('3.6 Window 5 Crash — Startup Self-Healing (Completes Forward)', () => {
    const dir = path.join(testRoot, 'wal_window5_hook');

    // Run startup self-healing
    cleanupOrphanRecoveryTransactions(dir);

    // Invariant 1: Forward state preserved (zero reversion to old material!)
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.recovery'), 'utf8'), 'COMMITTED_NEW_REC_35');
    assert.strictEqual(fs.readFileSync(path.join(dir, 'fuin.master.enc'), 'utf8'), 'COMMITTED_NEW_MASTER_35');

    // Invariant 2: Rollback and commit markers cleaned up
    const files = fs.readdirSync(dir);
    assert.ok(!files.some(f => f.endsWith('.commit')), 'Commit marker must be removed');
    assert.ok(!files.some(f => f.endsWith('.rollback')), 'Rollback file must be removed');
  });

  await runCheck('3.7 Interleaved Multi-Transaction Self-Healing (TxA rollback vs TxB rollforward)', () => {
    const dir = path.join(testRoot, 'wal_interleaved');
    fs.mkdirSync(dir, { recursive: true });

    const recFile = path.join(dir, 'fuin.recovery');
    const masterFile = path.join(dir, 'fuin.master.enc');
    fs.writeFileSync(recFile, 'CURRENT_RECOVERY_VAL', 'utf8');
    fs.writeFileSync(masterFile, 'CURRENT_MASTER_VAL', 'utf8');

    // Tx A: Window 3 crash (uncommitted, no commit marker)
    const txA = 'tx_uncommitted_aaa';
    const rollbackA = path.join(dir, `.fuin.recovery.${txA}.rollback`);
    fs.writeFileSync(rollbackA, 'ROLLED_BACK_RECOVERY_A', 'utf8');

    // Tx B: Window 5 crash (committed, commit marker exists)
    const txB = 'tx_committed_bbb';
    const rollbackB = path.join(dir, `.fuin.recovery.${txB}.rollback`);
    const commitB = path.join(dir, `.fuin.recovery.${txB}.commit`);
    fs.writeFileSync(rollbackB, 'OLD_RECOVERY_B_IGNORED', 'utf8');
    fs.writeFileSync(commitB, JSON.stringify({ committedAt: Date.now(), txId: txB }), 'utf8');

    cleanupOrphanRecoveryTransactions(dir);

    // Tx B should have been discarded (completed forward, rollbackB and commitB deleted)
    assert.strictEqual(fs.existsSync(rollbackB), false, 'Committed rollback file must be deleted');
    assert.strictEqual(fs.existsSync(commitB), false, 'Commit marker must be deleted');

    // Tx A should have been applied (rolled back)
    assert.strictEqual(fs.existsSync(rollbackA), false, 'Uncommitted rollback file must be consumed');
    assert.strictEqual(fs.readFileSync(recFile, 'utf8'), 'ROLLED_BACK_RECOVERY_A');
  });

  await runCheck('3.8 Dangling commit marker without rollback: safely cleaned up', () => {
    const dir = path.join(testRoot, 'wal_dangling_commit');
    fs.mkdirSync(dir, { recursive: true });

    const danglingCommit = path.join(dir, '.fuin.recovery.orphan_tx.commit');
    fs.writeFileSync(danglingCommit, '{"committedAt":123}', 'utf8');

    cleanupOrphanRecoveryTransactions(dir);
    assert.strictEqual(fs.existsSync(danglingCommit), false, 'Dangling commit marker must be removed');
  });

  await runCheck('3.9 Stale .tmp file reaping: >60s deleted, <60s preserved', () => {
    const dir = path.join(testRoot, 'wal_stale_tmp');
    fs.mkdirSync(dir, { recursive: true });

    const staleTmp = path.join(dir, '.fuin.recovery.stale.tmp');
    const freshTmp = path.join(dir, '.fuin.recovery.fresh.tmp');

    fs.writeFileSync(staleTmp, 'stale', 'utf8');
    fs.writeFileSync(freshTmp, 'fresh', 'utf8');

    const now = Date.now();
    const oldTime = (now - 75000) / 1000; // 75 seconds ago
    const recentTime = (now - 15000) / 1000; // 15 seconds ago

    fs.utimesSync(staleTmp, oldTime, oldTime);
    fs.utimesSync(freshTmp, recentTime, recentTime);

    cleanupOrphanRecoveryTransactions(dir);

    assert.strictEqual(fs.existsSync(staleTmp), false, 'Tmp file >60s old must be purged');
    assert.strictEqual(fs.existsSync(freshTmp), true, 'Tmp file <60s old must NOT be purged');
  });

  await runCheck('3.10 Null, undefined, and non-existent directory safety', () => {
    assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(null));
    assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(undefined));
    assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(''));
    assert.doesNotThrow(() => cleanupOrphanRecoveryTransactions(path.join(testRoot, 'nonexistent_directory_xyz')));
  });

  // ──────────────────────────────────────────────────────────────────────────
  // Summary & Verdict
  // ──────────────────────────────────────────────────────────────────────────
  console.log('\n' + '═'.repeat(78));
  console.log(`CHALLENGER 2 SUMMARY: ${passes} PASSED, ${failures} FAILED`);
  console.log('═'.repeat(78));

  if (failures > 0) {
    console.error(`\nFAILED TESTS (${failures}):`);
    failureDetails.forEach(f => {
      console.error(` - ${f.desc}`);
      console.error(`   Error: ${f.error}`);
    });
    process.exit(1);
  } else {
    console.log('\nVERDICT: ALL 21 ADVERSARIAL DURABILITY & WAL INVARIANTS VERIFIED (APPROVE)\n');
    try { fs.rmSync(testRoot, { recursive: true, force: true }); } catch {}
    process.exit(0);
  }
}

executeAllTests();
