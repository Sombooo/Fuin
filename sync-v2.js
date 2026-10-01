'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — PHASE 4: Desktop End-to-End Orchestration
// sync-v2.js
//
// This module connects:
//   Phase 1 (sync-v2-crypto.js)   — Argon2id + XChaCha20-Poly1305 + envelope
//   Phase 2 (sync-v2-payload.js)  — Canonical CBOR + zstd + snapshot_hash
//   Phase 3 (sync-v2-transport.js)— Base45 + CRC32 + QR wire format
//
// SECURITY BOUNDARY:
//   - Vault Password feeds existing decryptData() (Vault layer, untouched)
//   - Sync Password feeds deriveSyncKey() (Sync layer, Phase 1)
//   - These two passwords MUST remain strictly separate
//   - machineId MUST NOT enter Sync Key derivation (INV-03)
//   - Plaintext entries MUST NOT be written to disk
//   - Plaintext entries MUST NOT be logged
//
// GENERATION SEMANTICS:
//   Generation increments when a new snapshot payload is BUILT (option B from spec).
//   Rationale: V2 is currently one-way Desktop→Mobile with no Mobile ACK channel.
//   Incrementing at build time ensures monotonicity and determinism without
//   requiring Mobile acknowledgment. Each "rebuild" in the UI generates a new
//   snapshot with a higher generation. The generation persists across restarts.
//
// OVERSIZED PAYLOAD LIMIT:
//   MAX_QR_CHUNKS = 500 chunks. At 200B/chunk, this allows ~100KB plaintext entries.
//   A typical password vault of 1000 entries is well within this limit.
//   If exceeded, sync is rejected before encryption.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto   = require('crypto');
const syncCrypto  = require('./sync-v2-crypto.js');
const { buildSyncPayload, GenerationManager, sanitizeForCBOR, computeSnapshotHash } = require('./sync-v2-payload.js');
const transport   = require('./sync-v2-transport.js');

// Max chunks before rejecting (transport guard)
const MAX_QR_CHUNKS = 500;

// ── ACTIVE SYNC SESSION STATE ─────────────────────────────────────────────────
// All mutable session state is owned here, not scattered across main.js globals.

/** @type {string[]|null} Current V2 QR chunk strings */
let _activeChunks = null;

/** @type {string|null} Session ID hex (for UI display) */
let _activeSessionIdHex = null;

/** @type {NodeJS.Timeout|null} Auto-expiry timer */
let _sessionTimer = null;

/** @type {Function|null} Expiry callback registered by main.js */
let _onExpiry = null;

const SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Register a callback to be invoked when the session auto-expires.
 * @param {Function} cb
 */
function onSessionExpiry(cb) {
  _onExpiry = cb;
}

function _clearSession() {
  _activeChunks      = null;
  _activeSessionIdHex = null;
  if (_sessionTimer) { clearTimeout(_sessionTimer); _sessionTimer = null; }
}

/**
 * Explicitly cancel any active sync session (e.g. user clicks "Close").
 */
function cancelSyncSession() {
  _clearSession();
}

/**
 * Return true if a sync session is currently active.
 */
function isSyncSessionActive() {
  return _activeChunks !== null;
}

// ── GENERATION MANAGER (lazy-initialized with userData path) ──────────────────
let _generationManager = null;

/**
 * Initialize the generation manager with the Electron userData path.
 * Must be called once from main.js after app is ready.
 * @param {string} userDataPath
 */
function initGenerationManager(userDataPath) {
  if (_generationManager) return; // already initialized
  _generationManager = new GenerationManager(userDataPath);
}

function _requireGenerationManager() {
  if (!_generationManager) {
    throw new Error('SYNC_V2: GenerationManager not initialized. Call initGenerationManager() first.');
  }
  return _generationManager;
}

// ── VAULT ENTRY EXTRACTION ────────────────────────────────────────────────────

/**
 * Sanitize and extract exportable Vault entries from the plaintext payload.
 *
 * The existing persist() call in app.js produces:
 *   { type: 'fuin/vault', categories: [], entries: [...] }
 *
 * For sync we need only the entries array.
 * We do NOT re-encrypt here — decryptData() was already called upstream.
 *
 * @param {object} vaultPlaintext  Result of decryptData()
 * @returns {Array}  Vault entries array
 */
function extractVaultEntries(vaultPlaintext) {
  if (!vaultPlaintext || typeof vaultPlaintext !== 'object') {
    throw new TypeError('SYNC_V2: extractVaultEntries: expected an object from decryptData()');
  }
  // Vault structure: { type: 'fuin/vault', categories: [], entries: [...] }
  // Also accept partial payload from openSyncWindow (mode=partial)
  const entries = vaultPlaintext.entries;
  if (!Array.isArray(entries)) {
    throw new TypeError('SYNC_V2: extractVaultEntries: vaultPlaintext.entries is not an array');
  }
  return entries;
}

// ── PRIMARY V2 SYNC PIPELINE ──────────────────────────────────────────────────

/**
 * Build a complete V2 QR chunk set from plaintext Vault entries and a Sync Password.
 *
 * SECURITY:
 *   - syncPassword feeds deriveSyncKey() only (NOT Vault Password)
 *   - entries are plaintext from decryptData() — callers must ensure this
 *   - no plaintext is written to disk at any step
 *   - all intermediate Buffers are zeroed after use where possible
 *
 * @param {Array}  entries       Plaintext Vault entries (from extractVaultEntries)
 * @param {string} syncPassword  Sync Password (separate from Vault Password)
 * @returns {Promise<{ qrChunks: string[], sessionIdHex: string, generation: number, total: number }>}
 */
async function buildV2QRChunks(entries, syncPassword) {
  // Validate inputs
  if (!Array.isArray(entries)) {
    throw new TypeError('SYNC_V2: entries must be an array');
  }
  if (typeof syncPassword !== 'string' || syncPassword.length === 0) {
    throw new Error('SYNC_V2: Sync Password is required and must be a non-empty string');
  }

  const genManager = _requireGenerationManager();

  // ── PHASE 1: Generate session parameters ─────────────────────────────────
  const salt      = syncCrypto.generateSyncSalt();     // 16B CSPRNG
  const sessionId = syncCrypto.generateSessionId();    // 8B CSPRNG
  const sessHex   = sessionId.toString('hex');         // 16 lowercase hex chars

  // ── PHASE 1: Derive Sync Key ──────────────────────────────────────────────
  // INV-05: Argon2id only, no PBKDF2 fallback
  // INV-06: m=65536, t=3, p=4, effective_salt=salt||"FUIN_SYNC_V2"
  // INV-03: machineId NOT used here
  let key = null;
  try {
    key = await syncCrypto.deriveSyncKey(syncPassword, salt);
  } catch (e) {
    // Key derivation failed — clean up and rethrow
    salt.fill(0);
    sessionId.fill(0);
    throw new Error(`SYNC_V2: Key derivation failed — ${e.message}`);
  }

  // ── PHASE 1: Build AAD ────────────────────────────────────────────────────
  // INV-16: AAD = [0x02][sessionId:8B][salt:16B] = exactly 25 bytes
  const aad = syncCrypto.buildAAD(sessionId, salt);

  // ── PHASE 2: Build payload CBOR + zstd ───────────────────────────────────
  let compressedBytes = null;
  try {
    const result = await buildSyncPayload(entries, sessionId, genManager);
    compressedBytes = result.compressedBytes;
    // result.snapshotHash and result.generation are embedded in the payload
  } catch (e) {
    // Clean up sensitive material before rethrowing
    if (key) { key.fill(0); }
    salt.fill(0);
    sessionId.fill(0);
    throw new Error(`SYNC_V2: Payload build failed — ${e.message}`);
  }

  // ── PHASE 1: Encrypt ──────────────────────────────────────────────────────
  // INV-07: XChaCha20-Poly1305
  // INV-08: 24B CSPRNG nonce (generated inside syncEncrypt)
  let envelope = null;
  try {
    const { ciphertext, nonce } = syncCrypto.syncEncrypt(compressedBytes, key, aad);

    // Zero compressed payload immediately after encryption
    compressedBytes.fill(0);
    compressedBytes = null;

    // ── PHASE 1: Build outer envelope ─────────────────────────────────────
    envelope = syncCrypto.buildEnvelope(salt, nonce, ciphertext);
  } catch (e) {
    if (key) { key.fill(0); }
    salt.fill(0);
    sessionId.fill(0);
    if (compressedBytes) { compressedBytes.fill(0); }
    throw new Error(`SYNC_V2: Encryption failed — ${e.message}`);
  } finally {
    // Key is no longer needed after encryption
    if (key) { key.fill(0); key = null; }
    salt.fill(0);
    sessionId.fill(0);
  }

  // ── PHASE 3: Chunk envelope → QR strings ─────────────────────────────────
  let qrChunks;
  try {
    qrChunks = transport.buildQRChunks(envelope, sessHex);
  } catch (e) {
    throw new Error(`SYNC_V2: Transport chunking failed — ${e.message}`);
  }

  // Oversized payload guard
  if (qrChunks.length > MAX_QR_CHUNKS) {
    throw new Error(
      `SYNC_V2: Payload too large — generated ${qrChunks.length} QR chunks ` +
      `(max ${MAX_QR_CHUNKS}). Reduce the number of entries or contact support.`
    );
  }

  // ── SESSION STATE ─────────────────────────────────────────────────────────
  _clearSession();
  _activeChunks       = qrChunks;
  _activeSessionIdHex = sessHex;

  // Auto-expiry timer
  _sessionTimer = setTimeout(() => {
    _clearSession();
    if (_onExpiry) _onExpiry();
  }, SESSION_TIMEOUT_MS);

  return {
    qrChunks,
    sessionIdHex: sessHex,
    generation:   genManager.get(),
    total:        qrChunks.length,
  };
}

/**
 * Rebuild QR chunks for the SAME session state.
 * Each rebuild creates a new session (new salt, sessionId, nonce) per spec.
 *
 * @param {Array}  entries
 * @param {string} syncPassword
 * @returns {Promise<{ qrChunks: string[], ... }>}
 */
async function rebuildV2QRChunks(entries, syncPassword) {
  // Full rebuild — clears old session, creates new cryptographic parameters
  return buildV2QRChunks(entries, syncPassword);
}

/**
 * Return the currently active QR chunk strings, or null.
 * @returns {string[]|null}
 */
function getActiveChunks() {
  return _activeChunks;
}

/**
 * Return the current session ID hex, or null.
 * @returns {string|null}
 */
function getActiveSessionIdHex() {
  return _activeSessionIdHex;
}

// ── EXPORTS ───────────────────────────────────────────────────────────────────

module.exports = {
  // Lifecycle
  initGenerationManager,
  onSessionExpiry,
  cancelSyncSession,
  isSyncSessionActive,
  getActiveChunks,
  getActiveSessionIdHex,

  // Vault extraction
  extractVaultEntries,

  // Pipeline
  buildV2QRChunks,
  rebuildV2QRChunks,
  computeSnapshotHash,

  // Constants
  MAX_QR_CHUNKS,
};
