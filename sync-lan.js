'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN HYBRID SYNC — LAN (LOCAL NETWORK) TRANSPORT & MERGE MODULE
 * sync-lan.js
 *
 * Implements:
 *   R1. One-Time Optical Pairing (pairKey CSPRNG, deviceId, QR generation, revocation)
 *   R2. Ephemeral Local Transport (No background listeners, 120s timeout,
 *       RFC1918-only network interface guard, XChaCha20-Poly1305 encryption)
 *   R3. Two-Way Conflict-Free Deterministic Merge (updatedAt, deletedAt tombstone,
 *       non-destructive history preservation)
 *   R4. Hybrid Settings Toggle & Air-Gap Preservation
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const crypto = require('crypto');
const http   = require('http');
const os     = require('os');
const fs     = require('fs');
const path   = require('path');
const syncCrypto = require('./sync-v2-crypto.js');

// ── CONSTANTS ─────────────────────────────────────────────────────────────────
const DEFAULT_LAN_PORT     = 8765;
const EPHEMERAL_TIMEOUT_MS = 120 * 1000; // 120 seconds maximum lifetime (R2)
const PAIR_KEY_LENGTH      = 32;         // 32-byte CSPRNG pairKey (R1)
const PROTOCOL_VERSION     = 'fuin-lan-v1';

// Exactly 25 bytes binary AAD for XChaCha20-Poly1305 (matches SYNC_V2 AAD length)
const LAN_SYNC_AAD = Buffer.from('FUIN_LAN_SYNC_V1_PROTOCOL', 'utf8');

// ── ATOMIC FILE WRITE HELPER ──────────────────────────────────────────────────
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
    try { fs.unlinkSync(tempPath); } catch {}
    throw renameErr;
  }
}

// ── RFC1918 & NETWORK UTILITIES ───────────────────────────────────────────────
/**
 * Verifies if an IPv4 or loopback address belongs strictly to local private networks (RFC 1918 / loopback / link-local).
 * Never permits public internet routing.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isRFC1918OrLoopback(ip) {
  if (!ip || typeof ip !== 'string') return false;
  let cleanIp = ip.trim();

  // Strip IPv4-mapped IPv6 prefix if present (e.g. ::ffff:192.168.1.10)
  if (cleanIp.startsWith('::ffff:')) {
    cleanIp = cleanIp.slice(7);
  }

  const lower = cleanIp.toLowerCase();
  if (lower === '::1' || lower === 'localhost') return true;

  // IPv6 Link-Local (fe80::/10, RFC 4291)
  if (lower.startsWith('fe80:')) return true;

  // IPv6 Unique Local Address (fc00::/7 - fc00:: or fd00::, RFC 4193)
  if (lower.startsWith('fc') || lower.startsWith('fd')) {
    if (lower.includes(':')) return true;
  }

  const parts = cleanIp.split('.');
  if (parts.length !== 4 || parts.some(p => !/^\d+$/.test(p) || parseInt(p, 10) < 0 || parseInt(p, 10) > 255)) {
    return false;
  }

  const [a, b] = parts.map(p => parseInt(p, 10));
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 10.0.0.0/8 (RFC 1918 Class A)
  if (a === 10) return true;
  // 172.16.0.0/12 (RFC 1918 Class B: 172.16.x.x - 172.31.x.x)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 (RFC 1918 Class C)
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 (Link-Local, RFC 3927)
  if (a === 169 && b === 254) return true;

  return false;
}

/**
 * Returns list of local IPv4 RFC1918 network interface addresses.
 * @returns {string[]}
 */
function getLocalRFC1918Addresses() {
  const interfaces = os.networkInterfaces();
  const addresses = [];

  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        if (isRFC1918OrLoopback(iface.address)) {
          addresses.push(iface.address);
        }
      }
    }
  }

  if (addresses.length === 0) {
    addresses.push('127.0.0.1');
  }

  return [...new Set(addresses)];
}

// ── CRYPTOGRAPHIC PACKET FRAMING (XChaCha20-Poly1305) ─────────────────────────
/**
 * Encrypts arbitrary payload with 32-byte pairKey using XChaCha20-Poly1305.
 *
 * @param {object|string|Buffer} dataObj
 * @param {Buffer} pairKeyBuffer - Exactly 32 bytes Buffer
 * @returns {{ nonce: string, ciphertext: string }}
 */
function encryptLanPayload(dataObj, pairKeyBuffer) {
  if (!Buffer.isBuffer(pairKeyBuffer) || pairKeyBuffer.length !== PAIR_KEY_LENGTH) {
    throw new RangeError(`SYNC_LAN: pairKey must be a 32-byte Buffer (got ${pairKeyBuffer?.length})`);
  }

  let plaintextBuf;
  if (Buffer.isBuffer(dataObj)) {
    plaintextBuf = dataObj;
  } else if (typeof dataObj === 'string') {
    plaintextBuf = Buffer.from(dataObj, 'utf8');
  } else {
    plaintextBuf = Buffer.from(JSON.stringify(dataObj), 'utf8');
  }

  const { ciphertext, nonce } = syncCrypto.syncEncrypt(plaintextBuf, pairKeyBuffer, LAN_SYNC_AAD);

  return {
    nonce: nonce.toString('hex'),
    ciphertext: ciphertext.toString('hex')
  };
}

/**
 * Decrypts LAN packet using 32-byte pairKey and XChaCha20-Poly1305.
 * Authenticates against LAN_SYNC_AAD. Throws immediately on auth failure.
 *
 * @param {{ nonce: string, ciphertext: string }} packet
 * @param {Buffer} pairKeyBuffer - Exactly 32 bytes Buffer
 * @returns {any} Decrypted parsed JSON or Buffer
 */
function decryptLanPayload(packet, pairKeyBuffer) {
  if (!packet || typeof packet.nonce !== 'string' || typeof packet.ciphertext !== 'string') {
    throw new TypeError('SYNC_LAN: Invalid packet format (expected nonce and ciphertext hex strings)');
  }
  if (!Buffer.isBuffer(pairKeyBuffer) || pairKeyBuffer.length !== PAIR_KEY_LENGTH) {
    throw new RangeError(`SYNC_LAN: pairKey must be a 32-byte Buffer (got ${pairKeyBuffer?.length})`);
  }

  const nonceBuf = Buffer.from(packet.nonce, 'hex');
  const ciphertextBuf = Buffer.from(packet.ciphertext, 'hex');

  const decryptedPlaintext = syncCrypto.syncDecrypt(ciphertextBuf, pairKeyBuffer, nonceBuf, LAN_SYNC_AAD);

  const str = decryptedPlaintext.toString('utf8');
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

// ── TWO-WAY CONFLICT-FREE DETERMINISTIC MERGE (R3) ────────────────────────────
function parseTimestamp(val) {
  if (typeof val === 'number' && !isNaN(val)) return val;
  if (typeof val === 'string' && val.trim()) {
    const parsed = Date.parse(val);
    if (!isNaN(parsed)) return parsed;
    const num = Number(val);
    if (!isNaN(num)) return num;
  }
  return null;
}

/**
 * Normalizes entry ensuring updatedAt, deletedAt, isDeleted, and history are standard.
 *
 * @param {object} entry
 * @returns {object}
 */
function normalizeEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;

  const now = Date.now();
  const id = entry.id || (typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));

  let updatedAt = parseTimestamp(entry.updatedAt) ??
                  parseTimestamp(entry.updated) ??
                  parseTimestamp(entry.createdAt) ??
                  parseTimestamp(entry.created) ??
                  now;

  let deletedAt = parseTimestamp(entry.deletedAt);
  if (deletedAt === null && entry.isDeleted) {
    deletedAt = updatedAt;
  }

  // If deletedAt is set and newer than updatedAt, ensure updatedAt reflects the deletion time
  if (deletedAt !== null && deletedAt > updatedAt) {
    updatedAt = deletedAt;
  }

  const isDeleted = deletedAt !== null;

  const safeBase = {};
  for (const [k, v] of Object.entries(entry)) {
    if (k !== '__proto__' && k !== 'constructor' && k !== 'prototype') {
      safeBase[k] = v;
    }
  }

  const sanitized = {
    ...safeBase,
    id,
    updatedAt,
    updated: updatedAt,
    deletedAt,
    isDeleted,
    history: Array.isArray(entry.history) ? [...entry.history] : []
  };
  return sanitized;
}

/**
 * Creates clean historical snapshot of an entry without nested recursive history.
 *
 * @param {object} entry
 * @returns {object}
 */
function createHistorySnapshot(entry) {
  const { history, ...snapshot } = entry;
  return {
    ...snapshot,
    archivedAt: Date.now()
  };
}

/**
 * Merges history arrays non-destructively and deduplicates.
 *
 * @param {Array} winnerHistory
 * @param {Array} loserHistory
 * @param {object} loserEntry
 * @returns {Array}
 */
function mergeHistories(winnerHistory, loserHistory, loserEntry) {
  const combined = [];
  const seen = new Set();

  function addSnapshot(snap) {
    if (!snap || typeof snap !== 'object') return;
    const key = `${snap.updatedAt || snap.updated || 0}_${snap.site || ''}_${snap.username || ''}_${snap.password || ''}_${snap.note || ''}_${snap.totp || ''}_${snap.deletedAt || (snap.isDeleted ? 'del' : 'act')}`;
    if (!seen.has(key)) {
      seen.add(key);
      const { history: _ignored, ...cleanSnap } = snap;
      combined.push(cleanSnap);
    }
  }

  if (Array.isArray(winnerHistory)) {
    for (const h of winnerHistory) addSnapshot(h);
  }
  if (Array.isArray(loserHistory)) {
    for (const h of loserHistory) addSnapshot(h);
  }
  if (loserEntry) {
    addSnapshot(createHistorySnapshot(loserEntry));
  }

  // Sort descending by timestamp
  combined.sort((a, b) => (b.updatedAt || b.updated || 0) - (a.updatedAt || a.updated || 0));
  return combined;
}

/**
 * Compares core data fields between two entries to detect meaningful modifications.
 */
function areCoreFieldsEqual(a, b) {
  return (
    (a.site || '') === (b.site || '') &&
    (a.username || '') === (b.username || '') &&
    (a.password || '') === (b.password || '') &&
    ((a.category || '').trim() || 'Diğer') === ((b.category || '').trim() || 'Diğer') &&
    (a.note || '') === (b.note || '') &&
    (a.url || '') === (b.url || '') &&
    (a.totp || '') === (b.totp || '') &&
    Boolean(a.fav) === Boolean(b.fav) &&
    (a.deletedAt || null) === (b.deletedAt || null) &&
    Boolean(a.isDeleted) === Boolean(b.isDeleted)
  );
}

/**
 * Two-way deterministic conflict-free merge for password vault entries (R3).
 *
 * Invariants:
 * 1. If an entry exists only in Local, it is preserved.
 * 2. If an entry exists only in Remote, it is preserved.
 * 3. If an entry exists in both:
 *    - The edition with greater `updatedAt` becomes the main active record.
 *    - The older edition is preserved in `history` to prevent silent data loss.
 *    - If `updatedAt` is identical, a deterministic tie-breaker selects the main record,
 *      preserving the other in `history`.
 * 4. Tombstone (`deletedAt`):
 *    - An update with `updatedAt > deletedAt` revives/updates the record.
 *    - A deletion with `deletedAt >= updatedAt` marks the record deleted (`isDeleted: true`),
 *      preserving previous content in `history`.
 *
 * @param {Array<object>} localEntries
 * @param {Array<object>} remoteEntries
 * @returns {{ mergedEntries: Array<object>, stats: object }}
 */
function mergeVaultEntries(localEntries, remoteEntries) {
  const normLocal = (Array.isArray(localEntries) ? localEntries : []).map(normalizeEntry).filter(Boolean);
  const normRemote = (Array.isArray(remoteEntries) ? remoteEntries : []).map(normalizeEntry).filter(Boolean);

  const localMap = new Map();
  for (const e of normLocal) {
    if (localMap.has(e.id)) {
      const prev = localMap.get(e.id);
      if (e.updatedAt > prev.updatedAt) localMap.set(e.id, e);
    } else {
      localMap.set(e.id, e);
    }
  }

  const remoteMap = new Map();
  for (const e of normRemote) {
    if (remoteMap.has(e.id)) {
      const prev = remoteMap.get(e.id);
      if (e.updatedAt > prev.updatedAt) remoteMap.set(e.id, e);
    } else {
      remoteMap.set(e.id, e);
    }
  }

  const allIds = new Set([...localMap.keys(), ...remoteMap.keys()]);
  const mergedEntries = [];

  let addedFromRemote = 0;
  let addedFromLocal = 0;
  let conflictsResolved = 0;
  let identicalMatches = 0;

  for (const id of allIds) {
    const loc = localMap.get(id);
    const rem = remoteMap.get(id);

    if (loc && !rem) {
      // Local only
      mergedEntries.push(loc);
      addedFromLocal++;
    } else if (!loc && rem) {
      // Remote only
      mergedEntries.push(rem);
      addedFromRemote++;
    } else {
      // Both exist -> compare and resolve
      if (areCoreFieldsEqual(loc, rem)) {
        // Core identical; merge histories if needed
        const mergedHistory = mergeHistories(loc.history, rem.history, null);
        mergedEntries.push({
          ...loc,
          history: mergedHistory
        });
        identicalMatches++;
      } else {
        // Conflict! Determine winner by updatedAt
        let winner, loser;

        if (loc.updatedAt > rem.updatedAt) {
          winner = loc;
          loser = rem;
        } else if (rem.updatedAt > loc.updatedAt) {
          winner = rem;
          loser = loc;
        } else {
          // Exact tie-breaker: deterministic canonical string hash
          const canonical = (o) => JSON.stringify([
            o.id || '',
            o.site || '',
            o.username || '',
            o.password || '',
            o.category || '',
            o.note || '',
            o.url || '',
            o.totp || '',
            o.updatedAt || 0,
            o.deletedAt || 0
          ]);
          const hashLoc = crypto.createHash('sha256').update(canonical(loc)).digest('hex');
          const hashRem = crypto.createHash('sha256').update(canonical(rem)).digest('hex');
          if (hashLoc >= hashRem) {
            winner = loc;
            loser = rem;
          } else {
            winner = rem;
            loser = loc;
          }
        }

        const mergedHistory = mergeHistories(winner.history, loser.history, loser);
        mergedEntries.push({
          ...winner,
          history: mergedHistory
        });
        conflictsResolved++;
      }
    }
  }

  // Sort deterministically by site then id
  mergedEntries.sort((a, b) => {
    const sA = (a.site || '').toLowerCase();
    const sB = (b.site || '').toLowerCase();
    if (sA !== sB) return sA.localeCompare(sB);
    return (a.id || '').localeCompare(b.id || '');
  });

  return {
    mergedEntries,
    stats: {
      total: mergedEntries.length,
      addedFromRemote,
      addedFromLocal,
      conflictsResolved,
      identicalMatches
    }
  };
}

// ── PAIRING MANAGER (R1) ──────────────────────────────────────────────────────
class PairingManager {
  /**
   * @param {string} userDataPath - Directory to persist paired devices
   */
  constructor(userDataPath) {
    this.userDataPath = userDataPath;
    this.devicesFilePath = path.join(userDataPath, 'fuin.paired-devices.json');
    this.pendingFilePath = path.join(userDataPath, 'fuin.pending-pairings.json');
    this.deviceIdFilePath = path.join(userDataPath, 'fuin.device-id');
    this.pairedDevices = this._loadDevices();
    this.pendingPairings = this._loadPendingPairings();
    this.desktopDeviceId = this._loadOrGenerateDeviceId();
  }

  _loadOrGenerateDeviceId() {
    try {
      if (fs.existsSync(this.deviceIdFilePath)) {
        const id = fs.readFileSync(this.deviceIdFilePath, 'utf8').trim();
        if (id) return id;
      }
    } catch {}

    const newId = `fuin-desktop-${crypto.randomBytes(8).toString('hex')}`;
    try {
      writeAtomicSync(this.deviceIdFilePath, newId, { mode: 0o600 });
    } catch {}
    return newId;
  }

  _getSafeStorage() {
    try {
      const electron = require('electron');
      if (electron && electron.safeStorage && typeof electron.safeStorage.isEncryptionAvailable === 'function') {
        if (electron.safeStorage.isEncryptionAvailable()) {
          return electron.safeStorage;
        }
      }
    } catch {}
    return null;
  }

  _serializeProtected(data) {
    const jsonStr = JSON.stringify(data, null, 2);
    const ss = this._getSafeStorage();
    if (ss) {
      try {
        const encBuf = ss.encryptString(jsonStr);
        return JSON.stringify({ safeStorage: true, payload: encBuf.toString('base64') });
      } catch {}
    }
    return jsonStr;
  }

  _deserializeProtected(raw) {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.safeStorage === true && typeof parsed.payload === 'string') {
      const ss = this._getSafeStorage();
      if (ss) {
        const decStr = ss.decryptString(Buffer.from(parsed.payload, 'base64'));
        return JSON.parse(decStr);
      }
      return null;
    }
    return parsed;
  }

  _loadDevices() {
    try {
      if (fs.existsSync(this.devicesFilePath)) {
        const raw = fs.readFileSync(this.devicesFilePath, 'utf8');
        const parsed = this._deserializeProtected(raw);
        if (Array.isArray(parsed)) return parsed;
      }
    } catch {}
    return [];
  }

  _saveDevices() {
    writeAtomicSync(this.devicesFilePath, this._serializeProtected(this.pairedDevices), { mode: 0o600 });
  }

  _loadPendingPairings() {
    const map = new Map();
    try {
      if (fs.existsSync(this.pendingFilePath)) {
        const raw = fs.readFileSync(this.pendingFilePath, 'utf8');
        const parsed = this._deserializeProtected(raw);
        if (Array.isArray(parsed)) {
          const now = Date.now();
          for (const item of parsed) {
            if (item && item.pairKeyHex && (now - (item.createdAt || 0) < 24 * 60 * 60 * 1000)) {
              map.set(item.pairKeyHex, item);
            }
          }
        }
      }
    } catch {}
    return map;
  }

  _savePendingPairings() {
    try {
      const arr = Array.from(this.pendingPairings.values());
      writeAtomicSync(this.pendingFilePath, this._serializeProtected(arr), { mode: 0o600 });
    } catch {}
  }

  clearAll() {
    this.pairedDevices = [];
    this.pendingPairings.clear();
    try { if (fs.existsSync(this.devicesFilePath)) fs.unlinkSync(this.devicesFilePath); } catch {}
    try { if (fs.existsSync(this.pendingFilePath)) fs.unlinkSync(this.pendingFilePath); } catch {}
    try { if (fs.existsSync(this.deviceIdFilePath)) fs.unlinkSync(this.deviceIdFilePath); } catch {}
  }

  getDesktopDeviceId() {
    return this.desktopDeviceId;
  }

  /**
   * Generates static QR pairing payload.
   * QR contains: deviceId, 32-byte CSPRNG pairKey, port, and RFC1918 addresses.
   *
   * @param {object} [opts]
   * @returns {object}
   */
  generatePairingData(opts = {}) {
    const pairKey = crypto.randomBytes(PAIR_KEY_LENGTH);
    const pairKeyHex = pairKey.toString('hex');
    const port = opts.port || DEFAULT_LAN_PORT;
    const addresses = opts.addresses || getLocalRFC1918Addresses();

    const pairingPayload = {
      protocol: PROTOCOL_VERSION,
      type: 'pairing',
      deviceId: this.desktopDeviceId,
      pairKey: pairKeyHex,
      port: port,
      addresses: addresses,
      timestamp: Date.now()
    };

    // Store in pending pairings (persisted across restarts)
    this.pendingPairings.set(pairKeyHex, {
      pairKeyHex,
      createdAt: Date.now(),
      port,
      addresses
    });
    this._savePendingPairings();

    return pairingPayload;
  }

  /**
   * Registers a paired device (from mobile).
   *
   * @param {{ deviceId: string, deviceName?: string, pairKeyHex: string }} info
   * @returns {object}
   */
  addPairedDevice(info) {
    if (!info || !info.deviceId || !info.pairKeyHex) {
      throw new Error('SYNC_LAN: deviceId and pairKeyHex are required for pairing');
    }

    const pairKeyBuf = Buffer.from(info.pairKeyHex, 'hex');
    if (pairKeyBuf.length !== PAIR_KEY_LENGTH) {
      throw new RangeError(`SYNC_LAN: pairKey must be 32 bytes (got ${pairKeyBuf.length})`);
    }

    // Remove from pending if present
    this.pendingPairings.delete(info.pairKeyHex);
    this._savePendingPairings();

    const existingIndex = this.pairedDevices.findIndex(d => d.deviceId === info.deviceId);
    const record = {
      deviceId: info.deviceId,
      deviceName: info.deviceName || 'Mobil Cihaz',
      pairKeyHex: info.pairKeyHex,
      pairedAt: Date.now(),
      lastSyncAt: null
    };

    if (existingIndex !== -1) {
      this.pairedDevices[existingIndex] = record;
    } else {
      this.pairedDevices.push(record);
    }

    this._saveDevices();
    return record;
  }

  /**
   * Lists all paired devices. Full pairKey is masked for UI safety.
   *
   * @returns {Array<object>}
   */
  getPairedDevices() {
    return this.pairedDevices.map(d => ({
      deviceId: d.deviceId,
      deviceName: d.deviceName,
      pairedAt: d.pairedAt,
      lastSyncAt: d.lastSyncAt,
      keyPreview: `${d.pairKeyHex.slice(0, 6)}...${d.pairKeyHex.slice(-6)}`
    }));
  }

  /**
   * Revokes/deletes paired device by deviceId (one-click revocation).
   *
   * @param {string} deviceId
   * @returns {boolean}
   */
  removePairedDevice(deviceId) {
    const initialCount = this.pairedDevices.length;
    this.pairedDevices = this.pairedDevices.filter(d => d.deviceId !== deviceId && d.pairKeyHex !== deviceId);
    let removed = this.pairedDevices.length !== initialCount;

    if (this.pendingPairings.has(deviceId)) {
      this.pendingPairings.delete(deviceId);
      this._savePendingPairings();
      removed = true;
    }
    for (const [keyHex, item] of this.pendingPairings.entries()) {
      if (item.deviceId === deviceId || keyHex === deviceId) {
        this.pendingPairings.delete(keyHex);
        this._savePendingPairings();
        removed = true;
      }
    }

    if (removed) {
      this._saveDevices();
      return true;
    }
    return false;
  }

  /**
   * Looks up 32-byte Buffer pairKey for deviceId.
   * Checks confirmed paired devices first, then pending pairings.
   *
   * @param {string} deviceId
   * @returns {Buffer|null}
   */
  getDeviceKey(deviceId) {
    const paired = this.pairedDevices.find(d => d.deviceId === deviceId);
    if (paired) {
      return Buffer.from(paired.pairKeyHex, 'hex');
    }

    // If device presents a pending pairing key (most recent first)
    const now = Date.now();
    const sortedPending = Array.from(this.pendingPairings.values())
      .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

    for (const pending of sortedPending) {
      if (now - (pending.createdAt || 0) > 24 * 60 * 60 * 1000) {
        this.pendingPairings.delete(pending.pairKeyHex);
        continue;
      }
      if (deviceId === pending.pairKeyHex) {
        return Buffer.from(pending.pairKeyHex, 'hex');
      }
    }

    return null;
  }

  /**
   * Updates lastSyncAt timestamp for a device.
   *
   * @param {string} deviceId
   */
  updateDeviceLastSync(deviceId) {
    const d = this.pairedDevices.find(dev => dev.deviceId === deviceId);
    if (d) {
      d.lastSyncAt = Date.now();
      this._saveDevices();
    }
  }

  /**
   * Verifies if deviceId is officially paired.
   *
   * @param {string} deviceId
   * @returns {boolean}
   */
  isDevicePaired(deviceId) {
    return this.pairedDevices.some(d => d.deviceId === deviceId);
  }
}

// ── EPHEMERAL LOCAL TRANSPORT SERVER (R2) ─────────────────────────────────────
class EphemeralServer {
  /**
   * @param {object} options
   * @param {PairingManager} options.pairingManager
   * @param {Function} [options.getVaultEntries]
   * @param {Function} [options.applyMergedEntries]
   */
  constructor(options) {
    this.pairingManager = options.pairingManager;
    this.getVaultEntries = options.getVaultEntries || (() => []);
    this.applyMergedEntries = options.applyMergedEntries || (() => {});
    this.onDevicePaired = options.onDevicePaired || null;

    this.server = null;
    this.port = null;
    this.timeoutTimer = null;
    this.activeSockets = new Set();
    this.usedNonces = new Set();
    this.isRunning = false;
    this.startedAt = null;
    this.onCloseCallbacks = new Set();
  }

  isListening() {
    return this.isRunning && !!this.server && this.server.listening;
  }

  getPort() {
    return this.port;
  }

  getStatus() {
    const remainingMs = this.startedAt ? Math.max(0, EPHEMERAL_TIMEOUT_MS - (Date.now() - this.startedAt)) : 0;
    return {
      active: this.isListening(),
      port: this.port,
      addresses: getLocalRFC1918Addresses(),
      remainingSec: Math.ceil(remainingMs / 1000)
    };
  }

  onClosed(cb) {
    if (typeof cb === 'function') {
      this.onCloseCallbacks.add(cb);
    }
  }

  /**
   * Starts ephemeral listener socket.
   * Must live at most 120 seconds (R2).
   *
   * @param {object} [opts]
   * @param {number} [opts.port]
   * @param {number} [opts.timeoutMs]
   * @returns {Promise<{ port: number, addresses: string[] }>}
   */
  async start(opts = {}) {
    if (this.isListening()) {
      await this.stop('restart');
    }

    const requestedPort = opts.port !== undefined ? opts.port : DEFAULT_LAN_PORT;
    const timeoutMs = opts.timeoutMs || EPHEMERAL_TIMEOUT_MS;

    return new Promise((resolve, reject) => {
      this.server = http.createServer((req, res) => {
        this._handleRequest(req, res);
      });

      // Socket tracking and RFC1918 interface guard (R2)
      this.server.on('connection', (socket) => {
        const remoteIp = socket.remoteAddress;
        if (!isRFC1918OrLoopback(remoteIp)) {
          // Reject non-RFC1918 connection immediately (destroy socket)
          socket.destroy();
          return;
        }

        this.activeSockets.add(socket);
        socket.on('close', () => {
          this.activeSockets.delete(socket);
        });
      });

      this.server.on('error', (err) => {
        this.stop('error');
        reject(err);
      });

      this.server.listen(requestedPort, '0.0.0.0', () => {
        const addr = this.server.address();
        this.port = typeof addr === 'object' && addr ? addr.port : requestedPort;
        this.isRunning = true;
        this.startedAt = Date.now();

        // 120-second automatic expiration timer (R2)
        this.timeoutTimer = setTimeout(() => {
          this.stop('timeout');
        }, timeoutMs);

        resolve({
          port: this.port,
          addresses: getLocalRFC1918Addresses()
        });
      });
    });
  }

  /**
   * Immediately stops listening socket and terminates all connections.
   *
   * @param {string} [reason]
   * @returns {Promise<void>}
   */
  async stop(reason = 'stopped') {
    if (this.timeoutTimer) {
      clearTimeout(this.timeoutTimer);
      this.timeoutTimer = null;
    }

    // Force close active connections immediately
    for (const socket of this.activeSockets) {
      try { socket.destroy(); } catch {}
    }
    this.activeSockets.clear();
    this.usedNonces.clear();

    if (this.server) {
      await new Promise(resolve => {
        try {
          this.server.close(() => resolve());
        } catch {
          resolve();
        }
      });
      this.server = null;
    }

    this.isRunning = false;
    this.startedAt = null;

    for (const cb of this.onCloseCallbacks) {
      try { cb(reason); } catch {}
    }
  }

  _sendJson(res, statusCode, data) {
    try {
      const payload = JSON.stringify(data);
      res.writeHead(statusCode, {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Connection': 'close'
      });
      res.end(payload);
    } catch {}
  }

  _handleRequest(req, res) {
    req.on('error', () => {});

    // Handle OPTIONS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Connection': 'close'
      });
      res.end();
      return;
    }

    // Only accept POST requests
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Connection': 'close' });
      res.end('Method Not Allowed');
      return;
    }

    let body = '';
    let destroyed = false;
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 5 * 1024 * 1024) { // 5MB guard
        destroyed = true;
        req.destroy();
      }
    });

    req.on('end', async () => {
      if (destroyed) return;
      try {
        const parsed = JSON.parse(body || '{}');

        if (req.url === '/pair') {
          await this._handlePairRequest(parsed, res);
        } else if (req.url === '/sync') {
          await this._handleSyncRequest(parsed, res);
        } else {
          res.writeHead(404, { 'Connection': 'close' });
          res.end('Not Found');
        }
      } catch (err) {
        this._sendJson(res, 400, { error: err.message });
      }
    });
  }

  async _handlePairRequest(body, res) {
    const { deviceId, deviceName, pairKeyHex, nonce, ciphertext } = body;

    // Path A: AEAD-encrypted pairing proof (Zero-knowledge key confirmation over HTTP)
    if (nonce && ciphertext) {
      if (!deviceId || typeof nonce !== 'string' || typeof ciphertext !== 'string') {
        this._sendJson(res, 400, { error: 'Malformed encrypted pair request' });
        return;
      }
      if (this.usedNonces.has(nonce)) {
        this._sendJson(res, 400, { error: 'Pair request replay detected (nonce already used)' });
        return;
      }

      let matchedKeyHex = null;
      let decryptedProof = null;

      // 1. Check pending pairings
      for (const [keyHex] of this.pairingManager.pendingPairings.entries()) {
        try {
          decryptedProof = decryptLanPayload({ nonce, ciphertext }, Buffer.from(keyHex, 'hex'));
          matchedKeyHex = keyHex;
          break;
        } catch {}
      }

      // 2. Check existing paired devices if not in pending
      if (!matchedKeyHex) {
        for (const d of this.pairingManager.pairedDevices) {
          try {
            decryptedProof = decryptLanPayload({ nonce, ciphertext }, Buffer.from(d.pairKeyHex, 'hex'));
            matchedKeyHex = d.pairKeyHex;
            break;
          } catch {}
        }
      }

      if (!matchedKeyHex || !decryptedProof) {
        this._sendJson(res, 401, { error: 'Unauthorized pairing proof' });
        return;
      }

      if (typeof decryptedProof.timestamp === 'number') {
        if (Math.abs(Date.now() - decryptedProof.timestamp) > 120000) {
          this._sendJson(res, 400, { error: 'Pair request timestamp expired' });
          return;
        }
      }

      this.usedNonces.add(nonce);
      const finalDeviceId = decryptedProof.deviceId || deviceId;
      const finalDeviceName = decryptedProof.deviceName || deviceName || 'Mobil Cihaz';
      const savedRecord = this.pairingManager.addPairedDevice({
        deviceId: finalDeviceId,
        deviceName: finalDeviceName,
        pairKeyHex: matchedKeyHex
      });

      this._sendJson(res, 200, {
        success: true,
        desktopDeviceId: this.pairingManager.getDesktopDeviceId()
      });

      if (this.onDevicePaired) {
        try {
          this.onDevicePaired({
            deviceId: savedRecord.deviceId,
            deviceName: savedRecord.deviceName
          });
        } catch {}
      }
      return;
    }

    // Path B: Legacy / direct pairKeyHex fallback
    if (!deviceId || !pairKeyHex) {
      this._sendJson(res, 400, { error: 'deviceId and pairKeyHex (or encrypted proof) required' });
      return;
    }

    // Validate pairKey length
    const pairKeyBuf = Buffer.from(pairKeyHex, 'hex');
    if (pairKeyBuf.length !== PAIR_KEY_LENGTH) {
      this._sendJson(res, 400, { error: 'Invalid pairKey length' });
      return;
    }

    // Check if key is authorized (either in pending pairings or known)
    let keyBuf = this.pairingManager.getDeviceKey(deviceId);
    if (!keyBuf && this.pairingManager.pendingPairings.has(pairKeyHex)) {
      keyBuf = Buffer.from(pairKeyHex, 'hex');
    }

    if (!keyBuf || !crypto.timingSafeEqual(keyBuf, pairKeyBuf)) {
      this._sendJson(res, 401, { error: 'Unauthorized pairing key' });
      return;
    }

    const savedRecord = this.pairingManager.addPairedDevice({ deviceId, deviceName, pairKeyHex });
    this._sendJson(res, 200, {
      success: true,
      desktopDeviceId: this.pairingManager.getDesktopDeviceId()
    });

    if (this.onDevicePaired) {
      try {
        this.onDevicePaired({
          deviceId: savedRecord.deviceId,
          deviceName: savedRecord.deviceName
        });
      } catch {}
    }
  }

  async _handleSyncRequest(body, res) {
    const { deviceId, nonce, ciphertext, pendingPairKey } = body;
    if (!deviceId || !nonce || !ciphertext) {
      this._sendJson(res, 400, { error: 'Malformed sync packet' });
      return;
    }

    if (this.usedNonces.has(nonce)) {
      this._sendJson(res, 400, { error: 'Sync request replay detected (nonce already used)' });
      return;
    }

    let pairKeyBuf = null;
    let pendingKeyHexToFinalize = null;
    let matchedDeviceId = null;

    // 1. If client presents pendingPairKey and it exists in pending pairings, prioritize it
    if (pendingPairKey && typeof pendingPairKey === 'string') {
      const candidateKeyBuf = Buffer.from(pendingPairKey, 'hex');
      if (candidateKeyBuf.length === PAIR_KEY_LENGTH && this.pairingManager.pendingPairings.has(pendingPairKey)) {
        pairKeyBuf = candidateKeyBuf;
        pendingKeyHexToFinalize = pendingPairKey;
      }
    }

    // 2. If not specified or not pending, check known confirmed paired devices
    if (!pairKeyBuf) {
      const confirmedDevice = this.pairingManager.pairedDevices.find(
        d => (body.mobileDeviceId && d.deviceId === body.mobileDeviceId) ||
             (body.deviceId && d.deviceId === body.deviceId)
      );
      if (confirmedDevice) {
        pairKeyBuf = Buffer.from(confirmedDevice.pairKeyHex, 'hex');
        matchedDeviceId = confirmedDevice.deviceId;
      }
    }

    // 3. If still not found, check getDeviceKey
    if (!pairKeyBuf) {
      pairKeyBuf = this.pairingManager.getDeviceKey(deviceId);
      if (pairKeyBuf && this.pairingManager.pendingPairings.has(pairKeyBuf.toString('hex'))) {
        pendingKeyHexToFinalize = pairKeyBuf.toString('hex');
      }
    }

    // 4. If still not found and pending pairings exist, test candidate pending keys
    if (!pairKeyBuf && this.pairingManager.pendingPairings.size > 0) {
      for (const [keyHex] of this.pairingManager.pendingPairings.entries()) {
        const candidateBuf = Buffer.from(keyHex, 'hex');
        try {
          syncCrypto.syncDecrypt(
            Buffer.from(ciphertext, 'hex'),
            candidateBuf,
            Buffer.from(nonce, 'hex'),
            LAN_SYNC_AAD
          );
          pairKeyBuf = candidateBuf;
          pendingKeyHexToFinalize = keyHex;
          break;
        } catch {}
      }
    }

    // 5. If still not found, check if a known paired device matches
    if (!pairKeyBuf && this.pairingManager.pairedDevices.length > 0) {
      for (const d of this.pairingManager.pairedDevices) {
        const candidateBuf = Buffer.from(d.pairKeyHex, 'hex');
        try {
          syncCrypto.syncDecrypt(
            Buffer.from(ciphertext, 'hex'),
            candidateBuf,
            Buffer.from(nonce, 'hex'),
            LAN_SYNC_AAD
          );
          pairKeyBuf = candidateBuf;
          matchedDeviceId = d.deviceId;
          break;
        } catch {}
      }
    }

    if (!pairKeyBuf) {
      // Unauthorized device (R2)
      this._sendJson(res, 401, { error: 'Device not paired or unauthorized' });
      return;
    }

    // Decrypt using pairKey and XChaCha20-Poly1305
    let decryptedPayload;
    try {
      decryptedPayload = decryptLanPayload({ nonce, ciphertext }, pairKeyBuf);
    } catch (authErr) {
      // Immediate rejection of wrong / forged key (R2)
      this._sendJson(res, 403, { error: 'Authentication failed (wrong or forged key)' });
      return;
    }

    // Replay attack guard: Validate timestamp freshness (max 120s window)
    if (decryptedPayload && typeof decryptedPayload.timestamp === 'number') {
      const timeDelta = Math.abs(Date.now() - decryptedPayload.timestamp);
      if (timeDelta > 120000) {
        this._sendJson(res, 400, { error: 'Sync request timestamp expired (replay protection)' });
        return;
      }
    }

    this.usedNonces.add(nonce);

    // Determine the unique mobile device identifier:
    // 1. Prefer explicit mobileDeviceId from client
    // 2. If client passed a deviceId distinct from this desktop's own ID, use that
    // 3. Otherwise generate a distinct ID based on the pairing key
    const mobileId = (body.mobileDeviceId && typeof body.mobileDeviceId === 'string')
      ? body.mobileDeviceId
      : (body.deviceId && typeof body.deviceId === 'string')
        ? body.deviceId
        : `mobile-${(pendingKeyHexToFinalize || crypto.randomBytes(6).toString('hex')).slice(0, 12)}`;

    // If this was a pending pairing, officially finalize it now that authentication succeeded
    if (pendingKeyHexToFinalize) {
      const savedRecord = this.pairingManager.addPairedDevice({
        deviceId: mobileId,
        deviceName: body.deviceName || 'Mobil Cihaz',
        pairKeyHex: pendingKeyHexToFinalize
      });
      matchedDeviceId = mobileId;
      if (this.onDevicePaired) {
        try {
          this.onDevicePaired({
            deviceId: savedRecord.deviceId,
            deviceName: savedRecord.deviceName
          });
        } catch {}
      }
    }

    if (!decryptedPayload || !Array.isArray(decryptedPayload.entries)) {
      this._sendJson(res, 400, { error: 'Decrypted payload must contain entries array' });
      return;
    }

    // 1. Get current Desktop vault entries
    const desktopEntries = await Promise.resolve(this.getVaultEntries());

    // 2. Perform two-way conflict-free deterministic merge (R3)
    const { mergedEntries, stats } = mergeVaultEntries(desktopEntries, decryptedPayload.entries);

    // 3. Commit merged entries to Desktop vault
    await Promise.resolve(this.applyMergedEntries(mergedEntries, stats));

    // 4. Update device's lastSyncAt
    this.pairingManager.updateDeviceLastSync(matchedDeviceId || mobileId);

    // 5. Encrypt merged entries for client response with pairKey
    const responsePayload = {
      protocol: PROTOCOL_VERSION,
      timestamp: Date.now(),
      entries: mergedEntries,
      stats: stats
    };

    const encryptedResponse = encryptLanPayload(responsePayload, pairKeyBuf);

    // 6. Send response
    this._sendJson(res, 200, {
      success: true,
      ...encryptedResponse
    });

    // 7. Close server immediately upon transaction completion (R2)
    res.on('finish', () => {
      setImmediate(() => {
        this.stop('completed');
      });
    });
  }
}

// ── EXPORTS ───────────────────────────────────────────────────────────────────
module.exports = {
  // Constants
  DEFAULT_LAN_PORT,
  EPHEMERAL_TIMEOUT_MS,
  PAIR_KEY_LENGTH,
  PROTOCOL_VERSION,
  LAN_SYNC_AAD,

  // Network & RFC1918
  isRFC1918OrLoopback,
  getLocalRFC1918Addresses,

  // Crypto Framing
  encryptLanPayload,
  decryptLanPayload,

  // Two-Way Merge (R3)
  normalizeEntry,
  mergeHistories,
  mergeVaultEntries,

  // Classes
  PairingManager,
  EphemeralServer
};
