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
const net    = require('net');
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
function isCanonicalPrivateIPv4(ipStr) {
  if (typeof ipStr !== 'string' || !ipStr) return false;
  if (/[\s@?#/\\:\[\]]/.test(ipStr)) return false;

  const parts = ipStr.split('.');
  if (parts.length !== 4) return false;

  const octets = [];
  for (const p of parts) {
    // Reject leading zeros (e.g. "010.8.8.8"), hex, signs, or non-digits
    if (!/^(?:0|[1-9]\d{0,2})$/.test(p)) return false;
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0 || n > 255) return false;
    octets.push(n);
  }

  const [a, b] = octets;
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
 * Verifies if an IPv4 or IPv6 address belongs strictly to local private networks (RFC 1918 / loopback / link-local / ULA).
 * Never permits public internet routing, octal/hex/userinfo/hostname tricks, or loose prefix bypasses.
 *
 * @param {string} ip
 * @returns {boolean}
 */
function isRFC1918OrLoopback(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const cleanIp = ip.trim();
  if (!cleanIp || /[\s@?#/\\\[\]%]/.test(cleanIp)) return false;

  const lower = cleanIp.toLowerCase();
  if (lower === 'localhost') return true;

  // Strip IPv4-mapped IPv6 prefix strictly (e.g. ::ffff:192.168.1.10)
  if (lower.startsWith('::ffff:')) {
    return isCanonicalPrivateIPv4(cleanIp.slice(7));
  }

  // Strict IPv6 validation via net.isIPv6 BEFORE checking private IPv6 ranges (SYNC-01)
  if (net.isIPv6(cleanIp)) {
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return true;
    // IPv6 Link-Local (fe80::/10, RFC 4291)
    if (/^fe[89ab][0-9a-f]:/.test(lower)) return true;
    // IPv6 Unique Local Address (fc00::/7, RFC 4193)
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
    return false;
  }

  return isCanonicalPrivateIPv4(cleanIp);
}

function isValidLanHostHeader(hostHeader) {
  if (typeof hostHeader !== 'string') return false;
  const trimmed = hostHeader.trim();
  if (!trimmed || /[\s@?#/\\]/.test(trimmed)) return false;

  let hostPart = trimmed;
  if (trimmed.startsWith('[')) {
    const closeIdx = trimmed.indexOf(']');
    if (closeIdx <= 1) return false;
    hostPart = trimmed.slice(1, closeIdx);
    const rest = trimmed.slice(closeIdx + 1);
    if (rest) {
      if (!/^:\d{1,5}$/.test(rest)) return false;
      const portNum = Number(rest.slice(1));
      if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return false;
    }
    return net.isIPv6(hostPart) && isRFC1918OrLoopback(hostPart);
  }

  const colonIdx = trimmed.indexOf(':');
  if (colonIdx !== -1) {
    hostPart = trimmed.slice(0, colonIdx);
    const portStr = trimmed.slice(colonIdx + 1);
    if (!/^\d{1,5}$/.test(portStr)) return false;
    const portNum = Number(portStr);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return false;
  }

  const lowerHost = hostPart.toLowerCase();
  if (lowerHost === 'localhost') return true;
  return isCanonicalPrivateIPv4(hostPart);
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

function sanitizeCardBrand(raw) {
  if (typeof raw !== 'string') return '';
  const cleaned = raw.trim();
  if (!cleaned) return '';
  return /^(?:troy|visa|mastercard|amex|discover|jcb|maestro|generic|)$/i.test(cleaned)
    ? cleaned
    : '';
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
  const maxAllowedTs = now + 300000; // +5 min clock-skew ceiling (blocks future timestamp poisoning)
  const id = entry.id || (typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'));

  let rawUpdatedAt = parseTimestamp(entry.updatedAt) ??
                     parseTimestamp(entry.updated) ??
                     parseTimestamp(entry.createdAt) ??
                     parseTimestamp(entry.created) ??
                     now;
  let updatedAt = Math.min(rawUpdatedAt, maxAllowedTs);

  let rawDeletedAt = parseTimestamp(entry.deletedAt);
  let deletedAt = rawDeletedAt !== null ? Math.min(rawDeletedAt, maxAllowedTs) : null;
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

  if (Object.prototype.hasOwnProperty.call(safeBase, 'cardBrand')) {
    safeBase.cardBrand = sanitizeCardBrand(safeBase.cardBrand);
  }

  const sanitized = {
    ...safeBase,
    id,
    site: typeof entry.site === 'string' ? entry.site : '',
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
    const key = `${snap.updatedAt || snap.updated || 0}_${snap.type || 'login'}_${snap.site || ''}_${snap.username || ''}_${snap.password || ''}_${snap.cardNumber || ''}_${snap.secureNote || ''}_${snap.note || ''}_${snap.totp || ''}_${snap.deletedAt || (snap.isDeleted ? 'del' : 'act')}`;
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
    (a.type || 'login') === (b.type || 'login') &&
    (a.cardholderName || '') === (b.cardholderName || '') &&
    (a.cardNumber || '') === (b.cardNumber || '') &&
    (a.cardExpiry || '') === (b.cardExpiry || '') &&
    (a.cardCvv || '') === (b.cardCvv || '') &&
    (a.cardPin || '') === (b.cardPin || '') &&
    (a.secureNote || '') === (b.secureNote || '') &&
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
function normalizeSite(s) {
  return (s || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');
}

function getCredentialKey(e) {
  if (!e || e.isDeleted || e.deletedAt || (e.type && e.type !== 'login')) return '';
  const site = normalizeSite(e.site);
  const user = (e.username || '').trim().toLowerCase();
  return (site && user) ? `${site}||${user}` : '';
}

function mergeVaultEntries(localEntries, remoteEntries) {
  const normLocal = (Array.isArray(localEntries) ? localEntries : []).map(normalizeEntry).filter(Boolean);
  const normRemote = (Array.isArray(remoteEntries) ? remoteEntries : []).map(normalizeEntry).filter(Boolean);

  const localMap = new Map();
  const localKeyMap = new Map();
  for (const e of normLocal) {
    const credKey = getCredentialKey(e);
    if (credKey && localKeyMap.has(credKey)) {
      const existingId = localKeyMap.get(credKey);
      const existing = localMap.get(existingId);
      if (existing && e.updatedAt > existing.updatedAt) {
        localMap.delete(existingId);
        localMap.set(e.id, e);
        localKeyMap.set(credKey, e.id);
      }
      continue;
    }

    if (localMap.has(e.id)) {
      const prev = localMap.get(e.id);
      if (e.updatedAt > prev.updatedAt) localMap.set(e.id, e);
    } else {
      localMap.set(e.id, e);
      if (credKey) localKeyMap.set(credKey, e.id);
    }
  }

  const remoteMap = new Map();
  const remoteKeyMap = new Map();
  for (const e of normRemote) {
    const credKey = getCredentialKey(e);
    if (credKey && remoteKeyMap.has(credKey)) {
      const existingId = remoteKeyMap.get(credKey);
      const existing = remoteMap.get(existingId);
      if (existing && e.updatedAt > existing.updatedAt) {
        remoteMap.delete(existingId);
        remoteMap.set(e.id, e);
        remoteKeyMap.set(credKey, e.id);
      }
      continue;
    }

    // Semantic match: if remote entry matches a local credential by site+username with different ID, unify ID!
    if (credKey && localKeyMap.has(credKey) && !localMap.has(e.id)) {
      const matchedLocalId = localKeyMap.get(credKey);
      const unifiedEntry = { ...e, id: matchedLocalId };
      remoteMap.set(matchedLocalId, unifiedEntry);
      remoteKeyMap.set(credKey, matchedLocalId);
      continue;
    }

    if (remoteMap.has(e.id)) {
      const prev = remoteMap.get(e.id);
      if (e.updatedAt > prev.updatedAt) remoteMap.set(e.id, e);
    } else {
      remoteMap.set(e.id, e);
      if (credKey) remoteKeyMap.set(credKey, e.id);
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
    this.fallbackKeyFilePath = path.join(userDataPath, 'fuin.pairing.key');
    this._needsFallbackMigration = false;
    this.desktopDeviceId = this._loadOrGenerateDeviceId();
    // SYNC-03: Remove any legacy persisted pending-pairings file; keep pendingPairings memory-only
    try {
      if (fs.existsSync(this.pendingFilePath)) {
        fs.unlinkSync(this.pendingFilePath);
      }
    } catch {}
    this.pairedDevices = this._loadDevices();
    if (this._needsFallbackMigration && this.pairedDevices.length > 0) {
      try { this._saveDevices(); } catch {}
      this._needsFallbackMigration = false;
    }
    this.pendingPairings = new Map();
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

  _deriveLegacyDeviceIdFallbackKey() {
    const devId = this.getDesktopDeviceId() || 'fuin-desktop-default';
    return crypto.scryptSync(devId, 'FUIN_LOCAL_PAIRING_STORE_V1', 32);
  }

  // SYNC-07: Dedicated 0o600 32-byte random fallback key file with symlink defense
  // (never derives encryption key solely from plaintext fuin.device-id).
  _loadOrCreateLocalFallbackKey() {
    try {
      const st = fs.lstatSync(this.fallbackKeyFilePath);
      if (st.isSymbolicLink()) {
        try { fs.unlinkSync(this.fallbackKeyFilePath); } catch {}
      } else if (!st.isFile()) {
        throw new Error('SYNC_LAN: Fallback key path is non-regular');
      } else {
        const hex = fs.readFileSync(this.fallbackKeyFilePath, 'utf8').trim();
        if (/^[0-9a-f]{64}$/i.test(hex)) {
          return Buffer.from(hex, 'hex');
        }
      }
    } catch (err) {
      if (err && err.code !== 'ENOENT' && /non-regular/i.test(String(err.message))) {
        throw err;
      }
    }

    const freshKey = crypto.randomBytes(32);
    try {
      writeAtomicSync(this.fallbackKeyFilePath, freshKey.toString('hex'), { mode: 0o600 });
    } catch {}
    return freshKey;
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
    // Fallback encryption (AES-256-GCM) with dedicated 0o600 32-byte random key when OS keyring is unavailable
    const key = this._loadOrCreateLocalFallbackKey();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(Buffer.from(jsonStr, 'utf8')), cipher.final()]);
    const tag = cipher.getAuthTag();
    key.fill(0);
    return JSON.stringify({
      localEncrypted: true,
      keyVersion: 2,
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      payload: enc.toString('base64')
    });
  }

  _decryptLocalEnvelope(parsed, key) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parsed.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(parsed.tag, 'base64'));
    const dec = Buffer.concat([
      decipher.update(Buffer.from(parsed.payload, 'base64')),
      decipher.final()
    ]);
    return JSON.parse(dec.toString('utf8'));
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
    if (
      parsed &&
      parsed.localEncrypted === true &&
      typeof parsed.iv === 'string' &&
      typeof parsed.tag === 'string' &&
      typeof parsed.payload === 'string'
    ) {
      if (parsed.keyVersion === 2) {
        const key = this._loadOrCreateLocalFallbackKey();
        try {
          return this._decryptLocalEnvelope(parsed, key);
        } finally {
          key.fill(0);
        }
      }
      // Backward-compatible migration for legacy v1 device-id encrypted files
      const legacyKey = this._deriveLegacyDeviceIdFallbackKey();
      try {
        const migrated = this._decryptLocalEnvelope(parsed, legacyKey);
        this._needsFallbackMigration = true;
        return migrated;
      } finally {
        legacyKey.fill(0);
      }
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

  clearPendingPairings() {
    this.pendingPairings.clear();
  }

  clearAll() {
    this.pairedDevices = [];
    this.pendingPairings.clear();
    try { if (fs.existsSync(this.devicesFilePath)) fs.unlinkSync(this.devicesFilePath); } catch {}
    try { if (fs.existsSync(this.pendingFilePath)) fs.unlinkSync(this.pendingFilePath); } catch {}
    try { if (fs.existsSync(this.deviceIdFilePath)) fs.unlinkSync(this.deviceIdFilePath); } catch {}
    try { if (fs.existsSync(this.fallbackKeyFilePath)) fs.unlinkSync(this.fallbackKeyFilePath); } catch {}
  }

  getDesktopDeviceId() {
    return this.desktopDeviceId;
  }

  /**
   * Generates static QR pairing payload.
   * QR contains: deviceId, 32-byte CSPRNG pairKey, port, and RFC1918 addresses.
   * SYNC-03: Pending pairings are single-active and kept in memory only.
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

    // SYNC-03: Keep only one active pending pairing in memory (never persisted on disk)
    this.pendingPairings.clear();
    this.pendingPairings.set(pairKeyHex, {
      pairKeyHex,
      createdAt: Date.now(),
      port,
      addresses
    });

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
   * SYNC-02: Also deletes ALL paired device records sharing the revoked device's pairKeyHex
   * so shadow clones cannot survive revocation.
   *
   * @param {string} deviceId
   * @returns {boolean}
   */
  removePairedDevice(deviceId) {
    const initialCount = this.pairedDevices.length;
    const revokedKeys = new Set();
    for (const d of this.pairedDevices) {
      if (d.deviceId === deviceId || d.pairKeyHex === deviceId) {
        if (d.pairKeyHex) revokedKeys.add(d.pairKeyHex);
      }
    }

    this.pairedDevices = this.pairedDevices.filter(
      d => d.deviceId !== deviceId && d.pairKeyHex !== deviceId && !revokedKeys.has(d.pairKeyHex)
    );
    let removed = this.pairedDevices.length !== initialCount;

    if (this.pendingPairings.has(deviceId)) {
      this.pendingPairings.delete(deviceId);
      removed = true;
    }
    for (const [keyHex, item] of this.pendingPairings.entries()) {
      if (item.deviceId === deviceId || keyHex === deviceId || revokedKeys.has(keyHex)) {
        this.pendingPairings.delete(keyHex);
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
   * Looks up 32-byte Buffer pairKey for confirmed paired deviceId.
   * SYNC-03: Never returns unconfirmed pendingPairing keys.
   *
   * @param {string} deviceId
   * @returns {Buffer|null}
   */
  getDeviceKey(deviceId) {
    const paired = this.pairedDevices.find(d => d.deviceId === deviceId);
    if (paired) {
      return Buffer.from(paired.pairKeyHex, 'hex');
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
// Cross-session nonce replay cache (persists across EphemeralServer restarts for 5 minutes)
const _globalUsedNonces = new Map();
const NONCE_REPLAY_TTL_MS = 5 * 60 * 1000;

function _hasUsedNonce(nonce) {
  const now = Date.now();
  for (const [k, ts] of _globalUsedNonces.entries()) {
    if (now - ts > NONCE_REPLAY_TTL_MS) {
      _globalUsedNonces.delete(k);
    }
  }
  return _globalUsedNonces.has(nonce);
}

function _recordUsedNonce(nonce) {
  _globalUsedNonces.set(nonce, Date.now());
}

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
    this.usedNonces = {
      has: (n) => _hasUsedNonce(n),
      add: (n) => _recordUsedNonce(n),
      clear: () => {} // Retain nonces across server restarts within TTL window to prevent cross-session replay
    };
    this.isRunning = false;
    this.startedAt = null;
    this.onCloseCallbacks = new Set();
    this._inFlightBodyReads = 0;
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

      // SYNC-05: Connection and slowloris timeout hardening
      this.server.maxConnections = 8;
      this.server.headersTimeout = 10000;
      this.server.requestTimeout = 30000;

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
    this._inFlightBodyReads = 0;

    // SYNC-03: Clear memory-only pending pairings when the ephemeral server stops
    if (this.pairingManager && typeof this.pairingManager.clearPendingPairings === 'function') {
      try { this.pairingManager.clearPendingPairings(); } catch {}
    }

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
        'Connection': 'close'
      });
      res.end(payload);
    } catch {}
  }

  _handleRequest(req, res) {
    req.on('error', () => {});

    // Reject browser cross-origin preflights and non-POST requests (no wildcard CORS)
    if (req.method !== 'POST') {
      res.writeHead(405, { 'Connection': 'close' });
      res.end('Method Not Allowed');
      return;
    }

    // SYNC-05: Browser / CORS / CSRF / Private Network Access (PNA) guard BEFORE reading body
    if (req.headers['origin'] !== undefined || req.headers['sec-fetch-site'] !== undefined) {
      this._sendJson(res, 403, { error: 'Browser cross-origin requests are not allowed' });
      return;
    }

    // SYNC-05: DNS rebinding guard — Host header must be a valid local IPv4/IPv6/localhost literal
    if (!isValidLanHostHeader(req.headers['host'])) {
      this._sendJson(res, 403, { error: 'Invalid Host header' });
      return;
    }

    // SYNC-05: Require strict application/json Content-Type before reading body
    const contentType = String(req.headers['content-type'] || '').trim().toLowerCase();
    if (!(contentType === 'application/json' || contentType.startsWith('application/json;'))) {
      this._sendJson(res, 415, { error: 'Content-Type must be application/json' });
      return;
    }

    // SYNC-05: Cap concurrent in-flight body reads to 2 (mitigate LAN memory exhaustion)
    if (this._inFlightBodyReads >= 2) {
      this._sendJson(res, 429, { error: 'Too many concurrent requests' });
      return;
    }
    this._inFlightBodyReads++;
    let released = false;
    const releaseInFlight = () => {
      if (!released) {
        released = true;
        this._inFlightBodyReads = Math.max(0, this._inFlightBodyReads - 1);
      }
    };
    req.on('close', releaseInFlight);
    req.on('aborted', releaseInFlight);
    req.on('error', releaseInFlight);

    const chunks = [];
    let totalBytes = 0;
    let destroyed = false;
    req.on('data', chunk => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      totalBytes += buf.length;
      if (totalBytes > 5 * 1024 * 1024) { // Strict 5MB byte guard
        destroyed = true;
        chunks.length = 0;
        releaseInFlight();
        req.destroy();
        return;
      }
      chunks.push(buf);
    });

    req.on('end', async () => {
      releaseInFlight();
      if (destroyed) return;
      try {
        const bodyStr = Buffer.concat(chunks, totalBytes).toString('utf8');
        chunks.length = 0;
        const parsed = JSON.parse(bodyStr || '{}');

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
    if (!body || typeof body !== 'object') {
      this._sendJson(res, 400, { error: 'Malformed encrypted pair request' });
      return;
    }
    const { nonce, ciphertext } = body;

    // Require AEAD-encrypted pairing proof (Zero-knowledge key confirmation over HTTP)
    if (typeof nonce !== 'string' || typeof ciphertext !== 'string') {
      this._sendJson(res, 400, { error: 'Malformed encrypted pair request' });
      return;
    }

    if (this.usedNonces.has(nonce)) {
      this._sendJson(res, 400, { error: 'Pair request replay detected (nonce already used)' });
      return;
    }

    let matchedKeyHex = null;
    let decryptedProof = null;
    const now = Date.now();

    // SYNC-02 & SYNC-03: ONLY try active, non-expired pendingPairings keys (NEVER pairedDevices!)
    for (const [keyHex, pending] of this.pairingManager.pendingPairings.entries()) {
      if (!pending || (now - (pending.createdAt || 0)) > EPHEMERAL_TIMEOUT_MS) {
        this.pairingManager.pendingPairings.delete(keyHex);
        continue;
      }
      const keyBuf = Buffer.from(keyHex, 'hex');
      try {
        decryptedProof = decryptLanPayload({ nonce, ciphertext }, keyBuf);
        matchedKeyHex = keyHex;
        break;
      } catch {} finally {
        keyBuf.fill(0);
      }
    }

    if (!matchedKeyHex || !decryptedProof || typeof decryptedProof !== 'object') {
      this._sendJson(res, 401, { error: 'Unauthorized pairing proof' });
      return;
    }

    // SYNC-02: Strict proof contract — require authenticated action==='pair', direction==='request', and non-empty inner deviceId
    if (decryptedProof.action !== 'pair' || decryptedProof.direction !== 'request') {
      this._sendJson(res, 400, { error: 'Invalid pair packet action or direction' });
      return;
    }

    if (typeof decryptedProof.deviceId !== 'string' || decryptedProof.deviceId.trim().length === 0) {
      this._sendJson(res, 400, { error: 'Authenticated pairing proof must include a non-empty deviceId' });
      return;
    }

    if (typeof decryptedProof.timestamp !== 'number' || Math.abs(Date.now() - decryptedProof.timestamp) > EPHEMERAL_TIMEOUT_MS) {
      this._sendJson(res, 400, { error: 'Pair request timestamp missing or expired' });
      return;
    }

    this.usedNonces.add(nonce);
    // SYNC-02: NEVER fall back to unauthenticated outer body.deviceId
    const finalDeviceId = decryptedProof.deviceId.trim().slice(0, 128);
    const finalDeviceName = (typeof decryptedProof.deviceName === 'string' && decryptedProof.deviceName.trim())
      ? decryptedProof.deviceName.trim().slice(0, 128)
      : 'Mobil Cihaz';
    const savedRecord = this.pairingManager.addPairedDevice({
      deviceId: finalDeviceId,
      deviceName: finalDeviceName,
      pairKeyHex: matchedKeyHex
    });

    const desktopId = this.pairingManager.getDesktopDeviceId();
    const ackKeyBuf = Buffer.from(matchedKeyHex, 'hex');
    let responseProof;
    try {
      responseProof = encryptLanPayload({
        action: 'pair-ack',
        direction: 'response',
        requestNonce: nonce,
        desktopDeviceId: desktopId,
        timestamp: Date.now()
      }, ackKeyBuf);
    } finally {
      ackKeyBuf.fill(0);
    }

    this._sendJson(res, 200, {
      success: true,
      desktopDeviceId: desktopId,
      nonce: responseProof.nonce,
      ciphertext: responseProof.ciphertext
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
    if (!body || typeof body !== 'object') {
      this._sendJson(res, 400, { error: 'Malformed sync packet' });
      return;
    }
    const { deviceId, nonce, ciphertext } = body;
    if (!deviceId || typeof nonce !== 'string' || typeof ciphertext !== 'string') {
      this._sendJson(res, 400, { error: 'Malformed sync packet' });
      return;
    }

    let pairKeyBuf = null;
    let matchedDeviceId = null;
    let decryptedPayload = null;

    // SYNC-03: ONLY authenticate against confirmed pairedDevices (NO pendingPairings lookup!)
    // 1. Check known confirmed paired devices by explicit mobileDeviceId / deviceId first
    const confirmedDevice = this.pairingManager.pairedDevices.find(
      d => (body.mobileDeviceId && d.deviceId === body.mobileDeviceId) ||
           (body.deviceId && d.deviceId === body.deviceId)
    );
    if (confirmedDevice) {
      const candidateBuf = Buffer.from(confirmedDevice.pairKeyHex, 'hex');
      try {
        decryptedPayload = decryptLanPayload({ nonce, ciphertext }, candidateBuf);
        pairKeyBuf = candidateBuf;
        matchedDeviceId = confirmedDevice.deviceId;
      } catch {
        candidateBuf.fill(0);
      }
    }

    // 2. If not matched directly, try remaining confirmed pairedDevices
    if (!pairKeyBuf && this.pairingManager.pairedDevices.length > 0) {
      for (const d of this.pairingManager.pairedDevices) {
        if (confirmedDevice && d.deviceId === confirmedDevice.deviceId) continue;
        const candidateBuf = Buffer.from(d.pairKeyHex, 'hex');
        try {
          decryptedPayload = decryptLanPayload({ nonce, ciphertext }, candidateBuf);
          pairKeyBuf = candidateBuf;
          matchedDeviceId = d.deviceId;
          break;
        } catch {
          candidateBuf.fill(0);
        }
      }
    }

    // SYNC-05: Unify all /sync auth failures to HTTP 401 (eliminates 403-vs-401 deviceId oracle)
    if (!pairKeyBuf || !decryptedPayload || typeof decryptedPayload !== 'object') {
      this._sendJson(res, 401, { error: 'Unauthorized' });
      return;
    }

    try {
      if (this.usedNonces.has(nonce)) {
        this._sendJson(res, 400, { error: 'Sync request replay detected (nonce already used)' });
        return;
      }
      // Reject reflected response packets or cross-endpoint pair packets
      if (
        decryptedPayload.direction === 'response' ||
        decryptedPayload.action === 'pair' ||
        decryptedPayload.action === 'pair-ack'
      ) {
        this._sendJson(res, 400, { error: 'Invalid sync packet direction or type (reflection detected)' });
        return;
      }

      // Replay attack guard: Validate timestamp freshness (max 120s window)
      if (typeof decryptedPayload.timestamp === 'number') {
        const timeDelta = Math.abs(Date.now() - decryptedPayload.timestamp);
        if (timeDelta > 120000) {
          this._sendJson(res, 400, { error: 'Sync request timestamp expired (replay protection)' });
          return;
        }
      }

      this.usedNonces.add(nonce);

      if (!Array.isArray(decryptedPayload.entries)) {
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
      this.pairingManager.updateDeviceLastSync(matchedDeviceId);

      // 5. Encrypt merged entries for client response with pairKey and cryptographic requestNonce binding
      const responsePayload = {
        protocol: PROTOCOL_VERSION,
        direction: 'response',
        requestNonce: nonce,
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
    } finally {
      pairKeyBuf.fill(0);
    }
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
  isValidLanHostHeader,
  getLocalRFC1918Addresses,

  // Crypto Framing
  encryptLanPayload,
  decryptLanPayload,

  // Two-Way Merge (R3)
  sanitizeCardBrand,
  normalizeEntry,
  mergeHistories,
  mergeVaultEntries,

  // Classes
  PairingManager,
  EphemeralServer
};
