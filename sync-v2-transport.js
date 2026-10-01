'use strict';
// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — PHASE 3: Desktop QR Transport Layer
// sync-v2-transport.js
//
// Responsibility: chunk, encode and reassemble the V2 outer envelope for QR transport.
//
// Pipeline (sender):
//   Phase 2 payload → Phase 1 encrypt → outer envelope Buffer
//       → split into binary chunks
//       → Base45 encode each chunk
//       → CRC32 each chunk
//       → QR header strings: FUIN|2|<sessId>|<idx>/<tot>|<crc>|<base45>
//
// Pipeline (receiver):
//   QR string → parse → validate → Base45 decode → CRC32 verify
//       → store chunk → assemble → envelope Buffer → Phase 1 decrypt
//
// Dependencies:
//   base45  — RFC 9285 encode/decode (with strict alphabet validation added here)
//   crc-32  — CRC32 (transport integrity only, NOT cryptographic)
//
// FROZEN INVARIANTS:
//   INV-12: QR encoding is Base45 (RFC 9285).
//   INV-18: CRC32 is transport integrity only, not a security mechanism.
//   INV-19: QR format: FUIN|<VER>|<SESSID>|<IDX>/<TOT>|<CRC>|<DATA>
//   INV-23: Outer envelope magic 0x46 0x53, wire_version 0x02, overhead 59 bytes.
// ═══════════════════════════════════════════════════════════════════════════════

const _b45  = require('base45');
const CRC32 = require('crc-32');
const crypto = require('crypto');

// ── CONSTANTS ─────────────────────────────────────────────────────────────────

/**
 * QR Chunk binary payload byte size (per chunk, before Base45 encoding).
 * A single binary chunk of 200 bytes encodes to ~243 Base45 characters.
 * With the ~30-char header overhead the total QR payload is ~273 chars, well
 * within QR Code version 10-L (272) to version 11-L (321) capacity at lower
 * error-correction.  Keeping it at 200 bytes is safe for all common QR
 * renderers and leaves enough headroom for the header.
 *
 * NOTE: This value is a fixed Desktop V2 constant.  Do NOT change it at
 * runtime.  If the QR renderer changes, update this constant and bump the
 * transport version accordingly.
 */
const CHUNK_BYTE_SIZE = 200;

/**
 * Supported QR protocol version.  Only version 2 is accepted (INV-19).
 */
const SUPPORTED_VERSION = 2;

/**
 * QR frame prefix (literal ASCII).
 */
const QR_PREFIX = 'FUIN';

/**
 * RFC 9285 Base45 alphabet — exactly 45 characters in canonical order.
 * Characters outside this set are illegal and must be rejected.
 */
const BASE45_ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';
const BASE45_ALPHABET_SET = new Set(BASE45_ALPHABET);

// ── BASE45 (strict, RFC 9285) ─────────────────────────────────────────────────

/**
 * Encode a Buffer/Uint8Array to a Base45 string (RFC 9285).
 * @param {Buffer} data
 * @returns {string}
 */
function base45Encode(data) {
  if (!Buffer.isBuffer(data) && !(data instanceof Uint8Array)) {
    throw new TypeError('base45Encode: input must be Buffer or Uint8Array');
  }
  return _b45.encode(Buffer.from(data));
}

/**
 * Decode a Base45 string to a Buffer (RFC 9285).
 * Performs strict alphabet validation before delegating to the library.
 * @param {string} str
 * @returns {Buffer}
 */
function base45Decode(str) {
  if (typeof str !== 'string') {
    throw new TypeError('base45Decode: input must be a string');
  }
  // Strict alphabet validation — reject any character outside RFC 9285 set
  for (let i = 0; i < str.length; i++) {
    if (!BASE45_ALPHABET_SET.has(str[i])) {
      throw new RangeError(
        `base45Decode: invalid character '${str[i]}' at position ${i}. ` +
        'Only RFC 9285 Base45 alphabet characters are permitted.'
      );
    }
  }
  return Buffer.from(_b45.decode(str));
}

// ── CRC32 ─────────────────────────────────────────────────────────────────────

/**
 * Compute CRC32 over raw bytes and return an 8-character uppercase hex string.
 * CRC32_input  = raw binary bytes (Base45-decoded chunk bytes)
 * CRC32_output = 8 uppercase hex chars (e.g. "F9A3B1C2")
 *
 * NOTE: CRC32 is transport integrity ONLY.  It is NOT a cryptographic MAC.
 * @param {Buffer} data
 * @returns {string}  8 uppercase hex chars
 */
function computeCRC32(data) {
  // crc-32 returns signed int32 — convert to unsigned via >>> 0
  const unsigned = (CRC32.buf(data) >>> 0);
  return unsigned.toString(16).toUpperCase().padStart(8, '0');
}

/**
 * Verify a CRC32 hex string against raw bytes.
 * @param {Buffer} data
 * @param {string} expectedHex  8 uppercase hex chars
 * @returns {boolean}
 */
function verifyCRC32(data, expectedHex) {
  return computeCRC32(data) === expectedHex.toUpperCase();
}

// ── SESSION ID ────────────────────────────────────────────────────────────────

/**
 * Generate a new session ID: 8 CSPRNG bytes.
 * For QR transport, the sessionId is represented as 16 lowercase hex chars.
 * @returns {{ raw: Buffer, hex: string }}
 */
function generateQRSessionId() {
  const raw = crypto.randomBytes(8);
  return { raw, hex: raw.toString('hex') };  // lowercase by default
}

/**
 * Validate that a string is a valid QR session ID (16 lowercase hex chars).
 * @param {string} hex
 * @returns {boolean}
 */
function isValidSessionIdHex(hex) {
  return typeof hex === 'string' && /^[0-9a-f]{16}$/.test(hex);
}

// ── QR HEADER BUILDER ─────────────────────────────────────────────────────────

/**
 * Build a single QR chunk string per the FUIN V2 wire format:
 *
 *   FUIN|2|<sessId16hex>|<idx3>/<tot3>|<CRC32_8hex>|<base45_data>
 *
 * @param {string}  sessionIdHex  16 lowercase hex chars
 * @param {number}  index         1-based chunk index
 * @param {number}  total         total number of chunks
 * @param {Buffer}  chunkBytes    raw binary bytes for this chunk
 * @returns {string}
 */
function buildQRChunkString(sessionIdHex, index, total, chunkBytes) {
  if (!isValidSessionIdHex(sessionIdHex)) {
    throw new Error(`buildQRChunkString: invalid sessionIdHex '${sessionIdHex}'`);
  }
  if (!Number.isInteger(total) || total < 1) {
    throw new RangeError(`buildQRChunkString: total must be >= 1, got ${total}`);
  }
  if (!Number.isInteger(index) || index < 1 || index > total) {
    throw new RangeError(`buildQRChunkString: index ${index} out of range 1..${total}`);
  }
  if (!Buffer.isBuffer(chunkBytes) || chunkBytes.length === 0) {
    throw new TypeError('buildQRChunkString: chunkBytes must be non-empty Buffer');
  }

  const data  = base45Encode(chunkBytes);
  const crc   = computeCRC32(chunkBytes);  // CRC over raw bytes (pre-Base45)
  const idx   = String(index).padStart(3, '0');
  const tot   = String(total).padStart(3, '0');

  return `${QR_PREFIX}|${SUPPORTED_VERSION}|${sessionIdHex}|${idx}/${tot}|${crc}|${data}`;
}

// ── QR HEADER PARSER ──────────────────────────────────────────────────────────

/**
 * Parse and validate a QR chunk string.
 * Returns a parsed object or throws a descriptive error.
 *
 * Validation rules (per spec §11, §12):
 *   - Exactly 6 pipe-delimited fields
 *   - prefix === "FUIN"
 *   - version === 2
 *   - sessionId: 16 lowercase hex chars
 *   - IDX/TOT: integer, 1 ≤ IDX ≤ TOT, TOT > 0
 *   - CRC: 8 uppercase hex chars
 *   - DATA: non-empty valid Base45 string
 *   - CRC32(Base45Decode(DATA)) === CRC field
 *
 * @param {string} qrString
 * @returns {{ sessionIdHex: string, index: number, total: number, chunkBytes: Buffer }}
 */
function parseQRChunkString(qrString) {
  if (typeof qrString !== 'string' || qrString.length === 0) {
    throw new Error('parseQRChunkString: input must be a non-empty string');
  }

  const parts = qrString.split('|');
  if (parts.length !== 6) {
    throw new Error(
      `parseQRChunkString: expected 6 pipe-delimited fields, got ${parts.length}. ` +
      'Format: FUIN|<VER>|<SESSID>|<IDX>/<TOT>|<CRC>|<DATA>'
    );
  }

  const [prefix, verStr, sessionIdHex, indexTotal, crcHex, data] = parts;

  // Prefix
  if (prefix !== QR_PREFIX) {
    throw new Error(`parseQRChunkString: expected prefix '${QR_PREFIX}', got '${prefix}'`);
  }

  // Protocol version — must be exactly 2
  const version = parseInt(verStr, 10);
  if (isNaN(version) || String(version) !== verStr || version !== SUPPORTED_VERSION) {
    throw new Error(
      `parseQRChunkString: unsupported protocol version '${verStr}'. ` +
      `Only version ${SUPPORTED_VERSION} is supported. ` +
      'Unsupported sync protocol version. Please update your app.'
    );
  }

  // Session ID
  if (!isValidSessionIdHex(sessionIdHex)) {
    throw new Error(
      `parseQRChunkString: invalid sessionId '${sessionIdHex}'. ` +
      'Must be exactly 16 lowercase hex characters.'
    );
  }

  // IDX/TOT
  const slashIdx = indexTotal.indexOf('/');
  if (slashIdx === -1) {
    throw new Error(`parseQRChunkString: malformed IDX/TOT field '${indexTotal}'`);
  }
  const idxStr = indexTotal.slice(0, slashIdx);
  const totStr = indexTotal.slice(slashIdx + 1);
  const index  = parseInt(idxStr, 10);
  const total  = parseInt(totStr, 10);

  if (!Number.isInteger(index) || !Number.isInteger(total)) {
    throw new Error(`parseQRChunkString: non-integer IDX/TOT '${indexTotal}'`);
  }
  if (total <= 0) {
    throw new Error(`parseQRChunkString: total must be > 0, got ${total}`);
  }
  if (index < 1 || index > total) {
    throw new Error(`parseQRChunkString: index ${index} out of range 1..${total}`);
  }

  // CRC format — 8 uppercase hex
  if (!/^[0-9A-F]{8}$/.test(crcHex)) {
    throw new Error(
      `parseQRChunkString: malformed CRC field '${crcHex}'. Must be 8 uppercase hex chars.`
    );
  }

  // DATA — non-empty
  if (!data || data.length === 0) {
    throw new Error('parseQRChunkString: DATA field is empty');
  }

  // Base45 decode (strict — throws on invalid alphabet)
  let chunkBytes;
  try {
    chunkBytes = base45Decode(data);
  } catch (e) {
    throw new Error(`parseQRChunkString: Base45 decode failed — ${e.message}`);
  }

  // CRC32 verification — transport integrity (NOT cryptographic)
  if (!verifyCRC32(chunkBytes, crcHex)) {
    throw new Error(
      `parseQRChunkString: CRC32 mismatch for chunk ${index}/${total}. ` +
      'Chunk dropped (QR read error or corruption). Session continues.'
    );
  }

  return { sessionIdHex, index, total, chunkBytes };
}

// ── CHUNK GENERATOR ───────────────────────────────────────────────────────────

/**
 * Split a V2 outer envelope Buffer into QR chunk strings.
 *
 * @param {Buffer} envelopeBuffer   Complete V2 outer envelope (Phase 1 output)
 * @param {string} sessionIdHex     16 lowercase hex chars (from generateQRSessionId)
 * @param {number} [chunkByteSize]  Binary bytes per chunk (defaults to CHUNK_BYTE_SIZE)
 * @returns {string[]}              Array of QR chunk strings (1-indexed in headers)
 */
function buildQRChunks(envelopeBuffer, sessionIdHex, chunkByteSize = CHUNK_BYTE_SIZE) {
  if (!Buffer.isBuffer(envelopeBuffer) || envelopeBuffer.length === 0) {
    throw new TypeError('buildQRChunks: envelopeBuffer must be a non-empty Buffer');
  }
  if (!isValidSessionIdHex(sessionIdHex)) {
    throw new Error(`buildQRChunks: invalid sessionIdHex '${sessionIdHex}'`);
  }
  if (!Number.isInteger(chunkByteSize) || chunkByteSize < 1) {
    throw new RangeError('buildQRChunks: chunkByteSize must be a positive integer');
  }

  // Split envelope into binary chunks first, then encode each separately
  const total    = Math.ceil(envelopeBuffer.length / chunkByteSize);
  const chunks   = [];

  for (let i = 0; i < total; i++) {
    const start    = i * chunkByteSize;
    const end      = Math.min(start + chunkByteSize, envelopeBuffer.length);
    const binChunk = envelopeBuffer.slice(start, end);
    chunks.push(buildQRChunkString(sessionIdHex, i + 1, total, binChunk));
  }

  return chunks;
}

// ── CHUNK ASSEMBLER ───────────────────────────────────────────────────────────

/**
 * Isolated session assembly state.
 *
 * Usage:
 *   const assembler = new ChunkAssembler();
 *   for (const qrStr of qrStrings) {
 *     const result = assembler.add(qrStr);
 *     if (result.complete) {
 *       const envelope = result.envelope;  // ready for Phase 1 decrypt
 *     }
 *   }
 */
class ChunkAssembler {
  constructor() {
    this._reset();
  }

  _reset() {
    this._sessionIdHex = null;
    this._total        = null;
    this._chunks       = new Map(); // index → Buffer
  }

  /**
   * Add a raw QR string to the assembler.
   *
   * @param {string} qrString
   * @returns {{ complete: boolean, envelope?: Buffer, error?: string }}
   */
  add(qrString) {
    let parsed;
    try {
      parsed = parseQRChunkString(qrString);
    } catch (e) {
      // Malformed / CRC mismatch — drop chunk, session continues
      return { complete: false, error: e.message };
    }

    const { sessionIdHex, index, total, chunkBytes } = parsed;

    // First chunk seen — initialize session
    if (this._sessionIdHex === null) {
      this._sessionIdHex = sessionIdHex;
      this._total        = total;
    }

    // Session isolation — different sessionId → silently ignore (spec §11.4)
    if (sessionIdHex !== this._sessionIdHex) {
      return {
        complete: false,
        error: `Chunk from different session '${sessionIdHex}' ignored (active: '${this._sessionIdHex}')`
      };
    }

    // Inconsistent total within session → reject
    if (total !== this._total) {
      return {
        complete: false,
        error: `Inconsistent total: expected ${this._total}, got ${total}. Chunk rejected.`
      };
    }

    // Duplicate index → silently ignore (spec §11.4)
    if (this._chunks.has(index)) {
      return { complete: false };
    }

    this._chunks.set(index, chunkBytes);

    // Check completeness — all 1..total indices present
    if (this._chunks.size < this._total) {
      return { complete: false };
    }

    // All chunks received — assemble in order
    const parts = [];
    for (let i = 1; i <= this._total; i++) {
      if (!this._chunks.has(i)) {
        // Should not happen but guard defensively
        return { complete: false, error: `Missing chunk index ${i} during final assembly` };
      }
      parts.push(this._chunks.get(i));
    }

    const envelope = Buffer.concat(parts);
    this._reset(); // clear state after successful assembly
    return { complete: true, envelope };
  }

  /**
   * Return true if at least one chunk has been accepted for the current session.
   */
  isActive() {
    return this._sessionIdHex !== null;
  }

  /**
   * Number of unique chunk indices received so far.
   */
  receivedCount() {
    return this._chunks.size;
  }

  /**
   * Total chunks expected in the current session (null if no session active).
   */
  expectedTotal() {
    return this._total;
  }

  /**
   * Current active session ID hex (null if no session).
   */
  sessionIdHex() {
    return this._sessionIdHex;
  }

  /**
   * Reset assembler state (e.g. on timeout or session cancel).
   */
  reset() {
    this._reset();
  }
}

// ── EXPORTS ───────────────────────────────────────────────────────────────────

module.exports = {
  // Constants
  CHUNK_BYTE_SIZE,
  SUPPORTED_VERSION,
  QR_PREFIX,

  // Base45 (strict RFC 9285)
  base45Encode,
  base45Decode,

  // CRC32
  computeCRC32,
  verifyCRC32,

  // Session ID
  generateQRSessionId,
  isValidSessionIdHex,

  // QR chunk lifecycle
  buildQRChunkString,
  parseQRChunkString,
  buildQRChunks,

  // Assembly
  ChunkAssembler,
};
