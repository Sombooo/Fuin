'use strict';
const cbor = require('cbor');

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ── ATOMIC WRITE HELPER (ADV-08) ─────────────────────────────────────────────
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

// ── GENERATION MANAGER ────────────────────────────────────────────────────────
class GenerationManager {
    constructor(userDataPath) {
        this.filePath = path.join(userDataPath, 'fuin.sync-generation');
        this.current = this._load();
    }
    
    _load() {
        if (!fs.existsSync(this.filePath)) {
            return 0; // Number (53-bit safe integer)
        }
        try {
            const val = fs.readFileSync(this.filePath, 'utf8');
            const parsed = parseInt(val, 10);
            return Number.isSafeInteger(parsed) ? parsed : 0;
        } catch {
            return 0;
        }
    }
    
    incrementAndGet() {
        this.current += 1;
        writeAtomicSync(this.filePath, this.current.toString(), { mode: 0o600, encoding: 'utf8' });
        return this.current;
    }

    resetForTestOnly() {
        this.current = 0;
        if (fs.existsSync(this.filePath)) fs.unlinkSync(this.filePath);
    }
    
    get() {
        return this.current;
    }
}

// ── SANITIZER ─────────────────────────────────────────────────────────────────
function sanitizeForCBOR(obj) {
    if (Buffer.isBuffer(obj) || obj instanceof Uint8Array) return obj;
    if (obj === null) return null;
    if (Array.isArray(obj)) return obj.map(sanitizeForCBOR);
    if (typeof obj === 'object') {
        const out = {};
        // CBOR { canonical: true } sorts keys, but doing it here guarantees predictable traversal
        for (const k of Object.keys(obj).sort()) {
            if (obj[k] !== undefined) {
                out[k] = sanitizeForCBOR(obj[k]);
            }
        }
        return out;
    }
    return obj;
}

// ── CANONICAL SNAPSHOT HASH (ADV-01) ─────────────────────────────────────────
// CBOR encoding options: canonical key order + 16MB highWaterMark to prevent
// Node stream.Transform buffer truncation on payloads larger than 64KB (which
// causes premature truncation and "Insufficient data" during decoding).
const CBOR_CANONICAL_OPTS = { canonical: true, highWaterMark: 16 * 1024 * 1024 };

function computeSnapshotHash(entries) {
    if (!Array.isArray(entries)) return null;
    const sanitizedEntries = sanitizeForCBOR(entries);
    const entriesCbor = cbor.encodeOne(sanitizedEntries, CBOR_CANONICAL_OPTS);
    const snapshotHash = crypto.createHash('sha256').update(entriesCbor).digest();
    entriesCbor.fill(0);
    return snapshotHash;
}

// ── PAYLOAD BUILDER ─────────────────────────────────────────────────────────

const ZSTD_LEVEL = 3; // Zorunlu Phase 2 Constraint

async function buildSyncPayload(entries, sessionId, genManager, vaultSchemaVersion = 1) {
    const zstd = await import('zstdify');
    if (!Buffer.isBuffer(sessionId) || sessionId.length !== 8) {
        throw new Error('SYNC_V2: sessionId must be exactly 8 raw bytes.');
    }

    const sanitizedEntries = sanitizeForCBOR(entries);
    
    // Canonical CBOR(entries)
    const entriesCbor = cbor.encodeOne(sanitizedEntries, CBOR_CANONICAL_OPTS);
    
    // snapshot_hash (SHA-256 of entries ONLY)
    const snapshotHash = crypto.createHash('sha256').update(entriesCbor).digest();
    
    // Increment generation (never rolls back per rule)
    const generation = genManager.incrementAndGet();
    
    // Protocol ve Payload versiyonlari sabittir (Phase 2 Constraint)
    const payloadObj = {
        protocol_version: 2,
        payload_version: 1,
        vault_schema_version: vaultSchemaVersion,
        session_id: sessionId,
        timestamp: Math.floor(Date.now() / 1000), // Epoch seconds
        generation: generation,
        snapshot_hash: snapshotHash,
        entries: sanitizedEntries
    };
    
    // Canonical CBOR(payload)
    const payloadCbor = cbor.encodeOne(payloadObj, CBOR_CANONICAL_OPTS);
    
    // ZSTD level 3 (Constraint) - zstdify expects options object { level: 3 }
    const compressed = Buffer.from(zstd.compress(payloadCbor, { level: ZSTD_LEVEL }));
    
    // Self-Consistency Check
    const decompressed = Buffer.from(zstd.decompress(compressed));
    const parsed = cbor.decodeFirstSync(decompressed);
    
    const parsedEntriesCbor = cbor.encodeOne(parsed.entries, CBOR_CANONICAL_OPTS);
    const verifyHash = crypto.createHash('sha256').update(parsedEntriesCbor).digest();
    
    if (!verifyHash.equals(parsed.snapshot_hash)) {
        throw new Error('SYNC_V2_INTERNAL: Self-consistency verification failed.');
    }
    
    // Secure cleanup
    entriesCbor.fill(0);
    payloadCbor.fill(0);
    decompressed.fill(0);
    
    return {
        compressedBytes: compressed,
        snapshotHash: snapshotHash,
        generation: generation
    };
}

async function parseSyncPayload(compressedBytes) {
    const zstd = await import('zstdify');
    const decompressed = Buffer.from(zstd.decompress(compressedBytes));
    const parsed = cbor.decodeFirstSync(decompressed);
    
    const entriesCbor = cbor.encodeOne(parsed.entries, CBOR_CANONICAL_OPTS);
    const verifyHash = crypto.createHash('sha256').update(entriesCbor).digest();
    
    if (!verifyHash.equals(parsed.snapshot_hash)) {
        throw new Error('SYNC_V2_INTEGRITY: snapshot_hash mismatch in parsed payload.');
    }
    
    decompressed.fill(0);
    return parsed;
}

module.exports = {
    GenerationManager,
    buildSyncPayload,
    parseSyncPayload,
    sanitizeForCBOR,
    writeAtomicSync,
    computeSnapshotHash
};
