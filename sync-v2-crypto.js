'use strict';

// ═══════════════════════════════════════════════════════════════════════════════
// FUIN SYNC V2 — CRYPTO ABSTRACTION LAYER
//
// Bu modül SYNC_PROTOCOL.md V2 spesifikasyonuna göre implement edilmiştir.
// Yalnızca Sync Key derivation ve Sync payload şifreleme/çözme işlemlerini içerir.
//
// KAPSAM SINIRI:
//   - Vault encryption (encryptData / decryptData) bu dosyaya DOKUNMAZ.
//   - QR chunking, CBOR, zstd bu modülün kapsamında DEĞİLDİR (Phase 2+).
//   - Bu modül yalnızca crypto primitif'lerini expose eder.
//
// INVARIANT REFERANSLAR:
//   INV-01: Sync/Vault ayrı cryptographic path.
//   INV-05: KDF = Argon2id only. PBKDF2 fallback YASAK.
//   INV-06: m=65536, t=3, p=4, outLen=32, salt=16B. Sabit.
//   INV-07: XChaCha20-Poly1305.
//   INV-08: Nonce = 24B CSPRNG. Deterministik değil.
//   INV-11: sessionId = 8B CSPRNG.
//   INV-16: AAD = [0x02][sessionId:8B][salt:16B] = 25B binary.
//   INV-23: magic=[0x46,0x53], wire_version=0x02.
//   INV-26: Auth fail → plaintext asla açığa çıkmaz.
//   INV-27: Envelope overhead = 59 bytes. N = total - 59.
// ═══════════════════════════════════════════════════════════════════════════════

const crypto = require('crypto');

// ── CONSTANTS ─────────────────────────────────────────────────────────────────
// Bu sabitler runtime'da değiştirilemez. (INV-06, INV-21)

const SYNC_V2 = Object.freeze({
  // KDF (INV-05, INV-06)
  KDF_MEMORY:        65536,          // KiB — 64 MiB
  KDF_ITERATIONS:    3,
  KDF_PARALLELISM:   4,
  KDF_OUTLEN:        32,             // bytes
  SALT_LENGTH:       16,             // bytes
  DOMAIN_TAG:        'FUIN_SYNC_V2', // 12 bytes UTF-8

  // Cipher (INV-07, INV-08)
  NONCE_LENGTH:      24,             // bytes
  AUTH_TAG_LENGTH:   16,             // bytes
  KEY_LENGTH:        32,             // bytes

  // Session (INV-11)
  SESSION_ID_LENGTH: 8,              // bytes

  // AAD (INV-16)
  AAD_VERSION_BYTE:  0x02,
  AAD_LENGTH:        25,             // 1 + 8 + 16

  // Outer Envelope (INV-23, INV-27)
  MAGIC_0:           0x46,           // 'F'
  MAGIC_1:           0x53,           // 'S'
  WIRE_VERSION:      0x02,
  ENVELOPE_OVERHEAD: 59,             // 2+1+16+24+16
});

// ── DEPENDENCY GUARDS ─────────────────────────────────────────────────────────

let _sodium = null;

function requireSodium() {
  if (_sodium) return _sodium;
  try {
    _sodium = require('sodium-native');
    return _sodium;
  } catch (e) {
    throw new Error(
      'SYNC_V2_DEPENDENCY_MISSING: sodium-native yuklenemedi. ' +
      'XChaCha20-Poly1305 sifrelemesi kullanilamaz. Sync baslatilamaz.'
    );
  }
}

let _argon2      = null;
let _argon2Tried = false;

function requireArgon2() {
  if (!_argon2Tried) {
    _argon2Tried = true;
    try { _argon2 = require('argon2'); } catch { _argon2 = null; }
  }
  if (!_argon2) {
    throw new Error(
      'SYNC_V2_KDF_UNAVAILABLE: argon2 native modulu yuklenemedi. ' +
      'PBKDF2 fallback Sync V2 icin kesinlikle yasaktir. (INV-05) Sync baslatilamaz.'
    );
  }
  return _argon2;
}

// ── deriveSyncKey ─────────────────────────────────────────────────────────────
/**
 * Sync Key turetme. SYNC_PROTOCOL.md V2 §4.
 *
 * Algoritma : Argon2id (INV-05)
 * Parametreler: m=65536, t=3, p=4, outLen=32 (INV-06) — runtime'da degistirilemez
 * effective_salt = salt_16B || UTF-8("FUIN_SYNC_V2")   (INV-06)
 *
 * @param {string} passwordStr  Kullanicinin Sync Password'u (UTF-8)
 * @param {Buffer} salt         Tam 16 byte CSPRNG salt
 * @returns {Promise<Buffer>}   32 byte Sync Key (caller fill(0) sorumludur)
 * @throws Argon2 yoksa veya hataysa — PBKDF2 fallback OLMAZ
 */
async function deriveSyncKey(passwordStr, salt) {
  if (typeof passwordStr !== 'string') {
    throw new TypeError('SYNC_V2: passwordStr string olmalidir.');
  }
  if (passwordStr.length === 0 || passwordStr.length > 1024) {
    throw new RangeError('SYNC_V2: Sync Password uzunlugu 1-1024 karakter araliginda olmalidir.');
  }
  if (!Buffer.isBuffer(salt)) {
    throw new TypeError('SYNC_V2: salt Buffer olmalidir.');
  }
  if (salt.length !== SYNC_V2.SALT_LENGTH) {
    throw new RangeError(
      'SYNC_V2: salt tam olarak ' + SYNC_V2.SALT_LENGTH + ' byte olmalidir, ' +
      salt.length + ' byte verildi. (INV-06)'
    );
  }

  const argon2 = requireArgon2(); // PBKDF2 fallback YASAK

  const pwBuf = Buffer.from(passwordStr, 'utf8');

  // Domain separation (INV-06): effective_salt = salt_16B || "FUIN_SYNC_V2"
  const domainTag    = Buffer.from(SYNC_V2.DOMAIN_TAG, 'utf8'); // 12 bytes
  const effectiveSalt = Buffer.concat([salt, domainTag]);        // 28 bytes

  let syncKey = null;
  try {
    const raw = await argon2.hash(pwBuf, {
      type:        argon2.argon2id,
      salt:        effectiveSalt,
      memoryCost:  SYNC_V2.KDF_MEMORY,      // 65536
      timeCost:    SYNC_V2.KDF_ITERATIONS,  // 3
      parallelism: SYNC_V2.KDF_PARALLELISM, // 4
      hashLength:  SYNC_V2.KDF_OUTLEN,      // 32
      raw:         true,
    });
    syncKey = Buffer.from(raw);
    if (Buffer.isBuffer(raw) && typeof raw.fill === 'function') raw.fill(0);
  } catch (e) {
    pwBuf.fill(0);
    effectiveSalt.fill(0);
    throw new Error(
      'SYNC_V2_KDF_FAILED: Argon2id key derivation basarisiz oldu. ' +
      'PBKDF2 fallback Sync V2 icin yasaktir. Sync baslatilamaz. Hata: ' + e.message
    );
  }
  pwBuf.fill(0);
  effectiveSalt.fill(0);

  if (!Buffer.isBuffer(syncKey) || syncKey.length !== SYNC_V2.KDF_OUTLEN) {
    if (syncKey) syncKey.fill(0);
    throw new Error('SYNC_V2_KDF_FAILED: Argon2id beklenmeyen cikti uretti.');
  }

  return syncKey;
}

// ── SALT / SESSION ID GENERATION ─────────────────────────────────────────────

/** 16-byte CSPRNG sync salt uretir. (INV-06) 32B salt V2 icin yasaktir. */
function generateSyncSalt() {
  return crypto.randomBytes(SYNC_V2.SALT_LENGTH);
}

/** 8-byte CSPRNG sessionId uretir. (INV-11) */
function generateSessionId() {
  return crypto.randomBytes(SYNC_V2.SESSION_ID_LENGTH);
}

// ── buildAAD ─────────────────────────────────────────────────────────────────
/**
 * Deterministic binary AAD olusturur. (INV-16)
 *
 * Format: [0x02][sessionId:8B][salt:16B] = tam 25 bytes
 * String concat, pipe separator, raw/string mixing YASAK.
 * Yanlis uzunluklarda sessizce devam etmez — explicit hata firlatir.
 *
 * @param {Buffer} sessionId  Tam 8 byte
 * @param {Buffer} salt       Tam 16 byte
 * @returns {Buffer}          Tam 25 byte AAD
 */
function buildAAD(sessionId, salt) {
  if (!Buffer.isBuffer(sessionId)) {
    throw new TypeError('SYNC_V2: sessionId Buffer olmalidir.');
  }
  if (sessionId.length !== SYNC_V2.SESSION_ID_LENGTH) {
    throw new RangeError(
      'SYNC_V2: sessionId tam olarak ' + SYNC_V2.SESSION_ID_LENGTH + ' byte olmalidir, ' +
      sessionId.length + ' byte verildi. (INV-16)'
    );
  }
  if (!Buffer.isBuffer(salt)) {
    throw new TypeError('SYNC_V2: salt Buffer olmalidir.');
  }
  if (salt.length !== SYNC_V2.SALT_LENGTH) {
    throw new RangeError(
      'SYNC_V2: salt tam olarak ' + SYNC_V2.SALT_LENGTH + ' byte olmalidir, ' +
      salt.length + ' byte verildi. (INV-16)'
    );
  }

  const aad = Buffer.allocUnsafe(SYNC_V2.AAD_LENGTH); // 25
  aad[0] = SYNC_V2.AAD_VERSION_BYTE;                  // [0x02]
  sessionId.copy(aad, 1);                              // offset 1..8  (8B)
  salt.copy(aad, 1 + SYNC_V2.SESSION_ID_LENGTH);       // offset 9..24 (16B)

  return aad; // tam 25 byte
}

// ── syncEncrypt ───────────────────────────────────────────────────────────────
/**
 * XChaCha20-Poly1305 ile sifreleme. (INV-07, INV-08)
 *
 * Nonce her cagride CSPRNG ile uretilir — deterministik DEGILDIR.
 *
 * @param {Buffer} plaintext  Sifrelenecek veri
 * @param {Buffer} key        32 byte Sync Key
 * @param {Buffer} aad        25 byte AAD (buildAAD ciktisi)
 * @returns {{ ciphertext: Buffer, nonce: Buffer }}
 *   ciphertext: N+16B (libsodium cikti — ciphertext+auth_tag bitis,ik)
 *   nonce:      24B CSPRNG
 */
function syncEncrypt(plaintext, key, aad) {
  if (!Buffer.isBuffer(plaintext)) {
    throw new TypeError('SYNC_V2: plaintext Buffer olmalidir.');
  }
  if (!Buffer.isBuffer(key) || key.length !== SYNC_V2.KEY_LENGTH) {
    throw new RangeError('SYNC_V2: key tam olarak ' + SYNC_V2.KEY_LENGTH + ' byte olmalidir.');
  }
  if (!Buffer.isBuffer(aad) || aad.length !== SYNC_V2.AAD_LENGTH) {
    throw new RangeError('SYNC_V2: aad tam olarak ' + SYNC_V2.AAD_LENGTH + ' byte olmalidir.');
  }

  const sodium = requireSodium();

  // Nonce: CSPRNG — deterministik degil (INV-08)
  const nonce = crypto.randomBytes(SYNC_V2.NONCE_LENGTH);

  // libsodium: ciphertext = plaintext || auth_tag (bitiş,ik, 16B tag)
  const ciphertext = Buffer.allocUnsafe(
    plaintext.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES
  );

  sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    ciphertext, // output: ciphertext+tag
    plaintext,  // message
    aad,        // additional data
    null,       // nsec (unused in IETF variant)
    nonce,      // npub
    key         // k
  );

  return { ciphertext, nonce };
}

// ── syncDecrypt ───────────────────────────────────────────────────────────────
/**
 * XChaCha20-Poly1305 ile sifre cozme. (INV-07, INV-26)
 *
 * Auth Tag dogrulamasi basarisiz olursa plaintext ASLA disari verilmez.
 *
 * @param {Buffer} ciphertext  N+16B (ciphertext+auth_tag bitiş,ik)
 * @param {Buffer} key         32 byte Sync Key
 * @param {Buffer} nonce       24 byte nonce
 * @param {Buffer} aad         25 byte AAD
 * @returns {Buffer}           Plaintext (sadece auth OK ise)
 * @throws Auth fail durumunda — plaintext sizmaz (INV-26)
 */
function syncDecrypt(ciphertext, key, nonce, aad) {
  if (!Buffer.isBuffer(ciphertext)) {
    throw new TypeError('SYNC_V2: ciphertext Buffer olmalidir.');
  }
  if (!Buffer.isBuffer(key) || key.length !== SYNC_V2.KEY_LENGTH) {
    throw new RangeError('SYNC_V2: key tam olarak ' + SYNC_V2.KEY_LENGTH + ' byte olmalidir.');
  }
  if (!Buffer.isBuffer(nonce) || nonce.length !== SYNC_V2.NONCE_LENGTH) {
    throw new RangeError('SYNC_V2: nonce tam olarak ' + SYNC_V2.NONCE_LENGTH + ' byte olmalidir.');
  }
  if (!Buffer.isBuffer(aad) || aad.length !== SYNC_V2.AAD_LENGTH) {
    throw new RangeError('SYNC_V2: aad tam olarak ' + SYNC_V2.AAD_LENGTH + ' byte olmalidir.');
  }

  const sodium = requireSodium();
  const ABYTES = sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;

  if (ciphertext.length < ABYTES) {
    throw new RangeError(
      'SYNC_V2: ciphertext minimum ' + ABYTES + ' byte olmalidir (auth_tag dahil).'
    );
  }

  const plaintext = Buffer.allocUnsafe(ciphertext.length - ABYTES);

  // INV-26: Auth fail → sodium throw eder, plaintext temizlenir, exception wrap edilir.
  try {
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext,  // output (auth OK ise doldurulur)
      null,       // nsec
      ciphertext, // ciphertext+tag
      aad,        // additional data
      nonce,      // npub
      key         // k
    );
  } catch (_sodiumErr) {
    plaintext.fill(0); // guvenli temizlik — plaintext asla disari cikmaz (INV-26)
    throw new Error(
      'SYNC_V2_AUTH_FAILED: Sifre cozme basarisiz oldu. ' +
      'Yanlis Sync Password veya bozulmus/tahrif edilmis veri. ' +
      '(INV-26: plaintext aciga cikmadi)'
    );
  }

  return plaintext;
}

// ── buildEnvelope ─────────────────────────────────────────────────────────────
/**
 * V2 Outer Envelope olusturur. (INV-23, INV-27)
 *
 * Wire format:
 *   Offset 0  : [0x46][0x53]      — header_magic (2B)
 *   Offset 2  : [0x02]            — wire_version  (1B)
 *   Offset 3  : [salt: 16B]       — KDF salt
 *   Offset 19 : [nonce: 24B]      — XChaCha20 nonce
 *   Offset 43 : [ciphertext: N+16B] — ciphertext+auth_tag
 *   Total: N + 59 (INV-27)
 *
 * @param {Buffer} salt       16 byte KDF salt
 * @param {Buffer} nonce      24 byte nonce
 * @param {Buffer} ciphertext N+16B (syncEncrypt ciktisi)
 * @returns {Buffer}          Wire format envelope
 */
function buildEnvelope(salt, nonce, ciphertext) {
  if (!Buffer.isBuffer(salt) || salt.length !== SYNC_V2.SALT_LENGTH) {
    throw new RangeError('SYNC_V2: salt tam olarak ' + SYNC_V2.SALT_LENGTH + ' byte olmalidir.');
  }
  if (!Buffer.isBuffer(nonce) || nonce.length !== SYNC_V2.NONCE_LENGTH) {
    throw new RangeError('SYNC_V2: nonce tam olarak ' + SYNC_V2.NONCE_LENGTH + ' byte olmalidir.');
  }
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length < SYNC_V2.AUTH_TAG_LENGTH) {
    throw new RangeError(
      'SYNC_V2: ciphertext en az ' + SYNC_V2.AUTH_TAG_LENGTH + ' byte (auth_tag) olmalidir.'
    );
  }

  return Buffer.concat([
    Buffer.from([SYNC_V2.MAGIC_0, SYNC_V2.MAGIC_1]), // [0x46, 0x53]
    Buffer.from([SYNC_V2.WIRE_VERSION]),              // [0x02]
    salt,                                             // 16B
    nonce,                                            // 24B
    ciphertext,                                       // N+16B
  ]);
}

// ── parseEnvelope ─────────────────────────────────────────────────────────────
/**
 * V2 Outer Envelope parse eder. Malformed envelope kabul edilmez.
 *
 * Kontroller:
 *   - minimum length >= 59
 *   - magic [0x46, 0x53]
 *   - wire_version 0x02
 *   - salt: 16B
 *   - nonce: 24B
 *   - ciphertext: N+16B (N = total-59, minimum N>=0)
 *
 * @param {Buffer} envelope  Raw binary envelope
 * @returns {{ salt: Buffer, nonce: Buffer, ciphertext: Buffer }}
 * @throws Malformed envelope icin explicit hata
 */
function parseEnvelope(envelope) {
  if (!Buffer.isBuffer(envelope)) {
    throw new TypeError('SYNC_V2: envelope Buffer olmalidir.');
  }

  if (envelope.length < SYNC_V2.ENVELOPE_OVERHEAD) {
    throw new RangeError(
      'SYNC_V2_ENVELOPE_MALFORMED: Envelope cok kisa. ' +
      'Minimum ' + SYNC_V2.ENVELOPE_OVERHEAD + ' byte gereklidir, ' +
      envelope.length + ' byte alindi. (INV-27)'
    );
  }

  // magic kontrolu
  if (envelope[0] !== SYNC_V2.MAGIC_0 || envelope[1] !== SYNC_V2.MAGIC_1) {
    throw new Error(
      'SYNC_V2_ENVELOPE_MALFORMED: Gecersiz header magic. ' +
      'Beklenen: [0x46, 0x53], alinan: [0x' + envelope[0].toString(16) +
      ', 0x' + envelope[1].toString(16) + '] (INV-23)'
    );
  }

  // wire_version kontrolu
  if (envelope[2] !== SYNC_V2.WIRE_VERSION) {
    throw new Error(
      'SYNC_V2_ENVELOPE_MALFORMED: Desteklenmeyen wire_version: 0x' +
      envelope[2].toString(16) + '. Beklenen: 0x' +
      SYNC_V2.WIRE_VERSION.toString(16) + ' (INV-23)'
    );
  }

  // Offset tablosu
  const OFF_SALT   = 3;
  const OFF_NONCE  = OFF_SALT  + SYNC_V2.SALT_LENGTH;   // 19
  const OFF_CIPHER = OFF_NONCE + SYNC_V2.NONCE_LENGTH;  // 43

  const salt       = envelope.slice(OFF_SALT,  OFF_NONCE);  // 16B
  const nonce      = envelope.slice(OFF_NONCE, OFF_CIPHER); // 24B
  const ciphertext = envelope.slice(OFF_CIPHER);            // N+16B

  // Defensive assertions
  if (salt.length !== SYNC_V2.SALT_LENGTH) {
    throw new Error('SYNC_V2_ENVELOPE_MALFORMED: salt ' + SYNC_V2.SALT_LENGTH + ' byte olmalidir.');
  }
  if (nonce.length !== SYNC_V2.NONCE_LENGTH) {
    throw new Error('SYNC_V2_ENVELOPE_MALFORMED: nonce ' + SYNC_V2.NONCE_LENGTH + ' byte olmalidir.');
  }
  if (ciphertext.length < SYNC_V2.AUTH_TAG_LENGTH) {
    throw new RangeError(
      'SYNC_V2_ENVELOPE_MALFORMED: ciphertext en az ' + SYNC_V2.AUTH_TAG_LENGTH +
      ' byte olmalidir (auth_tag). (INV-27)'
    );
  }

  return { salt, nonce, ciphertext };
}

// ── initSyncSession ───────────────────────────────────────────────────────────
/**
 * Sync session icin gerekli random material uretir.
 * salt: 16B CSPRNG (INV-06)
 * sessionId: 8B CSPRNG (INV-11)
 *
 * @returns {{ salt: Buffer, sessionId: Buffer }}
 */
function initSyncSession() {
  return {
    salt:      generateSyncSalt(),
    sessionId: generateSessionId(),
  };
}

// ── EXPORTS ───────────────────────────────────────────────────────────────────
module.exports = {
  SYNC_V2,
  initSyncSession,
  deriveSyncKey,
  generateSyncSalt,
  generateSessionId,
  buildAAD,
  syncEncrypt,
  syncDecrypt,
  buildEnvelope,
  parseEnvelope,
};
