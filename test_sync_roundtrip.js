'use strict';
// ═══════════════════════════════════════════════════════════════════
// FUIN — QR SYNC UÇTAN UCA DOĞRULAMA TESTİ
//
// Amaç: main.js'deki kriptografi/chunk mantığının, gerçek bir "masaüstü
// (gönderen) -> QR kareleri -> telefon (alan)" akışında veriyi kayıpsız
// ve doğru şekilde taşıdığını kanıtlamak. Kamera/UI gerektirmez; sadece
// protokolün (asıl kırılgan olan kısmın) doğruluğunu test eder.
//
// Bu dosya main.js'den birebir kopyalanan fonksiyonları kullanır —
// mantık iki yerde farklılaşırsa test de gerçek kodla senkron kalmalı.
// ═══════════════════════════════════════════════════════════════════
const crypto = require('crypto');
const assert = require('assert');

let argon2 = null;
try { argon2 = require('argon2'); } catch { argon2 = null; }
console.log('KDF motoru:', argon2 ? 'Argon2id' : 'PBKDF2-SHA512 (argon2 native modül bulunamadı, fallback)');

// ── main.js'den birebir alınan crypto çekirdeği ─────────────────────
async function deriveVaultKey(passwordStr, vaultSalt) {
  const pwBuf = Buffer.from(passwordStr, 'utf8');
  let key;
  if (argon2) {
    try {
      const raw = await argon2.hash(pwBuf, { type: argon2.argon2id, salt: vaultSalt, memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32, raw: true });
      key = Buffer.from(raw); raw.fill(0);
    } catch { key = null; }
  }
  if (!key) key = await new Promise((res, rej) => crypto.pbkdf2(pwBuf, vaultSalt, 200000, 32, 'sha512', (e, k) => e ? rej(e) : res(k)));
  pwBuf.fill(0);
  return key;
}

async function deriveSyncKey(passwordStr, syncSalt) {
  const pwBuf = Buffer.from(passwordStr, 'utf8');
  const domainSalt = Buffer.concat([syncSalt, Buffer.from('FUIN_SYNC_V1', 'utf8')]);
  let key;
  if (argon2) {
    try {
      const raw = await argon2.hash(pwBuf, { type: argon2.argon2id, salt: domainSalt, memoryCost: 65536, timeCost: 3, parallelism: 1, hashLength: 32, raw: true });
      key = Buffer.from(raw); raw.fill(0);
    } catch { key = null; }
  }
  if (!key) key = await new Promise((res, rej) => crypto.pbkdf2(pwBuf, domainSalt, 200000, 32, 'sha512', (e, k) => e ? rej(e) : res(k)));
  pwBuf.fill(0); domainSalt.fill(0);
  return key;
}

async function encryptData(plaintext, passwordStr) {
  const vaultSalt = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const vaultKey = await deriveVaultKey(passwordStr, vaultSalt);
  const jsonBuf = Buffer.from(JSON.stringify(plaintext), 'utf8');
  const cipher = crypto.createCipheriv('aes-256-gcm', vaultKey, iv);
  const enc1 = cipher.update(jsonBuf); const enc2 = cipher.final(); const tag = cipher.getAuthTag();
  vaultKey.fill(0); jsonBuf.fill(0);
  return Buffer.concat([vaultSalt, iv, tag, enc1, enc2]).toString('base64');
}

async function decryptData(b64Str, passwordStr) {
  const buf = Buffer.from(b64Str, 'base64');
  const vaultSalt = buf.slice(0, 32), iv = buf.slice(32, 44), tag = buf.slice(44, 60), data = buf.slice(60);
  const vaultKey = await deriveVaultKey(passwordStr, vaultSalt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', vaultKey, iv);
  decipher.setAuthTag(tag);
  const dec1 = decipher.update(data); const dec2 = decipher.final();
  vaultKey.fill(0);
  return JSON.parse(Buffer.concat([dec1, dec2]).toString('utf8'));
}

// ── GÖNDEREN TARAF (masaüstü / sync.html + main.js) ─────────────────
async function buildQRChunks(encryptedB64, syncKey, syncSalt, chunkSize = 400) {
  const rawBuf = Buffer.from(encryptedB64, 'utf8');
  const tIv = crypto.randomBytes(12);
  const transferId = crypto.randomBytes(8).toString('hex').toUpperCase();
  const cipher = crypto.createCipheriv('aes-256-gcm', syncKey, tIv);
  const enc1 = cipher.update(rawBuf); const enc2 = cipher.final(); const tag = cipher.getAuthTag();
  const packet = Buffer.concat([syncSalt, tIv, tag, enc1, enc2]);
  const b64Packet = packet.toString('base64');
  const chunks = [];
  for (let i = 0; i < b64Packet.length; i += chunkSize) chunks.push(b64Packet.slice(i, i + chunkSize));
  return chunks.map((data, index) => ({ fuin: true, transferId, index: index + 1, total: chunks.length, data }));
}

// ── ALAN TARAF (telefon / QR kamera okuyucu simülasyonu) ────────────
// Gerçek kamerada kareler karışık sırayla, tekrarlı ve bazen atlamalı
// gelebilir — bu yüzden alıcı mantığı index'e göre sıralayıp
// tekrarları eleyerek birleştirmeli. Bunu da burada simüle ediyoruz.
async function receiveAndDecrypt(scrambledChunks, passwordStr) {
  const byIndex = new Map();
  for (const c of scrambledChunks) byIndex.set(c.index, c); // tekrarları otomatik ele
  const total = scrambledChunks[0].total;
  for (let i = 1; i <= total; i++) {
    if (!byIndex.has(i)) throw new Error(`Eksik chunk: ${i}/${total}`);
  }
  let b64Packet = '';
  for (let i = 1; i <= total; i++) b64Packet += byIndex.get(i).data;

  const packet = Buffer.from(b64Packet, 'base64');
  const syncSalt = packet.slice(0, 32), tIv = packet.slice(32, 44), tag = packet.slice(44, 60), ciphertext = packet.slice(60);
  const syncKey = await deriveSyncKey(passwordStr, syncSalt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', syncKey, tIv);
  decipher.setAuthTag(tag);
  const dec1 = decipher.update(ciphertext); const dec2 = decipher.final();
  syncKey.fill(0);
  return Buffer.concat([dec1, dec2]).toString('utf8'); // = orijinal encryptedB64 (vault blob)
}

// ═══════════════════════════════════════════════════════════════════
// TEST SENARYOLARI
// ═══════════════════════════════════════════════════════════════════
async function main() {
  const MASTER_PASSWORD = 'test-master-şifre-Ω-🔒-2026';
  const vault = [
    { id: '1', site: 'github.com', category: 'Geliştirici / Araçlar', username: 'sombo', password: 'S3cr3t!Pass', totp: null },
    { id: '2', site: 'gmail.com', category: 'E-posta', username: 'sombo@example.com', password: 'AnotherP@ss99', totp: 'JBSWY3DPEHPK3PXP' },
  ];

  console.log('\n[1/4] Vault, master password ile şifreleniyor (vaultKey)...');
  const encryptedB64 = await encryptData(vault, MASTER_PASSWORD);
  console.log('  ✓ Şifreli vault boyutu:', encryptedB64.length, 'karakter (base64)');

  console.log('\n[2/4] Sync oturumu başlatılıyor (syncKey, vaultKey\'den bağımsız türetiliyor)...');
  const syncSalt = crypto.randomBytes(32);
  const syncKey = await deriveSyncKey(MASTER_PASSWORD, syncSalt);
  console.log('  ✓ syncKey türetildi (32 byte):', syncKey.length === 32);

  console.log('\n[3/4] QR chunk\'ları üretiliyor (400 karakterlik parçalar, chunkSize=400)...');
  const chunks = await buildQRChunks(encryptedB64, syncKey, syncSalt, 400);
  console.log(`  ✓ ${chunks.length} chunk üretildi, transferId=${chunks[0].transferId}`);
  console.log('  ✓ Her chunk JSON boyutu (tek bir QR karesine sığması gerekir):', JSON.stringify(chunks[0]).length, 'byte');

  console.log('\n[4/4] Alıcı tarafta chunk\'lar karıştırılıp (gerçek kamera senaryosu) yeniden birleştiriliyor...');
  const scrambled = [...chunks].sort(() => Math.random() - 0.5); // kamera sırası garantili değil
  const duplicated = [...scrambled, scrambled[0], scrambled[scrambled.length - 1]]; // aynı kare birden çok kez okunabilir
  const recoveredEncryptedB64 = await receiveAndDecrypt(duplicated, MASTER_PASSWORD);

  assert.strictEqual(recoveredEncryptedB64, encryptedB64, 'Geri kazanılan vault blob\'u orijinaliyle eşleşmiyor!');
  console.log('  ✓ Yeniden birleştirilen paket, orijinal şifreli vault ile birebir eşleşiyor');

  const recoveredVault = await decryptData(recoveredEncryptedB64, MASTER_PASSWORD);
  assert.deepStrictEqual(recoveredVault, vault, 'Çözülen vault içeriği orijinaliyle eşleşmiyor!');
  console.log('  ✓ Vault içeriği (2 kayıt, kategori dahil) kayıpsız şekilde geri çözüldü');

  console.log('\n[EK TEST] Yanlış şifreyle çözme reddedilmeli...');
  try {
    await receiveAndDecrypt(chunks, 'yanlis-sifre');
    throw new Error('BEKLENMEDİK: yanlış şifreyle çözüm başarılı oldu, bu bir güvenlik açığıdır!');
  } catch (e) {
    assert.ok(e.message.includes('Unsupported state') || e.message.includes('bad decrypt') || e.code === 'ERR_OSSL_EVP_BAD_DECRYPT' || e.message.includes('auth'), 'Beklenmeyen hata: ' + e.message);
    console.log('  ✓ Yanlış şifre GCM auth-tag doğrulamasında reddedildi (beklenen davranış)');
  }

  console.log('\n[EK TEST] Eksik chunk (kamera bir kareyi kaçırdı) reddedilmeli...');
  try {
    await receiveAndDecrypt(chunks.slice(1), MASTER_PASSWORD); // ilk chunk eksik
    throw new Error('BEKLENMEDİK: eksik chunk ile çözüm başarılı oldu!');
  } catch (e) {
    assert.ok(e.message.includes('Eksik chunk'), 'Beklenmeyen hata: ' + e.message);
    console.log('  ✓ Eksik chunk doğru şekilde tespit edildi ve reddedildi');
  }

  console.log('\n═══════════════════════════════════════════');
  console.log('TÜM TESTLER BAŞARILI — QR sync protokolü uçtan uca doğru çalışıyor.');
  console.log('═══════════════════════════════════════════');
}

main().catch(e => { console.error('\n✗ TEST BAŞARISIZ:', e); process.exit(1); });
