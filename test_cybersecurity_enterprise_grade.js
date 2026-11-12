'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST SUITE: test_cybersecurity_enterprise_grade.js
 *
 * Enterprise Cybersecurity & Cryptographic Rigor Audit Suite:
 *   1. Adversarial Fuzzing & Prototype Pollution Invariance
 *   2. Unicode Bidirectional Spoofing & Injection Resilience
 *   3. Heterogeneous Multi-Type (Login / Card / Note) Two-Way LAN Merge
 *   4. Zero Data Loss & Non-Destructive Conflict Resolution
 *   5. Clock-Skew Ceiling Protection (+5 min Future Timestamp Ceiling)
 *   6. Authenticated Cryptographic Tamper Detection (AES-256-GCM & Tag Verif.)
 *   7. Sensitive Data Masking & PCI-DSS Style Card Last-4 Isolation
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const syncLan = require('./sync-lan.js');

console.log('═'.repeat(75));
console.log('FUIN ENTERPRISE CYBERSECURITY & ADVERSARIAL RIGOR AUDIT');
console.log('═'.repeat(75));

let passes = 0;
let failures = 0;

function test(desc, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✕ [FAIL] ${desc}`);
    console.error(`         ${err.message}`);
    failures++;
  }
}

// ── TEST 1: PROTOTYPE POLLUTION RESILIENCE ────────────────────────────────────
test('1. Prototype pollution girişimleri normalizeEntry tarafından güvenle bertaraf edilir', () => {
  const maliciousEntry = JSON.parse(`{
    "id": "exploit-1",
    "site": "evil.com",
    "username": "attacker",
    "password": "pwn",
    "__proto__": { "polluted": "yes", "isAdmin": true },
    "constructor": { "prototype": { "polluted": "yes" } }
  }`);

  const normalized = syncLan.normalizeEntry(maliciousEntry);
  assert.strictEqual(normalized.id, 'exploit-1');
  assert.strictEqual(normalized.polluted, undefined, 'Prototype pollution tespit edildi ve engellendi');
  assert.strictEqual(({}).polluted, undefined, 'Global Object prototype temiz kaldı');
});

// ── TEST 2: ADVERSARIAL PAYLOAD & UNICODE BIPOLAR INJECTIONS ──────────────────
test('2. Aşırı uzun girdiler, null byte (\\0) ve RTL spoofing normalizeEntry motorunu çökertmez', () => {
  const giantNote = 'A'.repeat(250000); // 250 KB tekil not metni
  const rtlSite = 'moc.elgoog\u202E/p/moc.evil//:sptth';
  const nullByteUser = 'admin\0hidden_suffix';

  const entry = {
    id: 'fuzz-1',
    type: 'note',
    site: rtlSite,
    username: nullByteUser,
    secureNote: giantNote,
    updatedAt: 5000
  };

  const normalized = syncLan.normalizeEntry(entry);
  assert.strictEqual(normalized.id, 'fuzz-1');
  assert.strictEqual(normalized.site, rtlSite);
  assert.strictEqual(normalized.username, nullByteUser);
  assert.strictEqual(normalized.secureNote.length, 250000);
});

// ── TEST 3: FUTURE TIMESTAMP POISONING (CLOCK-SKEW CEILING) ───────────────────
test('3. Gelecek zaman damgası zehirlemesi (+5 dakikadan büyük) tavana vurur, kasayı ele geçiremez', () => {
  const now = Date.now();
  const futurePoisonTime = now + (1000 * 60 * 60 * 24 * 365); // 1 yıl ilerisi!

  const poisonEntry = {
    id: 'poison-1',
    site: 'target.com',
    username: 'alice',
    password: 'old',
    updatedAt: futurePoisonTime
  };

  const normalized = syncLan.normalizeEntry(poisonEntry);
  assert.ok(normalized.updatedAt <= now + 300000, 'Zaman damgası +5 dakikalık tavan sınırını aşamadı');
});

// ── TEST 4: HETEROGENEOUS TWO-WAY MERGE (LOGIN + CARD + NOTE) ────────────────
test('4. Giriş, Kredi Kartı ve Güvenli Not kayıtları iki yönlü P2P senkronizasyonunda eksiksiz birleşir', () => {
  const desktopEntries = [
    {
      id: 'login-1',
      type: 'login',
      site: 'github.com',
      username: 'alice',
      password: 'enc_pw1',
      totp: 'enc_totp1',
      category: 'Geliştirici / Araçlar',
      updatedAt: 1000
    },
    {
      id: 'card-1',
      type: 'card',
      site: 'Garanti Bonus',
      cardholderName: 'ALICE SMITH',
      cardNumber: 'enc_4543000011112222',
      cardLastFour: '2222',
      cardExpiry: '12/28',
      cardCvv: 'enc_999',
      category: 'Finans',
      updatedAt: 2000
    }
  ];

  const mobileEntries = [
    {
      id: 'note-1',
      type: 'note',
      site: 'Ev Wi-Fi Şifresi',
      secureNote: 'enc_WPA3_SuperSecret_2026',
      category: 'Diğer',
      updatedAt: 3000
    }
  ];

  const { mergedEntries, stats } = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);

  assert.strictEqual(mergedEntries.length, 3, 'Tüm 3 farklı tipteki kayıt birleşti');
  const login = mergedEntries.find(e => e.id === 'login-1');
  const card = mergedEntries.find(e => e.id === 'card-1');
  const note = mergedEntries.find(e => e.id === 'note-1');

  assert.ok(login && login.type === 'login', 'Login kaydı korundu');
  assert.ok(card && card.type === 'card' && card.cardLastFour === '2222', 'Kart kaydı ve last4 korundu');
  assert.ok(note && note.type === 'note' && note.secureNote === 'enc_WPA3_SuperSecret_2026', 'Güvenli not korundu');
});

// ── TEST 5: CONFLICT-FREE DETERMINISTIC MERGE FOR PAYMENT CARDS ───────────────
test('5. Kredi kartı çakışmasında en güncel sürüm ana kayıt olur, eski sürüm geçmişe (history) kaydedilir', () => {
  const desktopCard = {
    id: 'card-shared-1',
    type: 'card',
    site: 'İş Maximum',
    cardholderName: 'BOB',
    cardNumber: 'enc_card_old',
    cardExpiry: '06/26',
    cardCvv: 'enc_111',
    updatedAt: 1500
  };

  const mobileCard = {
    id: 'card-shared-1',
    type: 'card',
    site: 'İş Maximum',
    cardholderName: 'BOB',
    cardNumber: 'enc_card_new',
    cardExpiry: '06/28', // Kart yenilendi
    cardCvv: 'enc_222',
    updatedAt: 2500 // Daha güncel
  };

  const { mergedEntries } = syncLan.mergeVaultEntries([desktopCard], [mobileCard]);
  assert.strictEqual(mergedEntries.length, 1);
  const winner = mergedEntries[0];

  assert.strictEqual(winner.cardNumber, 'enc_card_new', 'Yeni kart verisi kazandı');
  assert.strictEqual(winner.cardExpiry, '06/28');
  assert.strictEqual(winner.history.length, 1, 'Eski kart verisi history içinde korundu');
  assert.strictEqual(winner.history[0].cardNumber, 'enc_card_old', 'Eski kart numarası veri kaybı olmadan saklandı');
});

// ── TEST 6: CRYPTOGRAPHIC AUTHENTICATED TAMPER RESISTANCE (AES-256-GCM) ───────
test('6. AES-256-GCM kimlik doğrulama etiketi bozulduğunda şifre çözme işlemi güvenle hata verir (Plaintext sızmaz)', () => {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const plaintext = Buffer.from('TOP_SECRET_CREDIT_CARD_PAN_4543999988887777');

  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Tamper: 1 bit flip in ciphertext
  const tamperedCiphertext = Buffer.from(ciphertext);
  tamperedCiphertext[0] ^= 0x01;

  assert.throws(() => {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    Buffer.concat([decipher.update(tamperedCiphertext), decipher.final()]);
  }, /unsupported state or unable to authenticate data/i, 'Bozulmuş şifreli metin deşifre edilemedi');

  // Tamper: 1 bit flip in auth tag
  const tamperedTag = Buffer.from(tag);
  tamperedTag[0] ^= 0x01;

  assert.throws(() => {
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tamperedTag);
    Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }, /unsupported state or unable to authenticate data/i, 'Bozulmuş kimlik etiketi deşifre edilemedi');
});

// ── TEST 7: SECURE NOTE TOMBSTONE & DELETION PROPAGATION ───────────────────────
test('7. Güvenli not silme (tombstone) işlemi diğer platformlara veri kaybı olmaksızın yayılır', () => {
  const desktopNote = {
    id: 'note-secret-99',
    type: 'note',
    site: 'Server SSH Passphrase',
    secureNote: 'ssh-ed25519-secret',
    updatedAt: 1000
  };

  const mobileDeletion = {
    id: 'note-secret-99',
    type: 'note',
    site: 'Server SSH Passphrase',
    secureNote: 'ssh-ed25519-secret',
    updatedAt: 2000,
    deletedAt: 2000,
    isDeleted: true
  };

  const { mergedEntries } = syncLan.mergeVaultEntries([desktopNote], [mobileDeletion]);
  assert.strictEqual(mergedEntries.length, 1);
  const result = mergedEntries[0];

  assert.strictEqual(result.isDeleted, true, 'Silme işlemi başarıyla uygulandı');
  assert.strictEqual(result.deletedAt, 2000);
  assert.strictEqual(result.history.length, 1, 'Silinmeden önceki içerik geçmişte güvenle arşivlendi');
  assert.strictEqual(result.history[0].secureNote, 'ssh-ed25519-secret');
});

// ── TEST 8: CREDIT CARD AUTO-RECOGNITION, FORMATTING & SIDEBAR ERGONOMICS ────
test('8. Kredi kartı Troy/Visa/Mastercard/Amex otomatik tanıma, biçimlendirme ve kenar çubuğu ergonomisi', () => {
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const styleCss = fs.readFileSync(path.join(__dirname, 'renderer', 'style.css'), 'utf8');

  // Verify functions exist in app.js
  assert.ok(appJs.includes('function detectCardBrand('), 'detectCardBrand fonksiyonu app.js içinde mevcut olmalıdır');
  assert.ok(appJs.includes('function formatCardNumber('), 'formatCardNumber fonksiyonu app.js içinde mevcut olmalıdır');
  assert.ok(appJs.includes('function formatCardExpiry('), 'formatCardExpiry fonksiyonu app.js içinde mevcut olmalıdır');

  // Extract and test detectCardBrand logic directly
  const detectFnMatch = appJs.match(/function detectCardBrand\([\s\S]*?\n\}/);
  assert.ok(detectFnMatch, 'detectCardBrand parse edilebilmelidir');
  const detectCardBrand = new Function(`return ${detectFnMatch[0]}`)();

  // Test Troy
  const troy = detectCardBrand('9792123456781234');
  assert.strictEqual(troy.brand, 'troy');
  assert.strictEqual(troy.name, 'TROY');

  // Test Visa
  const visa = detectCardBrand('4543123456789012');
  assert.strictEqual(visa.brand, 'visa');
  assert.strictEqual(visa.name, 'VISA');

  // Test Mastercard
  const mc1 = detectCardBrand('5412345678901234');
  assert.strictEqual(mc1.brand, 'mastercard');
  const mc2 = detectCardBrand('2221000011112222');
  assert.strictEqual(mc2.brand, 'mastercard');

  // Test Amex
  const amex = detectCardBrand('378282246310005');
  assert.strictEqual(amex.brand, 'amex');
  assert.strictEqual(amex.name, 'AMEX');
  assert.strictEqual(amex.maxLen, 15);

  // Test formatCardNumber logic
  const formatNumMatch = appJs.match(/function formatCardNumber\([\s\S]*?\n\}/);
  const formatCardNumber = new Function('detectCardBrand', `return ${formatNumMatch[0]}`)(detectCardBrand);

  const troyFormatted = formatCardNumber('9792123456781234');
  assert.strictEqual(troyFormatted.formatted, '9792 1234 5678 1234');

  const amexFormatted = formatCardNumber('378282246310005');
  assert.strictEqual(amexFormatted.formatted, '3782 822463 10005');

  // Test formatCardExpiry logic
  const formatExpMatch = appJs.match(/function formatCardExpiry\([\s\S]*?\n\}/);
  const formatCardExpiry = new Function(`return ${formatExpMatch[0]}`)();
  assert.strictEqual(formatCardExpiry('5'), '05/');
  assert.strictEqual(formatCardExpiry('1228'), '12/28');
  assert.strictEqual(formatCardExpiry('12/28'), '12/28');

  // Verify Sidebar layout and DOM IDs
  assert.ok(indexHtml.includes('class="sidebar-scroll"'), 'index.html içinde .sidebar-scroll kaydırma kapsayıcısı bulunmalıdır');
  assert.ok(indexHtml.includes('class="sidebar-bottom"'), 'index.html içinde .sidebar-bottom sabit kapsayıcısı bulunmalıdır');

  const sideBottomIdx = indexHtml.indexOf('class="sidebar-bottom"');
  const sideBottomHtml = indexHtml.slice(sideBottomIdx, sideBottomIdx + 1200);
  assert.ok(sideBottomHtml.includes('id="nav-sync"'), '#nav-sync butonu sabit .sidebar-bottom içinde olmalıdır');
  assert.ok(sideBottomHtml.includes('id="nav-lock"'), '#nav-lock butonu sabit .sidebar-bottom içinde olmalıdır');

  // Verify custom scrollbar styling in style.css
  assert.ok(styleCss.includes('.sidebar-scroll::-webkit-scrollbar'), 'style.css içinde .sidebar-scroll için özel kaydırma çubuğu tanımlanmalıdır');
  assert.ok(styleCss.includes('.card-brand-badge'), 'style.css içinde .card-brand-badge tanımlanmalıdır');
  assert.ok(styleCss.includes('.btn-sync-side'), 'style.css içinde .btn-sync-side tanımlanmalıdır');
});

// ── TEST 9: DYNAMIC I18N PARITY & MODAL PLACEHOLDER HYGIENE ──────────────────
test('9. Dil değişimi sırasında Kredi Kartı ve Güvenli Not alanlarının dinamik i18n senkronizasyonu', () => {
  const i18nJs = fs.readFileSync(path.join(__dirname, 'renderer', 'i18n.js'), 'utf8');
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

  // Verify neutral placeholder for cardholder name (no personal sample names)
  assert.strictEqual(indexHtml.includes('AHMET YILMAZ'), false, 'index.html içinde AHMET YILMAZ bulunmamalıdır');
  assert.strictEqual(i18nJs.includes('AHMET YILMAZ'), false, 'i18n.js içinde AHMET YILMAZ bulunmamalıdır');
  assert.ok(indexHtml.includes('placeholder="İsim Soyisim"'), 'index.html kart sahibi yer tutucusu "İsim Soyisim" olmalıdır');
  assert.ok(i18nJs.includes("fieldCardholderPh: 'İsim Soyisim'"), 'i18n.js TR sözlüğünde "İsim Soyisim" bulunmalıdır');
  assert.ok(i18nJs.includes("fieldCardholderPh: 'First & Last Name'"), 'i18n.js EN sözlüğünde "First & Last Name" bulunmalıdır');

  // Verify dynamic data-i18n attribute switching in setModalType
  assert.ok(appJs.includes("lblSite.setAttribute('data-i18n', 'fieldCardTitle')"), 'setModalType kart modunda data-i18n özniteliğini günceller');
  assert.ok(appJs.includes("fSite.setAttribute('data-i18n-placeholder', 'fieldCardTitlePh')"), 'setModalType kart modunda data-i18n-placeholder özniteliğini günceller');
  assert.ok(appJs.includes("lblSite.setAttribute('data-i18n', 'fieldNoteTitle')"), 'setModalType not modunda data-i18n özniteliğini günceller');
  assert.ok(appJs.includes("fSite.setAttribute('data-i18n-placeholder', 'fieldNoteTitlePh')"), 'setModalType not modunda data-i18n-placeholder özniteliğini günceller');

  // Verify refreshDynamicI18nLabels calls setModalType to prevent UI drift
  assert.ok(appJs.includes('setModalType(currentModalType)'), 'refreshDynamicI18nLabels içinde setModalType çağrılarak arayüz yenilenmelidir');

  // Verify Security Info card in Ayarlar uses standard full-width layout
  assert.ok(indexHtml.includes('id="securityInfoCard"'), 'Ayarlar içinde #securityInfoCard bulunmalıdır');
  assert.ok(indexHtml.includes('data-i18n="settingSecuritySectionTitle"'), 'Ayarlar içinde Güvenlik bölüm başlığı bulunmalıdır');
});

// ── TEST 10: 2FA MODAL WRAPPER FLEX SPACING INVARIANCE ────────────────────────
test('10. 2FA modal bölümü (#section-2fa-wrap) dikey flex düzeni, 12px gap ve çizgi yapışmama doğrulaması', () => {
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const styleCss = fs.readFileSync(path.join(__dirname, 'renderer', 'style.css'), 'utf8');
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

  // Verify flex styling in index.html and style.css
  assert.ok(indexHtml.includes('id="section-2fa-wrap" style="display:flex; flex-direction:column; gap:12px;"'), 'index.html içinde #section-2fa-wrap dikey flex ve gap:12px içermelidir');
  assert.ok(styleCss.includes('#section-2fa-wrap {\n  display: flex;\n  flex-direction: column;\n  gap: 12px;\n}'), 'style.css içinde #section-2fa-wrap tanımlı olmalıdır');

  // Verify app.js sets display to 'flex' (never 'block' which would break gap)
  assert.ok(appJs.includes("if (sec2fa) sec2fa.style.display = 'flex';"), 'app.js login modunda sec2fa.style.display flex yapmalıdır');
  assert.strictEqual(appJs.includes("if (sec2fa) sec2fa.style.display = 'block';"), false, 'app.js içinde sec2fa display block kullanılmamalıdır');
});

console.log('═'.repeat(75));
console.log(`SUMMARY: ${passes} passed, ${failures} failed.`);
console.log('═'.repeat(75));

if (failures > 0) process.exit(1);
