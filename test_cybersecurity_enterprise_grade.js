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

// ── TEST 11: THEME TOGGLE CENTERING & MODAL CATEGORY TYPE SWITCHING ───────────
test('11. Tema düğmesi (#themeToggle) SVG ortalama ve modal tür değişiminde kategori sıfırlama doğrulanır', () => {
  const indexHtml = fs.readFileSync(path.join(__dirname, 'renderer', 'index.html'), 'utf8');
  const styleCss = fs.readFileSync(path.join(__dirname, 'renderer', 'style.css'), 'utf8');
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

  // Verify #themeToggle uses inline SVG (immune to Unicode glyph baseline shift) and clean flex CSS
  assert.ok(indexHtml.includes('id="themeToggleHalf"'), 'index.html #themeToggle içinde #themeToggleHalf SVG path bulunmalıdır');
  assert.ok(/#themeToggle\s*\{[\s\S]*?width:\s*28px;\s*height:\s*28px;[\s\S]*?display:\s*inline-flex;[\s\S]*?padding:\s*0;/.test(styleCss), '#themeToggle CSS tam ortalanmış inline-flex + padding:0 olmalıdır');

  // Extract setModalType & applyTheme and verify behavioral transitions in an isolated mock DOM
  const setModalMatch = appJs.match(/function setModalType\(type\)\s*\{[\s\S]*?\n\}/);
  const applyThemeMatch = appJs.match(/function applyTheme\(theme\)\s*\{[\s\S]*?\n\}/);
  assert.ok(setModalMatch && applyThemeMatch, 'setModalType ve applyTheme işlevleri ayrıştırılabilmelidir');

  const elements = {};
  const makeEl = (id, initVal = '') => {
    const attrs = {};
    const el = {
      id,
      value: initVal,
      textContent: '',
      placeholder: '',
      style: {},
      classList: { toggle: () => {} },
      setAttribute: (k, v) => { attrs[k] = v; },
      getAttribute: (k) => attrs[k]
    };
    elements[id] = el;
    return el;
  };
  ['btnTypeLogin', 'btnTypeCard', 'btnTypeNote', 'lbl-site', 'f-site', 'section-login-fields', 'section-card-fields', 'section-note-fields', 'section-2fa-wrap'].forEach(id => makeEl(id));
  const fCat = makeEl('f-category', 'Diğer');
  const half = makeEl('themeToggleHalf');

  const runner = new Function('els', `
    let currentModalType = 'login';
    let modalCategoryManuallySet = false;
    let editId = null;
    const t = (k) => k;
    const localStorage = { setItem: () => {} };
    const document = {
      documentElement: { dataset: {} },
      getElementById: (id) => els[id] || null
    };
    ${setModalMatch[0]}
    ${applyThemeMatch[0]}
    return {
      setModalType,
      applyTheme,
      setManual: (v) => { modalCategoryManuallySet = v; }
    };
  `)(elements);

  // New entry: login ('Diğer') -> card ('Finans') -> login ('Diğer') -> card ('Finans') -> note ('Diğer')
  runner.setModalType('card');
  assert.strictEqual(fCat.value, 'Finans', 'Kart sekmesine geçince kategori Finans olmalıdır');
  runner.setModalType('login');
  assert.strictEqual(fCat.value, 'Diğer', 'Karttan Giriş sekmesine geçince otomatik kategori Diğer olmalıdır');
  runner.setModalType('card');
  assert.strictEqual(fCat.value, 'Finans', 'Tekrar Kart sekmesine geçince kategori Finans olmalıdır');
  runner.setModalType('note');
  assert.strictEqual(fCat.value, 'Diğer', 'Karttan Güvenli Not sekmesine geçince otomatik kategori Diğer olmalıdır');

  // Manual selection must be preserved across tab switches
  fCat.value = 'İş / Kurumsal';
  runner.setManual(true);
  runner.setModalType('card');
  assert.strictEqual(fCat.value, 'İş / Kurumsal', 'Kullanıcı manuel kategori seçtiyse Kart sekmesine geçişte korunmalıdır');
  runner.setModalType('login');
  assert.strictEqual(fCat.value, 'İş / Kurumsal', 'Kullanıcı manuel kategori seçtiyse Giriş sekmesine geçişte korunmalıdır');

  // Theme SVG path flips between dark and light cleanly
  runner.applyTheme('dark');
  assert.strictEqual(half.getAttribute('d'), 'M12 3a9 9 0 0 1 0 18z', 'Koyu temada sağ yarım dolu SVG path kullanılmalıdır');
  runner.applyTheme('light');
  assert.strictEqual(half.getAttribute('d'), 'M12 3a9 9 0 0 0 0 18z', 'Açık temada sol yarım dolu SVG path kullanılmalıdır');
});

function extractAppFnBody(appCode, fnStart, fromIdx = 0) {
  const startIdx = typeof fnStart === 'number' ? fnStart : appCode.indexOf(fnStart, fromIdx);
  assert.ok(startIdx !== -1, `${fnStart} bulunamadı`);
  const braceStart = appCode.indexOf('{', startIdx);
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let inTemplate = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escaped = false;
  for (let i = braceStart; i < appCode.length; i++) {
    const ch = appCode[i];
    const next = appCode[i + 1];
    if (inLineComment) { if (ch === '\n') inLineComment = false; continue; }
    if (inBlockComment) { if (ch === '*' && next === '/') { inBlockComment = false; i++; } continue; }
    if (escaped) { escaped = false; continue; }
    if ((inSingle || inDouble || inTemplate) && ch === '\\') { escaped = true; continue; }
    if (inSingle) { if (ch === "'") inSingle = false; continue; }
    if (inDouble) { if (ch === '"') inDouble = false; continue; }
    if (inTemplate) { if (ch === '`') inTemplate = false; continue; }
    if (ch === '/' && next === '/') { inLineComment = true; i++; continue; }
    if (ch === '/' && next === '*') { inBlockComment = true; i++; continue; }
    if (ch === "'") { inSingle = true; continue; }
    if (ch === '"') { inDouble = true; continue; }
    if (ch === '`') { inTemplate = true; continue; }
    if (ch === '{') depth++;
    else if (ch === '}') {
      depth--;
      if (depth === 0) return appCode.slice(startIdx, i + 1);
    }
  }
  throw new Error(`Brace balance failed for ${fnStart}`);
}

// ── TEST 12: DESKTOP RAM ENCRYPTION & SYNC SERIALIZATION GUARD ([object Object] PREVENTION) ──
test('12a. Desktop sync, QR, pairing ve yedek geri yükleme tüm hassas alanları tam serileştirir', () => {
  const fs = require('fs');
  const path = require('path');
  const appCode = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

  const genBody = extractAppFnBody(appCode, 'const generateWithPassword = async');
  const lanBody = extractAppFnBody(appCode, 'async function startLanSyncFlow(');
  const pairBody = extractAppFnBody(appCode, 'async function openPairingModal(');
  const restoreBody = extractAppFnBody(appCode, 'async function restoreSnapshotByFilename(');
  const appliedStart = appCode.indexOf('api.onLanSyncApplied(');
  assert.ok(appliedStart !== -1, 'api.onLanSyncApplied bulunamadı');
  const appliedArrow = appCode.indexOf('=>', appliedStart);
  assert.ok(appliedArrow !== -1, 'onLanSyncApplied ok işareti bulunamadı');
  const appliedBody = extractAppFnBody(appCode, appliedArrow);

  assert.ok(/\bserializeEntryPlain\b/.test(genBody), 'generateWithPassword serializeEntryPlain kullanmalıdır');
  assert.ok(/\bserializeEntryPlain\b/.test(lanBody), 'startLanSyncFlow serializeEntryPlain kullanmalıdır');
  assert.ok(/\bserializeEntryPlain\b/.test(pairBody), 'openPairingModal serializeEntryPlain kullanmalıdır');
  assert.ok(/\bhydrateEntryMemory\b/.test(restoreBody), 'restoreSnapshotByFilename hydrateEntryMemory kullanmalıdır');
  assert.ok(/\bhydrateEntryMemory\b/.test(appliedBody), 'onLanSyncApplied hydrateEntryMemory kullanmalıdır');
  assert.ok(!/memDecrypt\s*\(\s*e\.password\s*\)/.test(genBody + lanBody + pairBody), 'Sync akışlarında eksik alan çözen eski memDecrypt(e.password) kalmamalıdır');
  assert.ok(/e\.type\s*===\s*'login'/.test(appliedBody), 'onLanSyncApplied site||user dedup sadece login kayıtlarına uygulanmalıdır');
});

(async () => {
  try {
    const fs = require('fs');
    const path = require('path');
    const { webcrypto } = require('crypto');
    const appCode = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

    const ramFieldsMatch = appCode.match(/const RAM_SECRET_FIELDS\s*=\s*\[[^\]]+\];/);
    assert.ok(ramFieldsMatch, 'RAM_SECRET_FIELDS tanımı bulunamadı');
    const ramBlock = [
      ramFieldsMatch[0],
      extractAppFnBody(appCode, 'async function memEncrypt('),
      extractAppFnBody(appCode, 'async function memDecrypt('),
      extractAppFnBody(appCode, 'function scrubLegacySecret('),
      extractAppFnBody(appCode, 'async function transformHistorySecrets('),
      extractAppFnBody(appCode, 'async function serializeEntryPlain('),
      extractAppFnBody(appCode, 'async function hydrateEntryMemory(')
    ].join('\n');

    const key = await webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const helpers = new Function('crypto', 'sessionKey', 'TextEncoder', 'TextDecoder', `
      ${ramBlock}
      return { memEncrypt, memDecrypt, serializeEntryPlain, hydrateEntryMemory };
    `)(webcrypto, key, TextEncoder, TextDecoder);

    const noteEntry = {
      id: 'note-1',
      type: 'note',
      site: 'Test Notu',
      secureNote: 'Gizli güvenli not içeriği 🚀',
      history: [{ secureNote: 'Eski güvenli not', date: 100 }],
      updatedAt: 2000
    };
    const cardEntry = {
      id: 'card-1',
      type: 'card',
      site: 'Amex Gold',
      cardNumber: '3782 822463 10005',
      cardCvv: '1234',
      cardPin: '9988',
      updatedAt: 2000
    };

    const hydratedNote = await helpers.hydrateEntryMemory(noteEntry);
    assert.strictEqual(typeof hydratedNote.secureNote, 'object');
    assert.ok(Array.isArray(hydratedNote.secureNote.iv) && Array.isArray(hydratedNote.secureNote.data));
    assert.strictEqual(typeof hydratedNote.history[0].secureNote, 'object');

    const plainNote = await helpers.serializeEntryPlain(hydratedNote);
    assert.strictEqual(plainNote.secureNote, 'Gizli güvenli not içeriği 🚀');
    assert.strictEqual(plainNote.history[0].secureNote, 'Eski güvenli not');

    // Re-hydrating an already RAM-encrypted Desktop object must preserve content instead of "[object Object]"
    const reHydratedNote = await helpers.hydrateEntryMemory(hydratedNote);
    const rePlainNote = await helpers.serializeEntryPlain(reHydratedNote);
    assert.strictEqual(rePlainNote.secureNote, 'Gizli güvenli not içeriği 🚀');
    assert.notStrictEqual(rePlainNote.secureNote, '[object Object]');

    // Card fields round-trip cleanly
    const hydratedCard = await helpers.hydrateEntryMemory(cardEntry);
    const plainCard = await helpers.serializeEntryPlain(hydratedCard);
    assert.strictEqual(plainCard.cardNumber, '3782 822463 10005');
    assert.strictEqual(plainCard.cardCvv, '1234');
    assert.strictEqual(plainCard.cardPin, '9988');

    // Alien objects passed to memEncrypt must return null, NEVER "[object Object]"
    assert.strictEqual(await helpers.memEncrypt({ iv: 'hex', tag: 'tag', data: 'data' }), null);
    assert.strictEqual(await helpers.memEncrypt({ foo: 'bar' }), null);

    // Legacy "[object Object]" corruption on card/note fields heals automatically
    const legacyCorruptCard = {
      id: 'legacy-card-1',
      type: 'card',
      site: 'Legacy Bank',
      cardNumber: '[object Object]',
      cardCvv: '[object Object]',
      cardPin: '[object Object]',
      secureNote: '[object Object]',
      updatedAt: 2000
    };
    const healedHydrated = await helpers.hydrateEntryMemory(legacyCorruptCard);
    const healedPlain = await helpers.serializeEntryPlain(healedHydrated);
    assert.strictEqual(healedPlain.cardNumber, '');
    assert.strictEqual(healedPlain.cardCvv, '');
    assert.strictEqual(healedPlain.cardPin, '');
    assert.strictEqual(healedPlain.secureNote, '');

    // Two distinct cards with identical bank name & cardholder name must NOT collide in sync-lan merge
    const cardMergeRes = syncLan.mergeVaultEntries(
      [{ id: 'card-a', type: 'card', site: 'Garanti', username: 'Kadir', cardholderName: 'Kadir', cardLastFour: '1111', updatedAt: 1000 }],
      [{ id: 'card-b', type: 'card', site: 'Garanti', username: 'Kadir', cardholderName: 'Kadir', cardLastFour: '2222', updatedAt: 2000 }]
    );
    assert.strictEqual(cardMergeRes.mergedEntries.length, 2, 'Aynı banka/isimli iki farklı kart senkronizasyonda ezilmemelidir');

    passes++;
    console.log('✅ PASS: 12b. Desktop WebCrypto hydrateEntryMemory/serializeEntryPlain güvenli not ve kartları bozmaz');
  } catch (err) {
    failures++;
    console.error('❌ FAIL: 12b. Desktop WebCrypto RAM koruma testi başarısız');
    console.error('   Reason:', err.stack || err.message);
  }

  // ── TEST 13: DESKTOP CATEGORY ALIAS NORMALIZATION & TR/EN DISPLAY PARITY ──────
  try {
    const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');
    const i18nJs = fs.readFileSync(path.join(__dirname, 'renderer', 'i18n.js'), 'utf8');
    const dictMatch = /const TRANSLATIONS\s*=\s*\{[\s\S]*?\n\};/.exec(i18nJs);
    assert.ok(dictMatch, 'renderer/i18n.js must declare TRANSLATIONS');
    const TRANSLATIONS = new Function(`${dictMatch[0]}; return TRANSLATIONS;`)();

    const startIdx = appJs.indexOf('const CATEGORY_KEY_MAP = {');
    const endMarker = '// özel/bilinmeyen kategori adı ise olduğu gibi bırak\n}';
    const endMarkerIdx = appJs.indexOf(endMarker, startIdx);
    const endIdx = endMarkerIdx !== -1 ? endMarkerIdx + endMarker.length : -1;
    assert.ok(startIdx !== -1 && endIdx !== -1 && endIdx > startIdx, 'CATEGORY_KEY_MAP / catLabel bloğu renderer/app.js içinde bulunmalıdır');
    const catSlice = appJs.slice(startIdx, endIdx);

    let activeLang = 'en';
    const tMock = (k) => (TRANSLATIONS[activeLang] && TRANSLATIONS[activeLang][k]) || k;
    const catHelpers = new Function('t', `${catSlice}; return { CATEGORY_KEY_MAP, canonicalCategory, catLabel };`)(tMock);

    // Desktop canonical + Mobile TR/EN values translate cleanly in EN
    activeLang = 'en';
    assert.strictEqual(catHelpers.catLabel('Finans'), 'Finance');
    assert.strictEqual(catHelpers.catLabel('Finance'), 'Finance');
    assert.strictEqual(catHelpers.catLabel('Diğer'), 'Other');
    assert.strictEqual(catHelpers.catLabel('Other'), 'Other');
    assert.strictEqual(catHelpers.catLabel('Sosyal'), 'Social Media');
    assert.strictEqual(catHelpers.catLabel('Social'), 'Social Media');
    assert.strictEqual(catHelpers.catLabel('İş'), 'Work / Corporate');
    assert.strictEqual(catHelpers.catLabel('Work'), 'Work / Corporate');
    assert.strictEqual(catHelpers.catLabel('E-Ticaret'), 'Shopping');
    assert.strictEqual(catHelpers.catLabel('Eğitim'), 'Education');
    assert.strictEqual(catHelpers.catLabel('Education'), 'Education');

    // Switched to TR: Mobile EN strings translate cleanly to Turkish
    activeLang = 'tr';
    assert.strictEqual(catHelpers.catLabel('Finance'), 'Finans');
    assert.strictEqual(catHelpers.catLabel('Social'), 'Sosyal Medya');
    assert.strictEqual(catHelpers.catLabel('Email'), 'E-posta');
    assert.strictEqual(catHelpers.catLabel('Work'), 'İş / Kurumsal');
    assert.strictEqual(catHelpers.catLabel('Shopping'), 'Alışveriş');
    assert.strictEqual(catHelpers.catLabel('Gaming'), 'Oyun');
    assert.strictEqual(catHelpers.catLabel('Developer'), 'Geliştirici / Araçlar');
    assert.strictEqual(catHelpers.catLabel('Education'), 'Eğitim');
    assert.strictEqual(catHelpers.catLabel('Other'), 'Diğer');

    // Canonicalization & custom category preservation
    assert.strictEqual(catHelpers.canonicalCategory('Finance'), 'Finans');
    assert.strictEqual(catHelpers.canonicalCategory('Social'), 'Sosyal Medya');
    assert.strictEqual(catHelpers.canonicalCategory('E-Ticaret'), 'Alışveriş');
    assert.strictEqual(catHelpers.canonicalCategory('İş'), 'İş / Kurumsal');
    assert.strictEqual(catHelpers.canonicalCategory('CustomVaultCat'), 'CustomVaultCat');
    assert.strictEqual(catHelpers.catLabel('CustomVaultCat'), 'CustomVaultCat');

    // All standard keys exist in both TR and EN in Desktop i18n
    for (const k of Object.values(catHelpers.CATEGORY_KEY_MAP)) {
      assert.ok(TRANSLATIONS.tr[k] && TRANSLATIONS.en[k], `Desktop i18n missing ${k}`);
    }

    passes++;
    console.log('✅ PASS: 13. Desktop kategori alias normalizasyonu ve TR/EN gösterim eşliği eksiksiz çalışır');
  } catch (err) {
    failures++;
    console.error('❌ FAIL: 13. Desktop kategori i18n testi başarısız');
    console.error('   Reason:', err.stack || err.message);
  }

  // ── TEST 14: POST-BETA.11 AUDIT SECURITY HARDENING & BOUNDARY CHECKS ──────────
  try {
    const mainJs = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');
    const appJs = fs.readFileSync(path.join(__dirname, 'renderer', 'app.js'), 'utf8');

    // 1. Production screen protection must require !app.isPackaged for dev screenshot flags
    assert.ok(
      /allowDevScreenshots\s*=\s*!app\.isPackaged\s*&&/.test(mainJs),
      'main.js allowDevScreenshots bayrağı mutlaka !app.isPackaged koşuluna bağlı olmalıdır'
    );

    // 2. install-update must use fs.lstatSync and reject symlinks
    const instStart = mainJs.indexOf("ipcMain.handle('install-update'");
    const instSlice = mainJs.slice(instStart, mainJs.indexOf('return true;', instStart));
    assert.ok(
      instSlice.includes('fs.lstatSync(resolvedPath)') && instSlice.includes('stat.isSymbolicLink()'),
      'install-update fs.lstatSync ile symlink reddi uygulamalıdır'
    );

    // 3. decryptBackupPacket must require isUnlocked and resist prototype lookup ("__proto__" / "constructor")
    const decStart = mainJs.indexOf('async function decryptBackupPacket(');
    const decEnd = mainJs.indexOf("ipcMain.handle('decrypt-backup'", decStart);
    assert.ok(decStart !== -1 && decEnd > decStart, 'decryptBackupPacket bloğu bulunmalıdır');
    const decSlice = mainJs.slice(decStart, decEnd);
    assert.ok(decSlice.includes('if (!isUnlocked)'), 'decryptBackupPacket kasa kilitliyken reddetmelidir');

    const seenKdfOpts = [];
    let mockUnlocked = false;
    const mockArgon2 = {
      argon2id: 2,
      hash: async (_pw, opts) => {
        seenKdfOpts.push(opts);
        // Trigger AES-GCM failure cleanly after capturing derived KDF parameters
        return Buffer.alloc(32, 0x42);
      }
    };
    const decFn = new Function(
      'crypto', 'argon2', 'getUnlocked', 'secureBuffer', 'unsecureBuffer',
      `${decSlice.replace(/\bisUnlocked\b/g, 'getUnlocked()')}; return decryptBackupPacket;`
    )(crypto, mockArgon2, () => mockUnlocked, () => {}, () => {});

    const sampleB64 = Buffer.alloc(80, 1).toString('base64');
    await assert.rejects(() => decFn(sampleB64, 'pw123', 'argon2id-128m-4t-1p'), /Vault is locked/);

    mockUnlocked = true;
    await assert.rejects(() => decFn(sampleB64, 'pw123', '__proto__'));
    await assert.rejects(() => decFn(sampleB64, 'pw123', 'constructor'));
    await assert.rejects(() => decFn(sampleB64, 'pw123', 'argon2id-64m-3t-1p'));
    assert.strictEqual(seenKdfOpts.length, 3);
    assert.strictEqual(seenKdfOpts[0].memoryCost, 131072, '__proto__ kdfTag güvenli varsayılana düşmelidir');
    assert.strictEqual(seenKdfOpts[0].timeCost, 4);
    assert.strictEqual(seenKdfOpts[1].memoryCost, 131072, 'constructor kdfTag güvenli varsayılana düşmelidir');
    assert.strictEqual(seenKdfOpts[2].memoryCost, 65536, 'argon2id-64m-3t-1p profili tanınmalıdır');

    // 4. Extension domainMatches must strictly exclude credit cards and secure notes
    const domStart = appJs.indexOf('function normalizeDomain(str) {');
    const domEnd = appJs.indexOf('let pendingExtReveal = null;', domStart);
    assert.ok(domStart !== -1 && domEnd > domStart, 'domainMatches bloğu bulunmalıdır');
    const domainMatches = new Function(`${appJs.slice(domStart, domEnd)}; return domainMatches;`)();
    assert.strictEqual(domainMatches({ type: 'card', site: 'garanti.com.tr', url: 'https://garanti.com.tr' }, 'garanti.com.tr'), false);
    assert.strictEqual(domainMatches({ type: 'note', site: 'wise.com', url: 'https://wise.com' }, 'wise.com'), false);
    assert.strictEqual(domainMatches({ type: 'login', site: 'github.com', url: 'https://github.com' }, 'github.com'), true);
    assert.strictEqual(domainMatches({ site: 'github.com', url: 'https://github.com' }, 'github.com'), true);

    // 5. Unlock guards on import/export & .fuin backup schema normalization
    for (const fnName of ['exportJSON', 'exportCSV', 'importJSON', 'importCSV']) {
      const fnIdx = appJs.indexOf(`async function ${fnName}()`);
      assert.ok(fnIdx !== -1 && appJs.slice(fnIdx, fnIdx + 120).includes('if (!master)'), `${fnName} !master korumasına sahip olmalıdır`);
    }
    const encBackupIdx = appJs.indexOf('async function importEncryptedBackup()');
    assert.ok(appJs.slice(encBackupIdx, encBackupIdx + 1800).includes('importers.importJSON(parsed)'), '.fuin içe aktarım FuinImporters.importJSON ile normalize edilmelidir');

    // 6. Importer ID-collision prevention across existing & batch entries
    const FuinImporters = require('./services/importers');
    const collidingJson = JSON.stringify({
      type: 'fuin/vault',
      entries: [
        { id: 'shared-uuid-123456', type: 'login', site: 'example.com', username: 'a', password: 'new-password' },
        { id: 'shared-uuid-123456', type: 'login', site: 'other.com', username: 'b', password: 'pw2' }
      ]
    });
    const impRes = FuinImporters.importJSON(collidingJson, {
      existingEntries: [{ id: 'shared-uuid-123456', type: 'login', site: 'example.com', username: 'a', password: 'old-password' }]
    });
    assert.strictEqual(impRes.entries.length, 2);
    assert.notStrictEqual(impRes.entries[0].id, 'shared-uuid-123456', 'Mevcut kayıt ID çakışması yeniden anahtarlanmalıdır');
    assert.notStrictEqual(impRes.entries[1].id, impRes.entries[0].id, 'Aynı içe aktarım içindeki ID çakışmaları benzersiz kalmalıdır');

    passes++;
    console.log('✅ PASS: 14. Ekran koruması, decrypt-backup KDF/kilit koruması, domainMatches tür yalıtımı ve ID çakışma sertleştirmesi doğrulandı');
  } catch (err) {
    failures++;
    console.error('❌ FAIL: 14. Güvenlik sertleştirme doğrulaması başarısız');
    console.error('   Reason:', err.stack || err.message);
  }

  console.log('═'.repeat(75));
  console.log(`SUMMARY: ${passes} passed, ${failures} failed.`);
  console.log('═'.repeat(75));

  if (failures > 0) process.exit(1);
})();
