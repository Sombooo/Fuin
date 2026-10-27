'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST SUITE: test_sync_lan_merge.js
 *
 * Verifies Acceptance Criteria (R3):
 *   1. Çift yönlü ekleme (Two-way addition between Desktop and Mobile)
 *   2. Çift yönlü güncelleme (Two-way update resolution by updatedAt)
 *   3. Silme & Tombstone (deletedAt propagation and resolution)
 *   4. Çakışma durumunda veri kaybı olmadığını kanıtlama:
 *      - En güncel sürüm ana kayıt yapılır
 *      - Diğer sürüm kaydın geçmişine (history) eklenir
 *      - Hiçbir kullanıcı verisi sessizce ezilmez
 *   5. Tarihçe birleştirme ve tekilleştirme (History merge & deduplication)
 *   6. Deterministik beraberlik çözümü (Tie-breaker determinism)
 *   7. Çift yönlü tam eşitlenme ve idempotentlik
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const syncLan = require('./sync-lan.js');

console.log('═'.repeat(75));
console.log('FUIN TEST: TWO-WAY CONFLICT-FREE DETERMINISTIC MERGE (R3)');
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

// ── TEST 1: TWO-WAY ADDITION ──────────────────────────────────────────────────
test('A. Çift yönlü ekleme: Masaüstündeki ve mobildeki yeni kayıtlar karşılıklı eklenir', () => {
  const desktopEntries = [
    { id: 'entry-1', site: 'github.com', username: 'alice', password: 'pw1', updatedAt: 1000 }
  ];
  const mobileEntries = [
    { id: 'entry-2', site: 'google.com', username: 'alice', password: 'pw2', updatedAt: 2000 }
  ];

  const { mergedEntries, stats } = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);

  assert.strictEqual(mergedEntries.length, 2, 'Toplam 2 kayıt olmalı');
  assert.strictEqual(stats.addedFromRemote, 1, '1 kayıt mobilden eklenmeli');
  assert.strictEqual(stats.addedFromLocal, 1, '1 kayıt masaüstünden korunmalı');

  const ids = mergedEntries.map(e => e.id);
  assert.ok(ids.includes('entry-1'));
  assert.ok(ids.includes('entry-2'));
});

test('B. Boş kasa ile ekleme durumları', () => {
  const desktopEntries = [
    { id: 'entry-1', site: 'github.com', username: 'alice', password: 'pw1', updatedAt: 1000 }
  ];

  // Mobil boş ise masaüstü aynen korunur
  const res1 = syncLan.mergeVaultEntries(desktopEntries, []);
  assert.strictEqual(res1.mergedEntries.length, 1);
  assert.strictEqual(res1.mergedEntries[0].id, 'entry-1');

  // Masaüstü boş ise mobil aynen eklenir
  const res2 = syncLan.mergeVaultEntries([], desktopEntries);
  assert.strictEqual(res2.mergedEntries.length, 1);
  assert.strictEqual(res2.mergedEntries[0].id, 'entry-1');

  // İkisi de boş ise boş döner
  const res3 = syncLan.mergeVaultEntries([], []);
  assert.strictEqual(res3.mergedEntries.length, 0);
});

// ── TEST 2: TWO-WAY UPDATE ────────────────────────────────────────────────────
test('C. Çift yönlü güncelleme: Daha güncel olan sürüm ana kayıt yapılır', () => {
  // Masaüstünde eski, mobilde yeni güncelleme
  const desktopEntries = [
    { id: 'rec-1', site: 'proton.me', username: 'bob', password: 'old_pw_1', updatedAt: 1000 }
  ];
  const mobileEntries = [
    { id: 'rec-1', site: 'proton.me', username: 'bob', password: 'new_pw_1_from_mobile', updatedAt: 2000 }
  ];

  const res1 = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res1.mergedEntries.length, 1);
  assert.strictEqual(res1.mergedEntries[0].password, 'new_pw_1_from_mobile', 'Daha yeni olan mobil sürüm kazanmalı');
  assert.strictEqual(res1.mergedEntries[0].updatedAt, 2000);

  // Mobilde eski, masaüstünde yeni güncelleme
  const desktopEntries2 = [
    { id: 'rec-2', site: 'amazon.com', username: 'bob', password: 'new_pw_2_from_desktop', updatedAt: 3000 }
  ];
  const mobileEntries2 = [
    { id: 'rec-2', site: 'amazon.com', username: 'bob', password: 'old_pw_2', updatedAt: 2500 }
  ];

  const res2 = syncLan.mergeVaultEntries(desktopEntries2, mobileEntries2);
  assert.strictEqual(res2.mergedEntries.length, 1);
  assert.strictEqual(res2.mergedEntries[0].password, 'new_pw_2_from_desktop', 'Daha yeni olan masaüstü sürüm kazanmalı');
  assert.strictEqual(res2.mergedEntries[0].updatedAt, 3000);
});

// ── TEST 3: DELETION & TOMBSTONES ─────────────────────────────────────────────
test('D. Silme ve Tombstone (deletedAt): Silinen kayıt karşılıklı silinir', () => {
  const desktopEntries = [
    { id: 'rec-del', site: 'netflix.com', username: 'charlie', password: 'pw', updatedAt: 1000 }
  ];
  // Mobilde silinmiş (tombstone: deletedAt = 1500)
  const mobileEntries = [
    { id: 'rec-del', site: 'netflix.com', username: 'charlie', password: 'pw', updatedAt: 1500, deletedAt: 1500, isDeleted: true }
  ];

  const res = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res.mergedEntries.length, 1);
  assert.strictEqual(res.mergedEntries[0].isDeleted, true, 'Silinmiş bayrağı korunmalı');
  assert.strictEqual(res.mergedEntries[0].deletedAt, 1500, 'deletedAt tombstone timestamp korunmalı');
});

test('E. Silinmiş kaydın sonradan başka cihazda düzenlenmesi durumu (Revival by later edit)', () => {
  // Masaüstünde t=1000'de silindi
  const desktopEntries = [
    { id: 'rec-revive', site: 'apple.com', username: 'dan', password: 'pw', updatedAt: 1000, deletedAt: 1000, isDeleted: true }
  ];
  // Mobilde t=2000'de yeni şifreyle güncellendi
  const mobileEntries = [
    { id: 'rec-revive', site: 'apple.com', username: 'dan', password: 'newer_pw_updated', updatedAt: 2000, deletedAt: null, isDeleted: false }
  ];

  const res = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res.mergedEntries.length, 1);
  assert.strictEqual(res.mergedEntries[0].isDeleted, false, 'Silinme sonrasındaki güncelleme kaydı canlandırmalı');
  assert.strictEqual(res.mergedEntries[0].password, 'newer_pw_updated');
  assert.strictEqual(res.mergedEntries[0].deletedAt, null);

  // Silinmiş sürüm geçmişte (history) korunmalı
  assert.ok(res.mergedEntries[0].history && res.mergedEntries[0].history.length > 0);
  assert.strictEqual(res.mergedEntries[0].history[0].isDeleted, true);
});

// ── TEST 4: CONFLICT PRESERVATION WITHOUT DATA LOSS ───────────────────────────
test('F. Çakışma durumunda veri kaybı olmadığını kanıtlama (R3 - Non-Destructive History)', () => {
  // İki cihazda aynı kayıt eşzamanlı farklı parolalar ve notlarla değiştirildi
  const desktopEntry = {
    id: 'conflict-entry-1',
    site: 'bank.com',
    username: 'user@bank.com',
    password: 'desktop_edited_super_secret_password_123',
    note: 'Created on Desktop with crucial security token XYZ',
    updatedAt: 5000
  };

  const mobileEntry = {
    id: 'conflict-entry-1',
    site: 'bank.com',
    username: 'user@bank.com',
    password: 'mobile_edited_another_secret_password_456',
    note: 'Edited on Phone on the go with phone token ABC',
    updatedAt: 4000
  };

  const { mergedEntries, stats } = syncLan.mergeVaultEntries([desktopEntry], [mobileEntry]);

  assert.strictEqual(mergedEntries.length, 1, 'Tek bir ana kayıt olmalı');
  assert.strictEqual(stats.conflictsResolved, 1, '1 çakışma çözüldü olarak sayılmalı');

  const mainRecord = mergedEntries[0];
  // 1. Kazanan sürüm: Daha güncel olan masaüstü sürümü (t=5000)
  assert.strictEqual(mainRecord.password, 'desktop_edited_super_secret_password_123');
  assert.strictEqual(mainRecord.note, 'Created on Desktop with crucial security token XYZ');
  assert.strictEqual(mainRecord.updatedAt, 5000);

  // 2. Kaybeden sürüm: Mobildeki sürüm ASLA SİLİNMEDİ, kaydın geçmişine (history) eklendi!
  assert.ok(Array.isArray(mainRecord.history), 'Ana kayıt history dizisine sahip olmalı');
  assert.strictEqual(mainRecord.history.length, 1, 'Geçmişte tam 1 eski sürüm bulunmalı');

  const archivedVersion = mainRecord.history[0];
  assert.strictEqual(archivedVersion.password, 'mobile_edited_another_secret_password_456', 'Mobildeki parola geçmişte eksiksiz korunmalı');
  assert.strictEqual(archivedVersion.note, 'Edited on Phone on the go with phone token ABC', 'Mobildeki not geçmişte eksiksiz korunmalı');
  assert.strictEqual(archivedVersion.updatedAt, 4000);
  assert.ok(archivedVersion.archivedAt > 0, 'Arşivlenme zamanı kaydedilmeli');
});

test('G. Ters yönlü çakışma (Mobildeki daha yeni ise masaüstü verisi geçmişte korunur)', () => {
  const desktopEntry = {
    id: 'conflict-entry-2',
    site: 'crypto.com',
    username: 'trader',
    password: 'desktop_old_key_999',
    note: 'Desktop seed phrase backup',
    updatedAt: 10000
  };

  const mobileEntry = {
    id: 'conflict-entry-2',
    site: 'crypto.com',
    username: 'trader',
    password: 'mobile_new_key_888',
    note: 'Mobile updated seed phrase',
    updatedAt: 15000
  };

  const { mergedEntries } = syncLan.mergeVaultEntries([desktopEntry], [mobileEntry]);
  const mainRecord = mergedEntries[0];

  assert.strictEqual(mainRecord.password, 'mobile_new_key_888', 'Mobil sürüm ana kayıt olmalı');
  assert.strictEqual(mainRecord.history.length, 1);
  assert.strictEqual(mainRecord.history[0].password, 'desktop_old_key_999', 'Masaüstü parolası geçmişte korunmalı');
  assert.strictEqual(mainRecord.history[0].note, 'Desktop seed phrase backup', 'Masaüstü notu geçmişte korunmalı');
});

// ── TEST 5: HISTORY MERGE & DEDUPLICATION ─────────────────────────────────────
test('H. Her iki tarafta da önceden mevcut olan geçmişlerin birleştirilmesi ve tekilleştirilmesi', () => {
  const desktopEntry = {
    id: 'rec-hist',
    site: 'vault.me',
    username: 'user',
    password: 'pw_v3',
    updatedAt: 3000,
    history: [
      { site: 'vault.me', username: 'user', password: 'pw_v1', updatedAt: 1000 }
    ]
  };

  const mobileEntry = {
    id: 'rec-hist',
    site: 'vault.me',
    username: 'user',
    password: 'pw_v2',
    updatedAt: 2000,
    history: [
      { site: 'vault.me', username: 'user', password: 'pw_v1', updatedAt: 1000 } // Aynı eski sürüm
    ]
  };

  const { mergedEntries } = syncLan.mergeVaultEntries([desktopEntry], [mobileEntry]);
  const mainRecord = mergedEntries[0];

  assert.strictEqual(mainRecord.password, 'pw_v3');
  // History pw_v2 ve tekilleştirilmiş pw_v1 içermelidir (toplam 2)
  assert.strictEqual(mainRecord.history.length, 2);
  const passwordsInHistory = mainRecord.history.map(h => h.password);
  assert.ok(passwordsInHistory.includes('pw_v2'));
  assert.ok(passwordsInHistory.includes('pw_v1'));
});

// ── TEST 6: DETERMINISTIC TIE-BREAKER ─────────────────────────────────────────
test('I. Birebir aynı milisaniyedeki düzenlemelerde deterministik beraberlik kararı', () => {
  const desktopEntry = {
    id: 'rec-tie',
    site: 'tie.com',
    username: 'user',
    password: 'alpha_desktop',
    updatedAt: 5555
  };

  const mobileEntry = {
    id: 'rec-tie',
    site: 'tie.com',
    username: 'user',
    password: 'beta_mobile',
    updatedAt: 5555
  };

  // İki yönden de çağrıldığında deterministik aynı sonucu vermeli
  const res1 = syncLan.mergeVaultEntries([desktopEntry], [mobileEntry]);
  const res2 = syncLan.mergeVaultEntries([mobileEntry], [desktopEntry]);

  assert.strictEqual(res1.mergedEntries[0].password, res2.mergedEntries[0].password);
  assert.strictEqual(res1.mergedEntries[0].history.length, 1);
  assert.strictEqual(res2.mergedEntries[0].history.length, 1);
});

// ── TEST 7: IDEMPOTENCY & FULL TWO-WAY ROUNDTRIP ──────────────────────────────
test('J. Birleştirme işleminin idempotentliği: Tekrar birleştirme veriyi değiştirmez', () => {
  const desktopEntries = [
    { id: '1', site: 'siteA.com', username: 'u1', password: 'p1', updatedAt: 100 },
    { id: '2', site: 'siteB.com', username: 'u2', password: 'p2', updatedAt: 200 }
  ];
  const mobileEntries = [
    { id: '2', site: 'siteB.com', username: 'u2', password: 'p2_mod', updatedAt: 300 },
    { id: '3', site: 'siteC.com', username: 'u3', password: 'p3', updatedAt: 400 }
  ];

  // 1. Birleştirme
  const run1 = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);

  // 2. İki cihaz da bu merged veriyi alır ve tekrar birbirleriyle eşitlerse
  const run2 = syncLan.mergeVaultEntries(run1.mergedEntries, run1.mergedEntries);

  assert.strictEqual(run2.mergedEntries.length, run1.mergedEntries.length);
  assert.deepStrictEqual(run2.mergedEntries, run1.mergedEntries, 'Tekrar birleştirme tam özdeş kalmalı');
});

// ── TEST 8: ISO STRING TIMESTAMPS & DATE PARSING ──────────────────────────────
test('K. ISO 8601 tarih stringleri ve string timestamp desteği', () => {
  const olderDateIso = '2026-09-01T12:00:00.000Z';
  const newerDateIso = '2026-10-01T12:00:00.000Z';

  const desktopEntries = [
    { id: 'iso-1', site: 'iso.com', username: 'user', password: 'old_iso_pw', updatedAt: olderDateIso }
  ];
  const mobileEntries = [
    { id: 'iso-1', site: 'iso.com', username: 'user', password: 'new_iso_pw', updatedAt: newerDateIso }
  ];

  const res = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res.mergedEntries.length, 1);
  assert.strictEqual(res.mergedEntries[0].password, 'new_iso_pw', 'Daha yeni ISO tarihli sürüm kazanmalı');
  assert.strictEqual(typeof res.mergedEntries[0].updatedAt, 'number', 'updatedAt parse edilerek unix ms number olmalı');
  assert.strictEqual(res.mergedEntries[0].updatedAt, Date.parse(newerDateIso));
  assert.strictEqual(res.mergedEntries[0].history[0].password, 'old_iso_pw');
});

// ── TEST 9: TOMBSTONE PRECEDENCE (deletedAt > updatedAt) ─────────────────────
test('L. Silinme zamanı (deletedAt) düzenleme zamanından yeniyse silinme kazanmalı', () => {
  // Masaüstünde t=1000'de düzenlenmişti, t=1500'de silindi (ancak updatedAt güncellenmemişti)
  const desktopEntries = [
    { id: 'tomb-1', site: 'tomb.com', username: 'u', password: 'pw', updatedAt: 1000, deletedAt: 1500, isDeleted: true }
  ];
  // Mobilde t=1200'de düzenlenmişti (silinmeden ÖNCE)
  const mobileEntries = [
    { id: 'tomb-1', site: 'tomb.com', username: 'u', password: 'pw_mobile_1200', updatedAt: 1200, deletedAt: null, isDeleted: false }
  ];

  const res = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res.mergedEntries.length, 1);
  assert.strictEqual(res.mergedEntries[0].isDeleted, true, 't=1500 silinmesi t=1200 düzenlemesini yenmeli');
  assert.strictEqual(res.mergedEntries[0].deletedAt, 1500);
});

// ── TEST 10: OPTIONAL FIELD NORMALIZATION (undefined vs empty string) ────────
test('M. Tanımsız ve boş metin alanları (undefined vs "") sahte çakışma üretmez', () => {
  const desktopEntries = [
    { id: 'norm-1', site: 'norm.com', username: 'u', password: 'pw', note: undefined, url: '', totp: undefined, updatedAt: 1000 }
  ];
  const mobileEntries = [
    { id: 'norm-1', site: 'norm.com', username: 'u', password: 'pw', note: '', url: undefined, totp: '', updatedAt: 1000 }
  ];

  const res = syncLan.mergeVaultEntries(desktopEntries, mobileEntries);
  assert.strictEqual(res.mergedEntries.length, 1);
  assert.strictEqual(res.stats.conflictsResolved, 0, 'Sahte çakışma olmamalı');
  assert.strictEqual(res.stats.identicalMatches, 1, 'Birebir eşleşme sayılmalı');
  assert.strictEqual(res.mergedEntries[0].history.length, 0, 'Gereksiz tarihçe snapshot üretilmemeli');
});

// ── TEST 11: CANONICAL TIE-BREAKER WITH SHUFFLED PROPERTY ORDER ───────────────
test('N. Nesne anahtar sırası farklı olsa dahi deterministik beraberlik kararı', () => {
  // desktopEntry ve mobileEntry alan sıralaması farklı nesneler
  const desktopEntry = {
    url: 'https://test.com',
    password: 'pw_tie_alpha',
    site: 'tie2.com',
    id: 'tie-shuffle',
    username: 'u',
    updatedAt: 9999
  };
  const mobileEntry = {
    id: 'tie-shuffle',
    site: 'tie2.com',
    username: 'u',
    password: 'pw_tie_beta',
    url: 'https://test.com',
    updatedAt: 9999
  };

  const res1 = syncLan.mergeVaultEntries([desktopEntry], [mobileEntry]);
  const res2 = syncLan.mergeVaultEntries([mobileEntry], [desktopEntry]);

  assert.strictEqual(res1.mergedEntries[0].password, res2.mergedEntries[0].password, 'Anahtar sırasına bakılmaksızın aynı taraf kazanmalı');
});

// ── TEST 12: DELETEDAT NULL VS UNDEFINED FALSE-CONFLICT PREVENTION ────────────
test('O. deletedAt null ile undefined karşılaştırması sahte çakışma üretmez', () => {
  const desktop = [
    { id: 't-del-match', site: 'test.com', username: 'u', password: 'p', deletedAt: null, updatedAt: 100 }
  ];
  const mobile = [
    { id: 't-del-match', site: 'test.com', username: 'u', password: 'p', updatedAt: 100 } // deletedAt is undefined
  ];

  const res = syncLan.mergeVaultEntries(desktop, mobile);
  assert.strictEqual(res.stats.conflictsResolved, 0, 'deletedAt: null vs undefined çakışma sayılmamalı');
  assert.strictEqual(res.stats.identicalMatches, 1);
  assert.strictEqual(res.mergedEntries[0].history.length, 0);
});

// ── TEST 13: AUTOMATIC ID GENERATION FOR ENTRIES LACKING ID ───────────────────
test('P. ID değeri bulunmayan kayıtlar otomatik UUID atanarak korunur, asla düşürülmez', () => {
  const desktop = [
    { site: 'no-id-desktop.com', username: 'alice', password: 'pw1', updatedAt: 100 }
  ];
  const mobile = [
    { site: 'no-id-mobile.com', username: 'bob', password: 'pw2', updatedAt: 200 }
  ];

  const res = syncLan.mergeVaultEntries(desktop, mobile);
  assert.strictEqual(res.mergedEntries.length, 2, 'İki kayıt da birleştirmede korunmalı');
  assert.ok(typeof res.mergedEntries[0].id === 'string' && res.mergedEntries[0].id.length > 0);
  assert.ok(typeof res.mergedEntries[1].id === 'string' && res.mergedEntries[1].id.length > 0);
  assert.notStrictEqual(res.mergedEntries[0].id, res.mergedEntries[1].id);
});

// ── TEST 14: CLEAN HISTORY STRIPPING (PREVENT RECURSIVE HISTORY BLOAT) ────────
test('Q. İç içe geçmiş (nested) history nesneleri snapshot alırken temizlenir', () => {
  const desktop = [
    {
      id: 'nest-1',
      site: 'nested.com',
      username: 'u',
      password: 'v2',
      updatedAt: 200,
      history: [
        {
          site: 'nested.com',
          username: 'u',
          password: 'v1',
          updatedAt: 100,
          history: [{ site: 'nested.com', password: 'v0', updatedAt: 50 }] // iç içe kirli history
        }
      ]
    }
  ];
  const mobile = [
    { id: 'nest-1', site: 'nested.com', username: 'u', password: 'v3', updatedAt: 300 }
  ];

  const res = syncLan.mergeVaultEntries(desktop, mobile);
  const main = res.mergedEntries[0];
  assert.strictEqual(main.password, 'v3');
  for (const h of main.history) {
    assert.strictEqual(h.history, undefined, 'Snapshot içinde alt history dizisi barındırılmamalı');
  }
});

// ── TEST 15: HISTORY PRESERVATION FOR NOTE AND TOTP DIFFERENCES ──────────────
test('R. note ve totp alanlarındaki değişiklikler tarihçede eksiksiz korunur', () => {
  const desktop = [
    {
      id: 'note-totp-1',
      site: 'service.com',
      username: 'u',
      password: 'same_password',
      note: 'Note version 2',
      totp: 'TOTP_V2',
      updatedAt: 200,
      history: [
        {
          site: 'service.com',
          username: 'u',
          password: 'same_password',
          note: 'Note version 1',
          totp: 'TOTP_V1',
          updatedAt: 100
        }
      ]
    }
  ];
  const mobile = [
    {
      id: 'note-totp-1',
      site: 'service.com',
      username: 'u',
      password: 'same_password',
      note: 'Note version 3',
      totp: 'TOTP_V3',
      updatedAt: 300
    }
  ];

  const res = syncLan.mergeVaultEntries(desktop, mobile);
  const main = res.mergedEntries[0];
  assert.strictEqual(main.note, 'Note version 3');
  assert.strictEqual(main.totp, 'TOTP_V3');
  assert.strictEqual(main.history.length, 2, 'Note/TOTP farkları olan iki eski sürüm de korunmalı');
  const notes = main.history.map(h => h.note);
  assert.ok(notes.includes('Note version 2'));
  assert.ok(notes.includes('Note version 1'));
});

console.log('═'.repeat(75));
console.log(`SONUÇ: ${passes} BAŞARILI, ${failures} BAŞARISIZ`);
console.log('═'.repeat(75));

if (failures > 0) {
  process.exit(1);
}
