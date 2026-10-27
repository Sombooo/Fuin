'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN ADVERSARIAL STRESS TEST SUITE: test_importers_adversarial.js
 *
 * Empirical Challenger M1-2:
 * 1. Fuzz CSV tokenizer with multiline nested quotes, unclosed quotes at EOF,
 *    empty/whitespace/single-char inputs, non-ASCII Unicode (emojis, Turkish, Cyrillic, CJK),
 *    mixed CRLF/LF/CR newlines, leading UTF-8 BOM.
 * 2. Test format detection resilience: rearranged columns, ambiguous headers,
 *    Bitwarden encrypted exports, corrupted JSON inputs.
 * 3. Test schema normalization: required fields, backward compatibility,
 *    password whitespace, duplicate entries, empty rows, crash immunity.
 * 4. Stress fuzzing: 500 randomized mutated inputs.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');
const FuinImporters = require('./services/importers');
const csv = require('./services/importers/csvImporter');
const json = require('./services/importers/jsonImporter');
const detector = require('./services/importers/detector');

console.log('═'.repeat(75));
console.log('FUIN EMPIRICAL CHALLENGER: ADVERSARIAL FUZZING & STRESS TEST');
console.log('═'.repeat(75));

let passes = 0;
let failures = 0;
const findings = [];

function test(desc, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✕ [FAIL] ${desc}`);
    console.error(`         ${err.message}`);
    failures++;
    findings.push({ test: desc, error: err.message, stack: err.stack });
  }
}

const UUID_V4_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// ── GROUP 1: CSV TOKENIZER ADVERSARIAL FUZZING ───────────────────────────────

console.log('\n--- Group 1: CSV Tokenizer Adversarial Fuzzing ---');

test('1.1.1 Multiline cells with nested quotes ("line 1\\n""line 2""\\nline 3")', () => {
  const input = 'site,username,password,notes\r\n' +
                'github.com,alice,secret123,"line 1\n""line 2""\nline 3"';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 2, 'Must produce 2 rows');
  assert.strictEqual(rows[1][3], 'line 1\n"line 2"\nline 3', 'Nested quotes and newlines must match');

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].notes, 'line 1\n"line 2"\nline 3');
});

test('1.1.2 Deeply nested escaped quotes and alternating quotes', () => {
  const input = 'site,username,password,notes\r\n' +
                'test.com,user,pass,"""""double"""" and """"triple"""" and ""single"""';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1][3], '""double"" and ""triple"" and "single"');
});

test('1.1.3 Multiline cells with CRLF newlines inside quotes', () => {
  const input = 'site,username,password,notes\r\n' +
                'test.com,user,pass,"row1\r\n""row2""\r\nrow3"';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1][3], 'row1\r\n"row2"\r\nrow3');
});

test('1.2.1 Unclosed quotes at EOF on last column (password)', () => {
  const input = 'site,username,password\r\ngithub.com,alice,"unclosedSecret';
  const rows = csv.parseCSV(input);
  assert.ok(rows.length >= 2, 'Must not crash or throw');
  assert.strictEqual(rows[1][0], 'github.com');
  assert.strictEqual(rows[1][1], 'alice');
  assert.strictEqual(rows[1][2], 'unclosedSecret');

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].password, 'unclosedSecret');
});

test('1.2.2 Unclosed quotes at EOF on first column (site)', () => {
  const input = 'site,username,password\r\n"unclosedSite,alice,secret';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 2);
  // Entire rest of line was consumed as field 0 due to unclosed quote
  assert.strictEqual(rows[1].length, 1);
  // Missing password, so importEntries should skip without crash
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 0);
});

test('1.2.3 Unclosed quote on header row does not crash or throw', () => {
  const input = '"site,username,password\r\ngithub.com,alice,secret123';
  const rows = csv.parseCSV(input);
  assert.ok(Array.isArray(rows));
  const res = FuinImporters.importFromText(input);
  assert.strictEqual(res.count, 0);
});

test('1.2.4 Standalone single unclosed quote character', () => {
  const rows = csv.parseCSV('"');
  assert.deepStrictEqual(rows, []);
  const res = FuinImporters.importFromText('"');
  assert.strictEqual(res.count, 0);
});

test('1.3.1 Empty input and whitespace-only inputs', () => {
  const whitespaceCases = ['', ' ', '   ', '\t', '\t\t', '\r\n', '\n', '\r', '  \r\n  \t  \n  '];
  for (const s of whitespaceCases) {
    const rows = csv.parseCSV(s);
    assert.deepStrictEqual(rows, [], `Expected empty rows for input: ${JSON.stringify(s)}`);
    const res = FuinImporters.importFromText(s);
    assert.strictEqual(res.count, 0);
    assert.strictEqual(res.format, 'unknown');
  }
});

test('1.3.2 Single-character inputs', () => {
  const singleChars = ['a', ',', '"', '\n', '\r', '\uFEFF', '0', ';', ' '];
  for (const ch of singleChars) {
    const rows = csv.parseCSV(ch);
    assert.ok(Array.isArray(rows), `parseCSV must return array for ${JSON.stringify(ch)}`);
    const res = FuinImporters.importFromText(ch);
    assert.strictEqual(res.count, 0, `importFromText count must be 0 for ${JSON.stringify(ch)}`);
  }
});

test('1.4.1 Non-ASCII Unicode: Turkish characters in all fields', () => {
  const input = 'site,username,password,notes,category\r\n' +
                'Kasa Girişi 🇹🇷,kullanıcı_ğüşöç,P@ss_ıİçÖşĞ!,çağlayan & şafak,Özel Güvenlik';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1][0], 'Kasa Girişi 🇹🇷');
  assert.strictEqual(rows[1][1], 'kullanıcı_ğüşöç');
  assert.strictEqual(rows[1][2], 'P@ss_ıİçÖşĞ!');
  assert.strictEqual(rows[1][3], 'çağlayan & şafak');
  assert.strictEqual(rows[1][4], 'Özel Güvenlik');

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'Kasa Girişi 🇹🇷');
  assert.strictEqual(entries[0].username, 'kullanıcı_ğüşöç');
  assert.strictEqual(entries[0].password, 'P@ss_ıİçÖşĞ!');
  assert.strictEqual(entries[0].notes, 'çağlayan & şafak');
  assert.strictEqual(entries[0].category, 'Özel Güvenlik');
});

test('1.4.2 Non-ASCII Unicode: Emojis, Cyrillic, CJK, and RTL Arabic', () => {
  const input = 'site,username,password,notes\r\n' +
                '"Сбербанк 🇷🇺",пользователь,пароль_123,Русские заметки\r\n' +
                '"みずほ銀行 🇯🇵",ユーザー名,パスワード99,日本語のメモ\r\n' +
                '"微信 🇨🇳",微信用户,密碼888,中文注释\r\n' +
                '"بنك الرياض 🇸🇦",مستخدم,كلمةالمرور,ملاحظات\r\n' +
                '"Emoji Vault 🔑🛡️👨‍👩‍👧‍👦",admin,p@ss!🔑,Family vault';
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 6);

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 5);
  assert.strictEqual(entries[0].title, 'Сбербанк 🇷🇺');
  assert.strictEqual(entries[1].title, 'みずほ銀行 🇯🇵');
  assert.strictEqual(entries[2].title, '微信 🇨🇳');
  assert.strictEqual(entries[3].title, 'بنك الرياض 🇸🇦');
  assert.strictEqual(entries[4].title, 'Emoji Vault 🔑🛡️👨‍👩‍👧‍👦');
  assert.strictEqual(entries[4].password, 'p@ss!🔑');
});

test('1.5.1 Mixed CRLF, LF, and CR newlines within same document', () => {
  const input = 'site,username,password\r\n' + // CRLF
                'site1.com,user1,pass1\r' +    // CR (Mac classic)
                'site2.com,user2,pass2\n' +    // LF (Unix)
                'site3.com,user3,pass3\r\n';   // CRLF
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows.length, 4);
  assert.deepStrictEqual(rows[1], ['site1.com', 'user1', 'pass1']);
  assert.deepStrictEqual(rows[2], ['site2.com', 'user2', 'pass2']);
  assert.deepStrictEqual(rows[3], ['site3.com', 'user3', 'pass3']);

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 3);
});

test('1.6.1 Leading UTF-8 Byte Order Mark (\\uFEFF) stripped correctly', () => {
  const input = '\uFEFFsite,username,password\r\ngithub.com,alice,secret123';
  assert.strictEqual(input.charCodeAt(0), 0xFEFF);
  const rows = csv.parseCSV(input);
  assert.strictEqual(rows[0][0], 'site', 'Header must not contain BOM character');

  const res = FuinImporters.importFromText(input);
  assert.strictEqual(res.format, 'fuin');
  assert.strictEqual(res.entries[0].title, 'github.com');
});

test('1.6.2 BOM with only whitespace or empty content', () => {
  assert.deepStrictEqual(csv.parseCSV('\uFEFF'), []);
  assert.deepStrictEqual(csv.parseCSV('\uFEFF   \r\n\t'), []);
  const res = FuinImporters.importFromText('\uFEFF');
  assert.strictEqual(res.count, 0);
});

// ── GROUP 2: FORMAT DETECTION RESILIENCE ─────────────────────────────────────

console.log('\n--- Group 2: Format Detection Resilience ---');

test('2.1.1 Rearranged Bitwarden CSV columns', () => {
  const headers = 'login_totp,login_password,login_username,login_uri,reprompt,fields,notes,name,type,favorite,folder';
  const row = 'JBSWY3DPEHPK3PXP,bwSecret!,alice,https://github.com,0,,MyNotes,GitHub,1,1,Development';
  const input = `${headers}\r\n${row}`;

  assert.strictEqual(FuinImporters.detectFormat(input), 'bitwarden');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'GitHub');
  assert.strictEqual(entries[0].username, 'alice');
  assert.strictEqual(entries[0].password, 'bwSecret!');
  assert.strictEqual(entries[0].url, 'https://github.com');
  assert.strictEqual(entries[0].totp, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(entries[0].category, 'Development');
  assert.strictEqual(entries[0].fav, true);
});

test('2.1.2 Rearranged LastPass CSV columns', () => {
  const headers = 'fav,grouping,name,extra,totp,password,username,url';
  const row = '1,DevOps,AWS Root,root key,123456,secret!,root,https://aws.amazon.com';
  const input = `${headers}\r\n${row}`;

  assert.strictEqual(FuinImporters.detectFormat(input), 'lastpass');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'AWS Root');
  assert.strictEqual(entries[0].username, 'root');
  assert.strictEqual(entries[0].password, 'secret!');
  assert.strictEqual(entries[0].category, 'DevOps');
  assert.strictEqual(entries[0].fav, true);
});

test('2.1.3 Rearranged Chrome CSV columns', () => {
  const headers = 'note,password,username,url,name';
  const row = 'my note,chromePass123,user@test.com,https://test.com,Test Service';
  const input = `${headers}\r\n${row}`;

  assert.strictEqual(FuinImporters.detectFormat(input), 'chrome');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'Test Service');
  assert.strictEqual(entries[0].password, 'chromePass123');
});

test('2.1.4 Rearranged Fuin CSV columns', () => {
  const headers = 'totp,note,url,password,username,category,site';
  const row = 'OTP456,note text,https://site.org,pass99,fuinuser,Kişisel,Site Org';
  const input = `${headers}\r\n${row}`;

  assert.strictEqual(FuinImporters.detectFormat(input), 'fuin');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'Site Org');
  assert.strictEqual(entries[0].category, 'Kişisel');
});

test('2.2.1 Ambiguous headers: only "name,password"', () => {
  const input = 'name,password\r\nGoogle,mySecret123';
  const det = detector.detectFormatDetails(input);
  assert.strictEqual(det.format, 'fuin');
  assert.strictEqual(det.confidence, 'medium');

  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'Google');
  assert.strictEqual(entries[0].password, 'mySecret123');
});

test('2.2.2 Ambiguous headers: only "title,secret"', () => {
  const input = 'title,secret\r\nGitHub,ghSecret';
  assert.strictEqual(FuinImporters.detectFormat(input), 'fuin');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'GitHub');
  assert.strictEqual(entries[0].password, 'ghSecret');
});

test('2.2.3 Ambiguous headers: only "url,password"', () => {
  const input = 'url,password\r\nhttps://gitlab.com,glSecret';
  assert.strictEqual(FuinImporters.detectFormat(input), 'fuin');
  const entries = FuinImporters.importEntries(input);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'gitlab.com', 'Title must fallback to URL hostname');
  assert.strictEqual(entries[0].password, 'glSecret');
});

test('2.2.4 Header without title or URL: "username,password" returns unknown format', () => {
  const input = 'username,password\r\nalice,secret123';
  assert.strictEqual(FuinImporters.detectFormat(input), 'unknown');
  const res = FuinImporters.importFromText(input);
  assert.strictEqual(res.count, 0);
});

test('2.3.1 Bitwarden encrypted export (encrypted: true) is rejected gracefully in importFromText', () => {
  const enc1 = JSON.stringify({ encrypted: true, items: [] });
  assert.throws(() => {
    FuinImporters.importFromText(enc1);
  }, /şifreli.*desteklenmemektedir/i);

  const enc2 = JSON.stringify({ encrypted: true, folders: [] });
  assert.throws(() => {
    FuinImporters.importFromText(enc2);
  }, /şifreli.*desteklenmemektedir/i);

  const enc3 = JSON.stringify({ encrypted: true, data: "encrypted_blob_data" });
  assert.throws(() => {
    FuinImporters.importFromText(enc3);
  }, /şifreli.*desteklenmemektedir/i);
});

test('2.3.2 Bitwarden encrypted export in importEntries throws gracefully', () => {
  assert.throws(() => {
    FuinImporters.importEntries(JSON.stringify({ encrypted: true, items: [] }));
  }, /şifreli.*desteklenmemektedir/i);
});

test('2.4.1 Corrupted JSON: Syntax errors handled safely without unhandled crashes', () => {
  const corruptPayloads = [
    '{ invalid json syntax }',
    '{"items": [ {"name": "test", "login": } ]}',
    '{"entries": [',
    '}{',
    '{"items": undefined}'
  ];
  for (const payload of corruptPayloads) {
    const res = FuinImporters.importFromText(payload);
    assert.strictEqual(res.format, 'unknown');
    assert.strictEqual(res.count, 0);
  }
});

test('2.4.2 Corrupted JSON: Arrays of primitives and nulls', () => {
  const nonVaultArrays = [
    JSON.stringify([1, 2, 3, 4, 5]),
    JSON.stringify(["a", "b", "c"]),
    JSON.stringify([null, null, null]),
    JSON.stringify([true, false]),
    JSON.stringify([])
  ];
  for (const payload of nonVaultArrays) {
    const res = FuinImporters.importFromText(payload);
    assert.strictEqual(res.count, 0, `Expected 0 entries for ${payload}`);
  }
});

test('2.4.3 Corrupted JSON: Bare primitives', () => {
  const primitives = ['123', 'true', 'false', 'null', '"hello world"'];
  for (const payload of primitives) {
    const res = FuinImporters.importFromText(payload);
    assert.strictEqual(res.count, 0);
  }
});

test('2.4.4 Corrupted JSON: Null items or entries properties', () => {
  const res1 = FuinImporters.importFromText(JSON.stringify({ items: null }));
  assert.strictEqual(res1.count, 0);

  const res2 = FuinImporters.importFromText(JSON.stringify({ entries: null }));
  assert.strictEqual(res2.count, 0);
});

// ── GROUP 3: SCHEMA NORMALIZATION & INTEGRITY ────────────────────────────────

console.log('\n--- Group 3: Schema Normalization & Integrity ---');

test('3.1.1 Full schema completeness on all standard fields', () => {
  const csvText = 'site,username,password,url,notes,totp,category\r\n' +
                  'Example,exUser,exPass,https://example.com,Important note,JBSWY3DPEHPK3PXP,Personal';
  const entries = FuinImporters.importEntries(csvText);
  assert.strictEqual(entries.length, 1);
  const e = entries[0];

  // Required core fields
  assert.strictEqual(typeof e.id, 'string');
  assert.ok(UUID_V4_REGEX.test(e.id), 'id must be valid UUID v4');
  assert.strictEqual(e.title, 'Example');
  assert.strictEqual(e.username, 'exUser');
  assert.strictEqual(e.password, 'exPass');
  assert.strictEqual(e.url, 'https://example.com');
  assert.strictEqual(e.notes, 'Important note');
  assert.strictEqual(e.totp, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(e.category, 'Personal');
  assert.strictEqual(typeof e.fav, 'boolean');
  assert.strictEqual(e.isDeleted, false);
  assert.strictEqual(e.deletedAt, null);
  assert.strictEqual(typeof e.created, 'number');
  assert.strictEqual(typeof e.updated, 'number');

  // Backward compatibility alias invariants
  assert.strictEqual(e.site, e.title, 'e.site must match e.title');
  assert.strictEqual(e.note, e.notes, 'e.note must match e.notes');
  assert.strictEqual(e.createdAt, e.created, 'e.createdAt must match e.created');
  assert.strictEqual(e.updatedAt, e.updated, 'e.updatedAt must match e.updated');
});

test('3.2.1 Password whitespace preservation (internal, leading, trailing)', () => {
  const csvText = 'site,username,password\r\n' +
                  's1,u1,"  leading and trailing  "\r\n' +
                  's2,u2,"with\ttab"\r\n' +
                  's3,u3,"with   multiple   spaces"';
  const entries = FuinImporters.importEntries(csvText);
  assert.strictEqual(entries.length, 3);
  assert.strictEqual(entries[0].password, '  leading and trailing  ');
  assert.strictEqual(entries[1].password, 'with\ttab');
  assert.strictEqual(entries[2].password, 'with   multiple   spaces');
});

test('3.3.1 Duplicate entries within imported document do not crash', () => {
  const csvText = 'site,username,password\r\n' +
                  'dupe.com,user1,pass1\r\n' +
                  'dupe.com,user1,pass1\r\n' +
                  'dupe.com,user1,pass1';
  const res = FuinImporters.importFromText(csvText);
  assert.strictEqual(res.count, 3);
  assert.strictEqual(res.skippedCount, 0);
});

test('3.3.2 Empty rows, commas-only rows, and whitespace rows do not crash', () => {
  const csvText = 'site,username,password\r\n' +
                  'valid1.com,u1,p1\r\n' +
                  '\r\n' +
                  '   \r\n' +
                  ',,\r\n' +
                  '   ,   ,   \r\n' +
                  'valid2.com,u2,p2\r\n' +
                  '\r\n';
  const res = FuinImporters.importFromText(csvText);
  assert.strictEqual(res.count, 2);
  assert.strictEqual(res.skippedCount, 2, '2 invalid rows with empty content skipped');
  assert.strictEqual(res.entries[0].title, 'valid1.com');
  assert.strictEqual(res.entries[1].title, 'valid2.com');
});

test('3.4.1 Null safety in existingEntries: finding reproduction', () => {
  // If existingEntries contains null/undefined, does it crash?
  try {
    FuinImporters.importFromText('site,username,password\r\ngithub.com,alice,pw123', {
      existingEntries: [null, undefined, { site: 'other.com' }]
    });
    // If it reaches here without throwing, null safety is passed
  } catch (err) {
    throw new Error(`CRASH VULNERABILITY: existingEntries containing null throws: ${err.message}`);
  }
});

// ── GROUP 4: RANDOMIZED FUZZING ──────────────────────────────────────────────

console.log('\n--- Group 4: Randomized Stress Fuzzing (500 cases) ---');

test('4.1 500 Pseudo-random corrupted and pathological inputs do not crash engine', () => {
  const seedChars = [
    '"', ',', '\r', '\n', '\uFEFF', ' ', '\t',
    'a', 'Z', '0', '9', 'ç', 'ğ', 'ı', 'ö', 'ş', 'ü', 'İ',
    '🔑', '🛡️', '🇷🇺', '🇨🇳', '🇯🇵', '🇸🇦',
    '{', '}', '[', ']', ':', '\\', '/', '<', '>', '\0'
  ];

  // Deterministic PRNG
  let seed = 1337;
  function rand() {
    seed = (seed * 1664525 + 1013904223) % 4294967296;
    return seed / 4294967296;
  }

  let crashCount = 0;
  for (let i = 0; i < 500; i++) {
    const len = Math.floor(rand() * 100) + 1;
    let s = '';
    for (let j = 0; j < len; j++) {
      s += seedChars[Math.floor(rand() * seedChars.length)];
    }

    try {
      csv.parseCSV(s);
      detector.detectFormat(s);
      FuinImporters.importFromText(s);
    } catch (err) {
      // Bitwarden encrypted JSON rejection is expected and permitted
      if (/şifreli/i.test(err.message)) continue;
      crashCount++;
      console.error(`  Fuzzer crashed on iteration ${i} with payload: ${JSON.stringify(s.slice(0, 30))}... Error: ${err.message}`);
    }
  }

  assert.strictEqual(crashCount, 0, `Engine crashed ${crashCount} times during 500 randomized fuzz runs`);
});

test('4.2 Performance & Scale Stress: 10,000 row CSV parse & import', () => {
  const rows = ['site,username,password,url,notes,totp,category'];
  for (let i = 0; i < 10000; i++) {
    rows.push('"Site_' + i + '","user_' + i + '","pass_' + i + '!","https://site' + i + '.com","Note ' + i + '","OTP' + i + '","Work"');
  }
  const bigCSV = rows.join('\r\n');
  const t0 = Date.now();
  const res = FuinImporters.importFromText(bigCSV);
  const elapsed = Date.now() - t0;
  assert.strictEqual(res.count, 10000);
  assert.strictEqual(res.skippedCount, 0);
  assert.ok(elapsed < 3000, `10,000 rows must import within 3s, took ${elapsed}ms`);
});

test('4.3 Direct jsonImporter.importJSON with encrypted Bitwarden payload', () => {
  // If json.importJSON is called directly with { encrypted: true, data: "..." }
  // Bitwarden encrypted format has encrypted: true.
  try {
    json.importJSON(JSON.stringify({ encrypted: true, data: 'ciphertext_blob' }));
    throw new Error('DIRECT_ENCRYPTED_BYPASS: json.importJSON accepted { encrypted: true } without error');
  } catch (err) {
    if (/şifreli.*desteklenmemektedir/i.test(err.message)) {
      // Passed: properly rejected
    } else {
      throw err;
    }
  }
});

test('4.4 Detector extractCSVHeaders with escaped quotes containing comma', () => {
  const headerWithEscapedComma = '"Notes / ""Important, Secret"" Instructions",login_password,login_username';
  const headers = detector.extractCSVHeaders(headerWithEscapedComma);
  // Escaped quote containing a comma should NOT split the header into 2 columns
  assert.strictEqual(headers.length, 3, `Expected 3 headers, but got ${headers.length}: ${JSON.stringify(headers)}`);
});

console.log('\n' + '═'.repeat(75));
console.log(`TEST SONUÇLARI: ${passes} BAŞARILI, ${failures} BAŞARISIZ`);
console.log('═'.repeat(75));

if (findings.length > 0) {
  console.log('\nTespit Edilen Zafiyetler / Hatalar:');
  findings.forEach((f, idx) => {
    console.log(`\n[${idx + 1}] ${f.test}`);
    console.log(`    Hata: ${f.error}`);
  });
  process.exit(1);
}
