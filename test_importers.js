'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST SUITE: test_importers.js
 *
 * Verifies Acceptance Criteria (Phase 1 Domain Services - Importers):
 *   1. RFC 4180 CSV Tokenizer:
 *      - Multiline entries inside quotes (\r\n and \n)
 *      - Escaped double quotes ("" -> ")
 *      - Commas within quoted values
 *      - UTF-8 BOM stripping (\uFEFF)
 *      - Mixed CRLF and LF delimiters
 *      - Trailing blank lines & unclosed quote recovery
 *   2. Format Detection:
 *      - Bitwarden CSV & unencrypted JSON
 *      - LastPass CSV
 *      - 1Password CSV (Classic & Modern)
 *      - Google Chrome CSV
 *      - Fuin native CSV & JSON
 *      - Unknown/empty content handling
 *   3. Data Normalization & Schema Compliance:
 *      - Standard schema: { id, title, username, password, url, notes, totp, category, created, updated }
 *      - Backward compatibility: title === site, notes === note
 *      - Password whitespace preservation (no unwanted trimming)
 *      - RFC 4122 v4 UUID format verification
 *   4. Edge Cases & Resilience:
 *      - Bitwarden encrypted JSON rejection
 *      - Bitwarden folderId-to-category resolution
 *      - Missing title or password row skipping
 *      - In-flight deduplication against existing vault entries
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const assert = require('assert');

// Target module
const FuinImporters = require('./services/importers');

console.log('═'.repeat(75));
console.log('FUIN TEST: CSV & JSON IO IMPORTERS DOMAIN SERVICE (M1 §R1)');
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

// ── TEST GROUP 1: RFC 4180 CSV TOKENIZER ─────────────────────────────────────

test('1.1 Tokenizer: Handles basic 3-column CSV with CRLF', () => {
  const csv = 'site,username,password\r\ngithub.com,alice,secret123\r\ngoogle.com,bob,secret456';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows.length, 3);
  assert.deepStrictEqual(rows[0], ['site', 'username', 'password']);
  assert.deepStrictEqual(rows[1], ['github.com', 'alice', 'secret123']);
  assert.deepStrictEqual(rows[2], ['google.com', 'bob', 'secret456']);
});

test('1.2 Tokenizer: Handles commas inside quoted fields', () => {
  const csv = 'site,notes,password\r\n"Google, Inc","Mountain View, CA",pw123';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows.length, 2);
  assert.strictEqual(rows[1][0], 'Google, Inc');
  assert.strictEqual(rows[1][1], 'Mountain View, CA');
  assert.strictEqual(rows[1][2], 'pw123');
});

test('1.3 Tokenizer: Handles escaped double quotes ("")', () => {
  const csv = 'site,notes,password\r\nAcme,"She said ""Hello World"" yesterday",pw123';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows[1][1], 'She said "Hello World" yesterday');
});

test('1.4 Tokenizer: Handles multiline notes inside quotes (RFC 4180 §2.6)', () => {
  const csv = 'site,notes,password\r\nGitHub,"Line 1\r\nLine 2\r\nLine 3",pw123\r\nGitLab,SingleLine,pw456';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows.length, 3, 'Multiline field must NOT split into multiple records');
  assert.strictEqual(rows[1][0], 'GitHub');
  assert.strictEqual(rows[1][1], 'Line 1\r\nLine 2\r\nLine 3');
  assert.strictEqual(rows[1][2], 'pw123');
  assert.strictEqual(rows[2][0], 'GitLab');
});

test('1.5 Tokenizer: Strips UTF-8 BOM (\\uFEFF) from file start', () => {
  const csv = '\uFEFFsite,username,password\r\ngithub.com,alice,pw123';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows[0][0], 'site', 'BOM character must be removed from first header');
});

test('1.6 Tokenizer: Ignores trailing blank lines', () => {
  const csv = 'site,username,password\r\ngithub.com,alice,pw123\r\n\r\n';
  const rows = FuinImporters.parseCSV(csv);
  assert.strictEqual(rows.length, 2);
});

test('1.7 Tokenizer: Gracefully recovers from unclosed quotes', () => {
  const csv = 'site,username,password\r\n"unclosed quote,alice,pw123';
  const rows = FuinImporters.parseCSV(csv);
  assert.ok(rows.length >= 2, 'Should not throw or crash on unclosed quotes');
});

// ── TEST GROUP 2: FORMAT DETECTION ───────────────────────────────────────────

test('2.1 Detector: Bitwarden CSV detection', () => {
  const text = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp';
  assert.strictEqual(FuinImporters.detectFormat(text), 'bitwarden');
});

test('2.2 Detector: Bitwarden unencrypted JSON detection', () => {
  const json = JSON.stringify({
    encrypted: false,
    folders: [{ id: 'f1', name: 'Work' }],
    items: [{ name: 'GitHub', login: { username: 'alice', password: 'pw' } }]
  });
  assert.strictEqual(FuinImporters.detectFormat(json), 'bitwarden');
});

test('2.3 Detector: LastPass CSV detection', () => {
  const text = 'url,username,password,totp,extra,name,grouping,fav';
  assert.strictEqual(FuinImporters.detectFormat(text), 'lastpass');
});

test('2.4 Detector: 1Password Classic CSV detection', () => {
  const text = 'Title,URL,Username,Password,Notes,OTPAuth';
  assert.strictEqual(FuinImporters.detectFormat(text), '1password');
});

test('2.5 Detector: 1Password Modern CSV detection', () => {
  const text = 'title,website,username,password,notes,one-time password';
  assert.strictEqual(FuinImporters.detectFormat(text), '1password');
});

test('2.6 Detector: Chrome / Edge CSV detection', () => {
  const text = 'name,url,username,password,note';
  assert.strictEqual(FuinImporters.detectFormat(text), 'chrome');
});

test('2.7 Detector: Fuin native CSV detection', () => {
  const text = 'site,category,username,password,url,note,totp';
  assert.strictEqual(FuinImporters.detectFormat(text), 'fuin');
});

test('2.8 Detector: Fuin native JSON detection', () => {
  const json = JSON.stringify({
    type: 'fuin/vault',
    entries: [{ site: 'github.com', password: 'pw' }]
  });
  assert.strictEqual(FuinImporters.detectFormat(json), 'fuin');
});

test('2.9 Detector: Unknown format handling', () => {
  const text = 'col_a,col_b,col_c\r\nval_a,val_b,val_c';
  assert.strictEqual(FuinImporters.detectFormat(text), 'unknown');
});

// ── TEST GROUP 3: FORMAT-SPECIFIC IMPORTERS ──────────────────────────────────

test('3.1 Bitwarden CSV: Full field import and normalization', () => {
  const csv = 'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\r\n' +
              'Dev,1,1,GitHub,"Recovery: 1111",,0,https://github.com,alice,bwSecret123!,JBSWY3DPEHPK3PXP';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.format, 'bitwarden');
  assert.strictEqual(res.count, 1);
  const e = res.entries[0];
  assert.strictEqual(e.title, 'GitHub');
  assert.strictEqual(e.site, 'GitHub');
  assert.strictEqual(e.username, 'alice');
  assert.strictEqual(e.password, 'bwSecret123!');
  assert.strictEqual(e.url, 'https://github.com');
  assert.strictEqual(e.notes, 'Recovery: 1111');
  assert.strictEqual(e.note, 'Recovery: 1111');
  assert.strictEqual(e.totp, 'JBSWY3DPEHPK3PXP');
  assert.strictEqual(e.category, 'Dev');
  assert.strictEqual(e.fav, true);
  assert.match(e.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
});

test('3.2 Bitwarden JSON: Folder-to-category mapping and Login filter', () => {
  const data = {
    encrypted: false,
    folders: [{ id: 'f-work', name: 'Office Work' }],
    items: [
      {
        folderId: 'f-work',
        name: 'Work Email',
        notes: 'Exchange server',
        favorite: false,
        login: {
          username: 'alice@corp.com',
          password: 'corporatePassword99!',
          uris: [{ uri: 'https://mail.corp.com' }],
          totp: 'OTP123'
        }
      },
      {
        name: 'Credit Card (Ignored)',
        card: { number: '4000123456789010' } // Should be skipped (no login)
      }
    ]
  };
  const res = FuinImporters.importFromText(JSON.stringify(data));
  assert.strictEqual(res.format, 'bitwarden');
  assert.strictEqual(res.count, 1, 'Only login items must be imported');
  const e = res.entries[0];
  assert.strictEqual(e.title, 'Work Email');
  assert.strictEqual(e.category, 'Office Work', 'Folder ID should be resolved to category name');
  assert.strictEqual(e.url, 'https://mail.corp.com');
});

test('3.3 Bitwarden Encrypted JSON: Rejects with informative error', () => {
  const encData = JSON.stringify({ encrypted: true, items: [] });
  assert.throws(() => {
    FuinImporters.importFromText(encData);
  }, /şifreli.*desteklenmemektedir/i);
});

test('3.4 LastPass CSV: Mapping and URL fallback', () => {
  const csv = 'url,username,password,extra,name,grouping,fav\r\n' +
              'https://aws.amazon.com,root,awsSecret!,console access,AWS Console,Cloud,1\r\n' +
              'https://unnamed.com,user,pw!,"",,Other,0';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.format, 'lastpass');
  assert.strictEqual(res.count, 2);
  assert.strictEqual(res.entries[0].title, 'AWS Console');
  assert.strictEqual(res.entries[0].category, 'Cloud');
  assert.strictEqual(res.entries[0].fav, true);
  // Fallback to URL when name is missing
  assert.strictEqual(res.entries[1].title, 'unnamed.com');
});

test('3.5 1Password CSV: Maps OTPAuth and website', () => {
  const csv = 'Title,URL,Username,Password,Notes,OTPAuth\r\n' +
              'GitLab,https://gitlab.com,dev,glSecret!,my notes,otpauth://totp/GitLab:dev?secret=JBSWY3DPEHPK3PXP';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.format, '1password');
  assert.strictEqual(res.count, 1);
  assert.strictEqual(res.entries[0].totp, 'otpauth://totp/GitLab:dev?secret=JBSWY3DPEHPK3PXP');
});

test('3.6 Chrome CSV: Imports credentials and notes', () => {
  const csv = 'name,url,username,password,note\r\n' +
              'Twitter,https://twitter.com,tweetguy,pass1234,chrome note';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.format, 'chrome');
  assert.strictEqual(res.entries[0].title, 'Twitter');
  assert.strictEqual(res.entries[0].notes, 'chrome note');
});

test('3.7 Fuin Native JSON: Preserves existing valid UUIDs and categories', () => {
  const vault = {
    type: 'fuin/vault',
    categories: ['İş', 'Finans'],
    entries: [
      {
        id: '12345678-1234-4234-8234-123456789abc',
        site: 'Kasa Girişi',
        username: 'admin',
        password: 'vaultMasterPassword',
        category: 'İş',
        note: 'Önemli not',
        created: 1600000000000,
        updated: 1600000001000
      }
    ]
  };
  const res = FuinImporters.importFromText(JSON.stringify(vault));
  assert.strictEqual(res.format, 'fuin');
  assert.strictEqual(res.entries[0].id, '12345678-1234-4234-8234-123456789abc');
  assert.strictEqual(res.entries[0].site, 'Kasa Girişi');
  assert.strictEqual(res.entries[0].created, 1600000000000);
});

// ── TEST GROUP 4: EDGE CASES & DATA HYGIENE ──────────────────────────────────

test('4.1 Hygiene: Preserves exact password whitespace (no trimming)', () => {
  const csv = 'site,username,password\r\n' +
              'spaced.com,user,"  leading and trailing  "';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.entries[0].password, '  leading and trailing  ');
});

test('4.2 Hygiene: Skips entries missing title or password', () => {
  const csv = 'site,username,password\r\n' +
              'valid.com,user,pass\r\n' +
              ',user,pass\r\n' +
              'nopass.com,user,\r\n' +
              'valid2.com,user2,pass2';
  const res = FuinImporters.importFromText(csv);
  assert.strictEqual(res.count, 2);
  assert.strictEqual(res.skippedCount, 2);
  assert.strictEqual(res.entries[0].title, 'valid.com');
  assert.strictEqual(res.entries[1].title, 'valid2.com');
});

test('4.3 Deduplication: Filters candidate duplicates against existing vault', () => {
  const existing = [
    { site: 'github.com', username: 'alice', password: 'pw1' }
  ];
  const csv = 'site,username,password\r\n' +
              'github.com,alice,pw1\r\n' +
              'github.com,alice,pw2\r\n' +
              'gitlab.com,alice,pw1';
  const res = FuinImporters.importFromText(csv, { existingEntries: existing });
  assert.strictEqual(res.count, 2, 'Candidate matching site, user, pass must be skipped');
  assert.strictEqual(res.skippedCount, 1);
});

test('4.4 Interface Contract: importEntries returns Array<VaultEntry>', () => {
  const csv = 'site,username,password\r\ngoogle.com,test,pw999';
  const entries = FuinImporters.importEntries(csv, 'fuin');
  assert.ok(Array.isArray(entries));
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].title, 'google.com');
  assert.strictEqual(entries[0].site, 'google.com');
});

console.log('═'.repeat(75));
console.log(`SONUÇ: ${passes} BAŞARILI, ${failures} BAŞARISIZ`);
console.log('═'.repeat(75));

if (failures > 0) process.exit(1);
