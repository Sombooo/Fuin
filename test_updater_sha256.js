'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const Module = require('module');
const os = require('os');
const path = require('path');

const updateMgr = require('./renderer/modules/updateManager.js');

const HASH_DMG = 'a'.repeat(64);
const HASH_EXE = 'b'.repeat(64);
const HASH_BLOCKMAP = 'c'.repeat(64);
const HASH_UPPER = 'ABCDEF0123456789'.repeat(4);

let passed = 0;
let failed = 0;

async function runTest(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${err && err.stack ? err.stack : err}`);
    failed++;
  }
}

function makeByteStream(chunks) {
  let idx = 0;
  return {
    getReader() {
      return {
        async read() {
          if (idx >= chunks.length) return { done: true, value: undefined };
          const value = chunks[idx++];
          return { done: false, value };
        },
        async cancel() {
          idx = chunks.length;
        }
      };
    }
  };
}

function makeMockResponse({ ok = true, status = 200, url, chunks = [], headers = {} }) {
  const normalizedHeaders = {};
  for (const [k, v] of Object.entries(headers)) {
    normalizedHeaders[k.toLowerCase()] = String(v);
  }
  const buffers = chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)));
  return {
    ok,
    status,
    url,
    headers: {
      get: (name) => normalizedHeaders[String(name).toLowerCase()] || null
    },
    body: makeByteStream(buffers),
    async text() {
      return Buffer.concat(buffers).toString('utf8');
    }
  };
}

function loadMainWithElectronMock(tmpDir, openedPaths = []) {
  const mainHandlers = {};
  const mockMainWindow = {
    webContents: { send: () => {}, on: () => {}, setWindowOpenHandler: () => {} },
    on: () => {},
    setContentProtection: () => {},
    loadFile: () => {},
    show: () => {},
    hide: () => {},
    isVisible: () => true
  };
  const origReq = Module.prototype.require;
  Module.prototype.require = function (id) {
    if (id === 'electron') {
      return {
        app: {
          getPath: () => tmpDir,
          isPackaged: false,
          quit: () => {},
          whenReady: () => new Promise(() => {}),
          on: () => {}
        },
        session: { defaultSession: { webRequest: { onHeadersReceived: () => {} } } },
        BrowserWindow: class {
          constructor() {
            return mockMainWindow;
          }
        },
        ipcMain: {
          handle: (ch, fn) => {
            mainHandlers[ch] = fn;
          },
          on: () => {}
        },
        dialog: {},
        clipboard: { writeText: () => {} },
        powerMonitor: { on: () => {}, getSystemIdleTime: () => 0 },
        shell: {
          openPath: async (p) => {
            openedPaths.push(p);
            return '';
          }
        },
        Tray: class {
          setToolTip() {}
          popUpContextMenu() {}
          setContextMenu() {}
          on() {}
        },
        Menu: { buildFromTemplate: () => ({}) },
        nativeImage: { createFromPath: () => ({ resize: () => ({}) }) },
        systemPreferences: {},
        safeStorage: {}
      };
    }
    return origReq.apply(this, arguments);
  };
  try {
    const mainPath = require.resolve('./main.js');
    delete require.cache[mainPath];
    const mainMod = require('./main.js');
    return { mainMod, mainHandlers };
  } finally {
    Module.prototype.require = origReq;
  }
}

(async () => {
  console.log('\n── Desktop Updater SHA-256 Verification Test Suite ──');

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'fuin-updater-sha256-'));
  const origFetch = global.fetch;

  try {
    // 1. renderer/modules/updateManager.js — extractExpectedSha256
    await runTest('1. extractExpectedSha256 reads GitHub native asset.digest (sha256: prefix & bare hex)', () => {
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg', digest: `sha256:${HASH_UPPER}` }, ''),
        HASH_UPPER.toLowerCase()
      );
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg', digest: `  ${HASH_DMG}  ` }, ''),
        HASH_DMG
      );
    });

    await runTest('2. extractExpectedSha256 parses releaseBody by exact filename and space/dot .exe normalization', () => {
      const body = [
        '### Checksums (SHA-256)',
        `${HASH_BLOCKMAP}  Fuin-1.0.0-beta.12-arm64.dmg.blockmap`,
        `${HASH_DMG}  Fuin-1.0.0-beta.12-arm64.dmg`,
        `${HASH_EXE}  Fuin Setup 1.0.0-beta.12.exe`
      ].join('\n');

      // Exact match for macOS .dmg (must NOT match .dmg.blockmap above it)
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0-beta.12-arm64.dmg' }, body),
        HASH_DMG
      );

      // GitHub converts spaces to dots in uploaded asset names: Fuin.Setup.1.0.0-beta.12.exe
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin.Setup.1.0.0-beta.12.exe' }, body),
        HASH_EXE
      );

      // Reverse direction: asset with spaces matching dotted name in markdown table
      const dottedBody = `| \`Fuin.Setup.1.0.0-beta.12.exe\` | \`${HASH_UPPER}\` |`;
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin Setup 1.0.0-beta.12.exe' }, dottedBody),
        HASH_UPPER.toLowerCase()
      );
    });

    await runTest('3. extractExpectedSha256 returns null for malformed, wrong-length, or missing hashes', () => {
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg', digest: 'sha256:deadbeef' }, ''),
        null
      );
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg', digest: `sha256:${'a'.repeat(65)}` }, ''),
        null
      );
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg' }, `${'z'.repeat(64)}  Fuin-1.0.0.dmg`),
        null
      );
      assert.strictEqual(
        updateMgr.extractExpectedSha256({ name: 'Fuin-1.0.0.dmg' }, `${'a'.repeat(65)}  Fuin-1.0.0.dmg`),
        null
      );
      // Unrelated asset hash in release body must NOT be returned for a different asset
      assert.strictEqual(
        updateMgr.extractExpectedSha256(
          { name: 'Fuin-1.0.0.AppImage' },
          `${HASH_DMG}  Fuin-1.0.0.dmg`
        ),
        null
      );
      assert.strictEqual(updateMgr.extractExpectedSha256(null, null), null);
    });

    // 2. renderer/modules/updateManager.js — findChecksumsAsset
    await runTest('4. findChecksumsAsset trusts only Sombooo/Fuin GitHub release URLs and rejects evil hosts', () => {
      const trustedUrl = 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/SHA256SUMS.txt';
      const relGood = {
        assets: [
          { name: 'Fuin-1.0.0-beta.12-arm64.dmg', browser_download_url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0-beta.12-arm64.dmg' },
          { name: 'SHA256SUMS.txt', browser_download_url: trustedUrl }
        ]
      };
      const found = updateMgr.findChecksumsAsset(relGood);
      assert.ok(found, 'Must find trusted SHA256SUMS.txt asset');
      assert.strictEqual(found.browser_download_url, trustedUrl);

      const badUrls = [
        'https://evil.com/Sombooo/Fuin/releases/download/v1.0.0/SHA256SUMS.txt',
        'http://github.com/Sombooo/Fuin/releases/download/v1.0.0/SHA256SUMS.txt',
        'https://github.com/Attacker/Fuin/releases/download/v1.0.0/SHA256SUMS.txt',
        'https://user:pass@github.com/Sombooo/Fuin/releases/download/v1.0.0/SHA256SUMS.txt'
      ];
      for (const badUrl of badUrls) {
        const res = updateMgr.findChecksumsAsset({
          assets: [{ name: 'SHA256SUMS.txt', browser_download_url: badUrl }]
        });
        assert.strictEqual(res, null, `Must reject untrusted checksum URL: ${badUrl}`);
      }
    });

    // Load main.js with Electron mock for helper + end-to-end download-update IPC tests
    const openedPaths = [];
    const { mainMod, mainHandlers } = loadMainWithElectronMock(tmpDir, openedPaths);
    const downloadUpdate = mainHandlers['download-update'];
    const installUpdate = mainHandlers['install-update'];
    assert.strictEqual(typeof downloadUpdate, 'function', 'download-update IPC handler must be registered');
    assert.strictEqual(typeof installUpdate, 'function', 'install-update IPC handler must be registered');

    // 3. main.js pure helpers
    await runTest('5. parseSha256FromChecksumsText matches .dmg, space/dot .exe, BSD format, and avoids suffix collisions', () => {
      const sumsText = [
        '# Official Fuin release checksums',
        `${HASH_BLOCKMAP}  Fuin-1.0.0-beta.12-arm64.dmg.blockmap`,
        `${HASH_DMG} *dist/Fuin-1.0.0-beta.12-arm64.dmg`,
        `${HASH_EXE}  ./Fuin Setup 1.0.0-beta.12.exe`,
        `SHA256 (Fuin-1.0.0-beta.12.AppImage) = ${HASH_UPPER}`
      ].join('\n');

      assert.strictEqual(
        mainMod.parseSha256FromChecksumsText(sumsText, 'Fuin-1.0.0-beta.12-arm64.dmg'),
        HASH_DMG
      );
      assert.strictEqual(
        mainMod.parseSha256FromChecksumsText(sumsText, 'Fuin.Setup.1.0.0-beta.12.exe'),
        HASH_EXE
      );
      assert.strictEqual(
        mainMod.parseSha256FromChecksumsText(sumsText, 'Fuin Setup 1.0.0-beta.12.exe'),
        HASH_EXE
      );
      assert.strictEqual(
        mainMod.parseSha256FromChecksumsText(sumsText, 'Fuin-1.0.0-beta.12.AppImage'),
        HASH_UPPER.toLowerCase()
      );
      assert.strictEqual(
        mainMod.parseSha256FromChecksumsText(sumsText, 'Fuin-missing.dmg'),
        null
      );
    });

    await runTest('6. isValidSha256Hex and isTrustedUpdateRedirectUrl enforce strict validation', () => {
      assert.strictEqual(mainMod.isValidSha256Hex(HASH_DMG), true);
      assert.strictEqual(mainMod.isValidSha256Hex(HASH_UPPER), true);
      assert.strictEqual(mainMod.isValidSha256Hex('short'), false);
      assert.strictEqual(mainMod.isValidSha256Hex('g'.repeat(64)), false);
      assert.strictEqual(mainMod.isValidSha256Hex(null), false);

      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('https://objects.githubusercontent.com/github-production-release-asset/123'), true);
      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('https://release-assets.githubusercontent.com/abc'), true);
      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('https://fuin.blob.core.windows.net/pkg'), true);
      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('http://objects.githubusercontent.com/abc'), false);
      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('https://evil.com/abc'), false);
      assert.strictEqual(mainMod.isTrustedUpdateRedirectUrl('https://user@github.com/abc'), false);
    });

    // 4. End-to-end download-update IPC handler verification
    const mockEvent = { sender: { send: () => {} } };
    const updatesDir = path.join(tmpDir, 'updates');

    await runTest('7. download-update passes with matching expectedSha256 and atomically renames .part -> destinationPath', async () => {
      const payload1 = Buffer.from('FUIN-INSTALLER-CHUNK-1-');
      const payload2 = Buffer.from('FUIN-INSTALLER-CHUNK-2-VERIFIED');
      const fullPayload = Buffer.concat([payload1, payload2]);
      const expectedHash = crypto.createHash('sha256').update(fullPayload).digest('hex');

      const assetUrl = 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0-beta.12-arm64.dmg';
      global.fetch = async () =>
        makeMockResponse({
          url: 'https://objects.githubusercontent.com/github-production-release-asset/Fuin-1.0.0-beta.12-arm64.dmg',
          chunks: [payload1, payload2],
          headers: { 'content-length': fullPayload.length }
        });

      const res = await downloadUpdate(mockEvent, {
        url: assetUrl,
        filename: 'Fuin-1.0.0-beta.12-arm64.dmg',
        expectedSha256: expectedHash.toUpperCase()
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.verified, true);
      assert.strictEqual(res.sha256, expectedHash);
      assert.strictEqual(res.filePath, path.join(updatesDir, 'Fuin-1.0.0-beta.12-arm64.dmg'));
      assert.ok(fs.existsSync(res.filePath), 'Verified installer must exist at destinationPath');
      assert.deepStrictEqual(fs.readFileSync(res.filePath), fullPayload);
      const leftoverParts = fs.readdirSync(updatesDir).filter((f) => f.endsWith('.part'));
      assert.strictEqual(leftoverParts.length, 0, 'No .part temp files should remain after atomic rename');
    });

    await runTest('8. download-update rejects tampered bytes on SHA-256 mismatch, removes .part, and never writes destinationPath', async () => {
      const goodPayload = Buffer.from('LEGITIMATE-INSTALLER-BYTES');
      const tamperedPayload = Buffer.from('TAMPERED-INSTALLER-BYTES!!');
      const expectedHash = crypto.createHash('sha256').update(goodPayload).digest('hex');
      const filename = 'Fuin-Tampered-Test.dmg';
      const destPath = path.join(updatesDir, filename);
      if (fs.existsSync(destPath)) fs.unlinkSync(destPath);

      global.fetch = async () =>
        makeMockResponse({
          url: 'https://objects.githubusercontent.com/github-production-release-asset/Fuin-Tampered-Test.dmg',
          chunks: [tamperedPayload],
          headers: { 'content-length': tamperedPayload.length }
        });

      await assert.rejects(
        () =>
          downloadUpdate(mockEvent, {
            url: `https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/${filename}`,
            filename,
            expectedSha256: expectedHash
          }),
        /SHA-256 integrity verification failed/
      );

      assert.strictEqual(fs.existsSync(destPath), false, 'Tampered installer must NEVER reach destinationPath');
      const leftoverParts = fs.readdirSync(updatesDir).filter((f) => f.endsWith('.part'));
      assert.strictEqual(leftoverParts.length, 0, 'Tampered .part temp file must be deleted on mismatch');
    });

    await runTest('9. download-update rejects malformed expectedSha256 before making any network request', async () => {
      let fetchCalled = false;
      global.fetch = async () => {
        fetchCalled = true;
        throw new Error('fetch should not be called');
      };

      for (const badHash of ['not-hex', 'abc123', 'a'.repeat(65), '   ', 12345]) {
        await assert.rejects(
          () =>
            downloadUpdate(mockEvent, {
              url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0.dmg',
              filename: 'Fuin-1.0.0.dmg',
              expectedSha256: badHash
            }),
          /Invalid SHA-256 checksum format/
        );
      }
      assert.strictEqual(fetchCalled, false, 'Malformed expectedSha256 must fail before fetch');
    });

    await runTest('10. download-update resolves SHA-256 via trusted checksumUrl (with space/dot .exe name) and verifies', async () => {
      const exeBytes = Buffer.from('MZ-WINDOWS-SETUP-INSTALLER-PAYLOAD');
      const exeHash = crypto.createHash('sha256').update(exeBytes).digest('hex');
      const checksumUrl = 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/SHA256SUMS.txt';
      const assetUrl = 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin.Setup.1.0.0-beta.12.exe';

      global.fetch = async (reqUrl) => {
        if (reqUrl === checksumUrl) {
          const text = `${exeHash}  Fuin Setup 1.0.0-beta.12.exe\n`;
          return makeMockResponse({
            url: 'https://objects.githubusercontent.com/github-production-release-asset/SHA256SUMS.txt',
            chunks: [Buffer.from(text)],
            headers: { 'content-length': Buffer.byteLength(text) }
          });
        }
        return makeMockResponse({
          url: 'https://objects.githubusercontent.com/github-production-release-asset/Fuin.Setup.1.0.0-beta.12.exe',
          chunks: [exeBytes],
          headers: { 'content-length': exeBytes.length }
        });
      };

      const res = await downloadUpdate(mockEvent, {
        url: assetUrl,
        filename: 'Fuin.Setup.1.0.0-beta.12.exe',
        expectedSha256: null,
        checksumUrl
      });

      assert.strictEqual(res.success, true);
      assert.strictEqual(res.verified, true);
      assert.strictEqual(res.sha256, exeHash);
      assert.ok(fs.existsSync(res.filePath));

      // Tampered installer with checksumUrl must also fail closed and clean up .part
      const badExeFilename = 'Fuin.Setup.1.0.0-beta.12-tampered.exe';
      const badDestPath = path.join(updatesDir, badExeFilename);
      if (fs.existsSync(badDestPath)) fs.unlinkSync(badDestPath);
      global.fetch = async (reqUrl) => {
        if (reqUrl === checksumUrl) {
          const text = `${exeHash}  Fuin Setup 1.0.0-beta.12-tampered.exe\n`;
          return makeMockResponse({
            url: 'https://objects.githubusercontent.com/github-production-release-asset/SHA256SUMS.txt',
            chunks: [Buffer.from(text)],
            headers: { 'content-length': Buffer.byteLength(text) }
          });
        }
        return makeMockResponse({
          url: 'https://objects.githubusercontent.com/github-production-release-asset/Fuin.Setup.1.0.0-beta.12-tampered.exe',
          chunks: [Buffer.from('TAMPERED-WINDOWS-EXE')],
          headers: { 'content-length': 20 }
        });
      };

      await assert.rejects(
        () =>
          downloadUpdate(mockEvent, {
            url: `https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/${badExeFilename}`,
            filename: badExeFilename,
            expectedSha256: null,
            checksumUrl
          }),
        /SHA-256 integrity verification failed/
      );
      assert.strictEqual(fs.existsSync(badDestPath), false, 'Tampered checksumUrl download must never reach destinationPath');
      assert.strictEqual(fs.readdirSync(updatesDir).filter((f) => f.endsWith('.part')).length, 0);
    });

    await runTest('11. download-update rejects untrusted checksumUrl, untrusted redirect, and oversized checksums file', async () => {
      let fetchCalled = false;
      global.fetch = async () => {
        fetchCalled = true;
        throw new Error('should not be called');
      };

      await assert.rejects(
        () =>
          downloadUpdate(mockEvent, {
            url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0.dmg',
            filename: 'Fuin-1.0.0.dmg',
            checksumUrl: 'https://evil.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/SHA256SUMS.txt'
          }),
        /Unauthorized checksum source/
      );
      assert.strictEqual(fetchCalled, false, 'Untrusted checksumUrl must fail before fetch');

      // Untrusted redirect on checksum download
      global.fetch = async () =>
        makeMockResponse({
          url: 'https://attacker.example/SHA256SUMS.txt',
          chunks: [Buffer.from(`${HASH_DMG}  Fuin-1.0.0.dmg\n`)]
        });

      await assert.rejects(
        () =>
          downloadUpdate(mockEvent, {
            url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0.dmg',
            filename: 'Fuin-1.0.0.dmg',
            checksumUrl: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/SHA256SUMS.txt'
          }),
        /Untrusted redirect host during checksum download/
      );

      // Oversized (> 64KB) checksums response
      const hugeChunk = Buffer.alloc(70 * 1024, 'a');
      global.fetch = async () =>
        makeMockResponse({
          url: 'https://objects.githubusercontent.com/SHA256SUMS.txt',
          chunks: [hugeChunk]
        });

      await assert.rejects(
        () =>
          downloadUpdate(mockEvent, {
            url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/Fuin-1.0.0.dmg',
            filename: 'Fuin-1.0.0.dmg',
            checksumUrl: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.12/SHA256SUMS.txt'
          }),
        /Checksums file exceeds maximum allowed size/
      );
    });

    await runTest('12. download-update fails CLOSED when no hash or checksumUrl exists (sha256-missing)', async () => {
      const payload = Buffer.from('LEGACY-RELEASE-DMG');
      const legacyPath = path.join(updatesDir, 'Fuin-Legacy.dmg');
      if (fs.existsSync(legacyPath)) fs.unlinkSync(legacyPath);

      global.fetch = async () =>
        makeMockResponse({
          url: 'https://objects.githubusercontent.com/github-production-release-asset/Fuin-Legacy.dmg',
          chunks: [payload],
          headers: { 'content-length': payload.length }
        });

      const res = await downloadUpdate(mockEvent, {
        url: 'https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.10/Fuin-Legacy.dmg',
        filename: 'Fuin-Legacy.dmg'
      });

      assert.strictEqual(res.success, false);
      assert.strictEqual(res.verified, false);
      assert.strictEqual(res.error, 'sha256-missing');
      assert.strictEqual(fs.existsSync(legacyPath), false, 'Unverified installer must NEVER be finalized on disk');
    });

    await runTest('13. install-update enforces private userData/updates dir, 0o600/0o700 perms, and SHA-256 re-verification', async () => {
      const payload = Buffer.from('VERIFIED-INSTALLER-FOR-INSTALL-CHECK');
      const expectedHash = crypto.createHash('sha256').update(payload).digest('hex');
      const filename = 'Fuin-Reverify-Test.dmg';

      global.fetch = async () =>
        makeMockResponse({
          url: `https://objects.githubusercontent.com/github-production-release-asset/${filename}`,
          chunks: [payload],
          headers: { 'content-length': payload.length }
        });

      const dlRes = await downloadUpdate(mockEvent, {
        url: `https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.13/${filename}`,
        filename,
        expectedSha256: expectedHash
      });
      assert.strictEqual(dlRes.success, true);
      assert.strictEqual(dlRes.verified, true);
      if (process.platform !== 'win32') {
        assert.strictEqual(fs.lstatSync(updatesDir).mode & 0o777, 0o700, 'updatesDir must be mode 0o700');
        assert.strictEqual(fs.lstatSync(dlRes.filePath).mode & 0o777, 0o600, 'downloaded installer must be mode 0o600');
      }

      // Valid install-update re-verifies SHA-256 and opens path
      openedPaths.length = 0;
      const ok = await installUpdate(mockEvent, { filePath: dlRes.filePath });
      assert.strictEqual(ok, true);
      assert.strictEqual(openedPaths.length, 1);

      // Post-download disk tampering MUST fail re-verification before shell.openPath
      fs.writeFileSync(dlRes.filePath, Buffer.from('TOCTOU-TAMPERED-INSTALLER-BYTES'));
      openedPaths.length = 0;
      await assert.rejects(
        () => installUpdate(mockEvent, { filePath: dlRes.filePath }),
        /SHA-256 integrity verification failed before install/
      );
      assert.strictEqual(openedPaths.length, 0, 'Tampered installer must NEVER be passed to shell.openPath');

      // Unverified arbitrary file dropped into updatesDir MUST fail closed
      const droppedFile = path.join(updatesDir, 'Fuin-Dropped.dmg');
      fs.writeFileSync(droppedFile, Buffer.from('DROPPED-BINARY'));
      await assert.rejects(
        () => installUpdate(mockEvent, { filePath: droppedFile }),
        /has not passed SHA-256 verification/
      );
    });
  } finally {
    global.fetch = origFetch;
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
  }

  console.log(`\nUpdater SHA-256 Suite: ${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
})();
