'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const Module = require('module');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

console.log('══════════════════════════════════════════════════════════════════════════════');
console.log('FUIN STAGE 1 — LOCAL ISOLATION & BOUNDARY SURFACE HARDENING TEST SUITE');
console.log('══════════════════════════════════════════════════════════════════════════════\n');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function test(name, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    failedTests++;
  }
}

async function testAsync(name, fn) {
  totalTests++;
  try {
    await fn();
    console.log(`  [PASS] ${name}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] ${name}: ${err.message}`);
    failedTests++;
  }
}

function makeShortTmpDir(prefix) {
  const base = (process.platform !== 'win32' && fs.existsSync('/tmp')) ? '/tmp' : os.tmpdir();
  return fs.mkdtempSync(path.join(base, prefix));
}

function makeMockApp(rootDir) {
  const userDataDir = path.join(rootDir, 'userData');
  const homeDir = path.join(rootDir, 'home');
  const tempDir = path.join(rootDir, 'temp');
  return {
    isPackaged: false,
    getVersion: () => '1.0.0-test',
    getPath: (name) => {
      if (name === 'userData') return userDataDir;
      if (name === 'home') return homeDir;
      if (name === 'temp') return tempDir;
      return path.join(rootDir, name);
    },
    _dirs: { userDataDir, homeDir, tempDir },
  };
}

async function runAll() {
  const extBridge = require('./main/extensionBridge');

  // ── 1. Token File Atomicity, Permissions & Symlink Defenses ────────────────
  console.log('[1. Extension Token Symlink Defense & Atomic 0o600 Creation]');

  test('1.1 ensurePrivateDirSync creates and tightens userData dir to 0o700 on POSIX', () => {
    const tmpRoot = makeShortTmpDir('fuin-iso-dir-');
    try {
      const targetDir = path.join(tmpRoot, 'private-user-data');
      fs.mkdirSync(targetDir, { recursive: true, mode: 0o755 });
      if (process.platform !== 'win32') {
        fs.chmodSync(targetDir, 0o755);
      }
      extBridge.ensurePrivateDirSync(targetDir);
      if (process.platform !== 'win32') {
        const mode = fs.lstatSync(targetDir).mode & 0o777;
        assert.strictEqual(mode, 0o700, `Expected 0o700, got 0o${mode.toString(8)}`);
      }
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  test('1.2 getOrCreateExtToken creates 64-hex token atomically with 0o600 and zero .tmp leftovers', () => {
    const tmpRoot = makeShortTmpDir('fuin-iso-tok-');
    try {
      const app = makeMockApp(tmpRoot);
      const token = extBridge.getOrCreateExtToken(app);
      assert.ok(/^[0-9a-f]{64}$/i.test(token), 'Token must be 64 hex chars');

      const tokenPath = extBridge.getExtTokenPath(app);
      const st = fs.lstatSync(tokenPath);
      assert.strictEqual(st.isSymbolicLink(), false, 'Token file must not be a symlink');
      assert.strictEqual(st.isFile(), true, 'Token file must be a regular file');

      if (process.platform !== 'win32') {
        assert.strictEqual(st.mode & 0o777, 0o600, 'Token file must be mode 0o600');
        assert.strictEqual(fs.lstatSync(app._dirs.userDataDir).mode & 0o777, 0o700, 'userData dir must be 0o700');
      }

      const leftoverTmps = fs.readdirSync(app._dirs.userDataDir).filter(f => f.endsWith('.tmp'));
      assert.strictEqual(leftoverTmps.length, 0, 'No temporary token files should remain');
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  if (process.platform !== 'win32') {
    test('1.3 getOrCreateExtToken replaces live symlink without reading or writing symlink target', () => {
      const tmpRoot = makeShortTmpDir('fuin-iso-sym-');
      try {
        const app = makeMockApp(tmpRoot);
        fs.mkdirSync(app._dirs.userDataDir, { recursive: true, mode: 0o700 });

        const victimPath = path.join(tmpRoot, 'victim-secret.txt');
        const attackerControlledHex = 'a'.repeat(64);
        fs.writeFileSync(victimPath, attackerControlledHex, { mode: 0o644 });

        const tokenPath = extBridge.getExtTokenPath(app);
        fs.symlinkSync(victimPath, tokenPath);

        const generatedToken = extBridge.getOrCreateExtToken(app);
        assert.notStrictEqual(generatedToken, attackerControlledHex, 'Must NEVER read token through a symlink');
        assert.ok(/^[0-9a-f]{64}$/i.test(generatedToken), 'Must generate a valid fresh 64-hex token');

        // Symlink target must remain completely untouched
        assert.strictEqual(fs.readFileSync(victimPath, 'utf8'), attackerControlledHex, 'Symlink target must NOT be modified');

        // Token path must now be a real regular file with mode 0o600
        const st = fs.lstatSync(tokenPath);
        assert.strictEqual(st.isSymbolicLink(), false, 'Token path must no longer be a symlink');
        assert.strictEqual(st.isFile(), true, 'Token path must be a regular file');
        assert.strictEqual(st.mode & 0o777, 0o600, 'Regenerated token file must have mode 0o600');
      } finally {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      }
    });

    test('1.4 getOrCreateExtToken neutralizes dangling symlink without creating target file', () => {
      const tmpRoot = makeShortTmpDir('fuin-iso-dang-');
      try {
        const app = makeMockApp(tmpRoot);
        fs.mkdirSync(app._dirs.userDataDir, { recursive: true, mode: 0o700 });

        const nonexistentTarget = path.join(tmpRoot, 'must-never-be-created.txt');
        const tokenPath = extBridge.getExtTokenPath(app);
        fs.symlinkSync(nonexistentTarget, tokenPath);

        const token = extBridge.getOrCreateExtToken(app);
        assert.ok(/^[0-9a-f]{64}$/i.test(token));
        assert.strictEqual(fs.existsSync(nonexistentTarget), false, 'Dangling symlink target must NEVER be created');
        const st = fs.lstatSync(tokenPath);
        assert.strictEqual(st.isSymbolicLink(), false);
        assert.strictEqual(st.isFile(), true);
        assert.strictEqual(st.mode & 0o777, 0o600);
      } finally {
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      }
    });
  }

  test('1.5 getOrCreateExtToken refuses non-regular token path (directory)', () => {
    const tmpRoot = makeShortTmpDir('fuin-iso-nonreg-');
    try {
      const app = makeMockApp(tmpRoot);
      const tokenPath = extBridge.getExtTokenPath(app);
      fs.mkdirSync(tokenPath, { recursive: true });
      assert.throws(() => extBridge.getOrCreateExtToken(app), /non-regular/i);
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  // ── 2. Native Host Wrapper & Manifest Hardening ────────────────────────────
  console.log('\n[2. Native Host Wrapper Escaping & Manifest Permissions]');

  test('2.1 formatNativeHostWrapperScript rejects CR/LF/NUL injection and safely quotes POSIX & Win32 paths', () => {
    assert.throws(() => extBridge.formatNativeHostWrapperScript('/bin/node\nid', '/app/host.js', 'darwin'), /control characters/i);
    assert.throws(() => extBridge.formatNativeHostWrapperScript('/bin/node', '/app/host.js\r\nevil', 'darwin'), /control characters/i);
    assert.throws(() => extBridge.formatNativeHostWrapperScript('/bin/node\0evil', '/app/host.js', 'linux'), /control characters/i);
    assert.throws(() => extBridge.formatNativeHostWrapperScript('C:\\Fuin"\\Fuin.exe', 'C:\\host.js', 'win32'), /double quote/i);

    const posixScript = extBridge.formatNativeHostWrapperScript("/opt/Fuin $(whoami)/'bin'/electron", '/opt/Fuin/host.js', 'darwin');
    assert.ok(posixScript.startsWith('#!/bin/sh\n'), 'Must start with #!/bin/sh');
    assert.ok(posixScript.includes("exec '/opt/Fuin $(whoami)/'\\''bin'\\''/electron' '/opt/Fuin/host.js' \"$@\""),
      'POSIX script must strictly single-quote executable and host paths to prevent shell substitution');

    const winScript = extBridge.formatNativeHostWrapperScript('C:\\Users\\100%User\\Fuin.exe', 'C:\\Program Files\\Fuin\\host.js', 'win32');
    assert.ok(winScript.includes('"C:\\Users\\100%%User\\Fuin.exe" "C:\\Program Files\\Fuin\\host.js" %*'),
      'Windows batch script must escape % signs cleanly');
  });

  test('2.2 ensureNativeHostWrapper & writeNativeHostManifest enforce 0o700/0o600 and never follow symlinks', () => {
    const tmpRoot = makeShortTmpDir('fuin-iso-wrap-');
    try {
      const app = makeMockApp(tmpRoot);
      const manifestTarget = path.join(tmpRoot, 'manifests', 'com.fuin.nativehost.json');
      let victimPath = null;

      if (process.platform !== 'win32') {
        fs.mkdirSync(path.dirname(manifestTarget), { recursive: true });
        victimPath = path.join(tmpRoot, 'victim-manifest.txt');
        fs.writeFileSync(victimPath, 'ORIGINAL_VICTIM');
        fs.symlinkSync(victimPath, manifestTarget);
      }

      const ok = extBridge.writeNativeHostManifest(manifestTarget, 'allowed_extensions', ['fuin-app@sombo.dev'], app);
      assert.strictEqual(ok, true, 'Manifest write must succeed');

      const parsed = JSON.parse(fs.readFileSync(manifestTarget, 'utf8'));
      assert.strictEqual(parsed.name, extBridge.NATIVE_HOST_NAME);
      assert.ok(fs.existsSync(parsed.path), 'Wrapper script must exist');

      if (process.platform !== 'win32') {
        assert.strictEqual(fs.readFileSync(victimPath, 'utf8'), 'ORIGINAL_VICTIM', 'Manifest symlink target must remain untouched');
        assert.strictEqual(fs.lstatSync(manifestTarget).isSymbolicLink(), false, 'Manifest must not be a symlink');
        assert.strictEqual(fs.lstatSync(manifestTarget).mode & 0o777, 0o600, 'Manifest must have mode 0o600');
        assert.strictEqual(fs.lstatSync(parsed.path).mode & 0o777, 0o700, 'Wrapper script must have mode 0o700');
      }
    } finally {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  // ── 3. Extension Bridge Socket Isolation, Windows ACL Flags & Auth Abuse ───
  console.log('\n[3. Extension Bridge Socket Isolation, Win32 ACLs & Per-Socket Auth Abuse]');

  test('3.1 Windows named pipe listen options enforce readableAll: false, writableAll: false', () => {
    const winOpts = extBridge.getBridgeListenOptions('\\\\.\\pipe\\fuin-ext-deadbeef', 'win32');
    assert.deepStrictEqual(winOpts, {
      path: '\\\\.\\pipe\\fuin-ext-deadbeef',
      readableAll: false,
      writableAll: false,
    });

    // Also verify startExtensionBridge passes exact options to net.Server.listen when platform === 'win32'
    const tmpRoot = makeShortTmpDir('fuin-iso-win32-');
    const origPlatformDesc = Object.getOwnPropertyDescriptor(process, 'platform');
    const origCreateServer = net.createServer;
    let capturedListenArg = null;
    try {
      const app = makeMockApp(tmpRoot);
      Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
      net.createServer = () => ({
        on: () => {},
        listen: (opts, cb) => {
          capturedListenArg = opts;
          if (typeof cb === 'function') cb();
        },
        close: () => {},
      });

      extBridge.startExtensionBridge({
        app,
        getMainWindow: () => null,
        getIsUnlocked: () => false,
        onActivity: () => {},
      });

      assert.ok(capturedListenArg && typeof capturedListenArg === 'object', 'win32 must pass listen options object');
      assert.ok(String(capturedListenArg.path).startsWith('\\\\.\\pipe\\fuin-ext-'), 'Must use HMAC-derived named pipe');
      assert.strictEqual(capturedListenArg.readableAll, false, 'win32 pipe must set readableAll: false');
      assert.strictEqual(capturedListenArg.writableAll, false, 'win32 pipe must set writableAll: false');
    } finally {
      extBridge.stopExtensionBridge();
      net.createServer = origCreateServer;
      Object.defineProperty(process, 'platform', origPlatformDesc);
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  if (process.platform !== 'win32') {
    await testAsync('3.2 startExtensionBridge unlinks symlinked socket safely without touching target, binds 0o600 socket, and rejects non-socket files', async () => {
      const tmpRoot = makeShortTmpDir('fuin-iso-sock-');
      try {
        const app = makeMockApp(tmpRoot);
        fs.mkdirSync(app._dirs.userDataDir, { recursive: true, mode: 0o755 });
        const socketPath = extBridge.getExtSocketPath(app);

        // Case A: regular file at socketPath -> must throw without deleting it
        fs.writeFileSync(socketPath, 'DO_NOT_DELETE');
        assert.throws(() => {
          extBridge.startExtensionBridge({
            app,
            getMainWindow: () => null,
            getIsUnlocked: () => false,
            onActivity: () => {},
          });
        }, /non-socket/i);
        assert.strictEqual(fs.readFileSync(socketPath, 'utf8'), 'DO_NOT_DELETE', 'Regular file must NOT be deleted');
        fs.unlinkSync(socketPath);

        // Case B: symlink at socketPath -> unlink only symlink, leave victim untouched, bind 0o600 socket
        const victimFile = path.join(tmpRoot, 'victim-sock-target.txt');
        fs.writeFileSync(victimFile, 'VICTIM_INTACT');
        fs.symlinkSync(victimFile, socketPath);

        extBridge.startExtensionBridge({
          app,
          getMainWindow: () => null,
          getIsUnlocked: () => false,
          onActivity: () => {},
        });

        for (let i = 0; i < 40; i++) {
          try {
            const st = fs.lstatSync(socketPath);
            if (st.isSocket() && (st.mode & 0o777) === 0o600) break;
          } catch {}
          await new Promise(r => setTimeout(r, 20));
        }

        assert.strictEqual(fs.readFileSync(victimFile, 'utf8'), 'VICTIM_INTACT', 'Symlink target must remain intact');
        const st = fs.lstatSync(socketPath);
        assert.strictEqual(st.isSymbolicLink(), false, 'Bound socket must not be a symlink');
        assert.strictEqual(st.isSocket(), true, 'Path must be a real Unix domain socket');
        assert.strictEqual(st.mode & 0o777, 0o600, 'POSIX socket must have 0o600 permissions');
        assert.strictEqual(fs.lstatSync(app._dirs.userDataDir).mode & 0o777, 0o700, 'Socket parent dir must be 0o700');
      } finally {
        extBridge.stopExtensionBridge();
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      }
    });

    await testAsync('3.3 startExtensionBridge destroys socket after 5 consecutive unauthorized attempts and resets counter on valid auth', async () => {
      const tmpRoot = makeShortTmpDir('fuin-iso-auth-');
      try {
        const app = makeMockApp(tmpRoot);
        const validToken = extBridge.getOrCreateExtToken(app);
        const socketPath = extBridge.getExtSocketPath(app);

        extBridge.startExtensionBridge({
          app,
          getMainWindow: () => null,
          getIsUnlocked: () => false,
          onActivity: () => {},
        });

        for (let i = 0; i < 40; i++) {
          try {
            if (fs.lstatSync(socketPath).isSocket()) break;
          } catch {}
          await new Promise(r => setTimeout(r, 20));
        }

        // Subtest A: 5 consecutive bad attempts -> 5 unauthorized replies then socket closes immediately
        const bruteResult = await new Promise((resolve, reject) => {
          const client = net.createConnection(socketPath);
          const replies = [];
          let buf = '';
          let closed = false;
          const timer = setTimeout(() => {
            client.destroy();
            reject(new Error('Timed out waiting for bridge to destroy abusive socket'));
          }, 4000);

          client.on('connect', () => {
            for (let i = 1; i <= 7; i++) {
              client.write(JSON.stringify({ id: `bad-${i}`, type: 'ping', token: 'wrong-token-' + i }) + '\n');
            }
          });
          client.on('data', (chunk) => {
            buf += chunk.toString('utf8');
            let nl;
            while ((nl = buf.indexOf('\n')) >= 0) {
              const line = buf.slice(0, nl).trim();
              buf = buf.slice(nl + 1);
              if (line) replies.push(JSON.parse(line));
            }
          });
          client.on('close', () => {
            closed = true;
            clearTimeout(timer);
            resolve({ replies, closed });
          });
          client.on('error', () => {});
        });

        assert.strictEqual(bruteResult.closed, true, 'Socket must be closed by server after 5 failed auth attempts');
        assert.strictEqual(bruteResult.replies.length, 5, `Expected exactly 5 unauthorized replies before teardown, got ${bruteResult.replies.length}`);
        for (const r of bruteResult.replies) {
          assert.strictEqual(r.error, 'unauthorized');
        }

        // Subtest B: Valid auth resets consecutive bad counter
        const resetResult = await new Promise((resolve, reject) => {
          const client = net.createConnection(socketPath);
          const replies = [];
          let buf = '';
          const queue = [
            { id: 'r1', type: 'ping', token: 'bad-1' },
            { id: 'r2', type: 'ping', token: 'bad-2' },
            { id: 'r3', type: 'ping', token: validToken },
            { id: 'r4', type: 'ping', token: 'bad-3' },
            { id: 'r5', type: 'ping', token: 'bad-4' },
            { id: 'r6', type: 'ping', token: 'bad-5' },
            { id: 'r7', type: 'ping', token: validToken },
          ];
          let idx = 0;
          const timer = setTimeout(() => {
            client.destroy();
            reject(new Error('Timed out during badAuthCount reset check'));
          }, 4000);

          const sendNext = () => {
            if (idx < queue.length) {
              client.write(JSON.stringify(queue[idx++]) + '\n');
            } else {
              clearTimeout(timer);
              client.end();
              resolve(replies);
            }
          };

          client.on('connect', sendNext);
          client.on('data', (chunk) => {
            buf += chunk.toString('utf8');
            let nl;
            while ((nl = buf.indexOf('\n')) >= 0) {
              const line = buf.slice(0, nl).trim();
              buf = buf.slice(nl + 1);
              if (line) {
                replies.push(JSON.parse(line));
                sendNext();
              }
            }
          });
          client.on('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
        });

        assert.strictEqual(resetResult.length, 7);
        assert.strictEqual(resetResult[2].ok, true);
        assert.strictEqual(resetResult[6].ok, true, 'Socket must remain usable when bad attempts are not 5 consecutive');
      } finally {
        extBridge.stopExtensionBridge();
        fs.rmSync(tmpRoot, { recursive: true, force: true });
      }
    });
  }

  // ── 4. Native Host POSIX SOCKET_PATH Symlink Defense ───────────────────────
  console.log('\n[4. Native Host SOCKET_PATH lstatSync Symlink & Socket Validation]');

  test('4.1 native-host/host.js preserves TOKEN_FILE lstatSync, Windows HMAC pipe, and adds SOCKET_PATH lstatSync', () => {
    const hostSrc = fs.readFileSync(path.join(__dirname, 'native-host', 'host.js'), 'utf8');
    assert.ok(hostSrc.includes('fs.lstatSync(TOKEN_FILE)'), 'Must preserve TOKEN_FILE lstatSync');
    assert.ok(hostSrc.includes('fuin-win32-pipe-v1'), 'Must preserve Windows HMAC pipe derivation');
    assert.ok(hostSrc.includes('fs.lstatSync(socketPath)'), 'Must inspect socketPath via lstatSync on POSIX');
    assert.ok(hostSrc.includes('sockStat.isSymbolicLink() || !sockStat.isSocket()'), 'Must reject symlinks and non-sockets');
  });

  if (process.platform !== 'win32') {
    await testAsync('4.2 native-host/host.js refuses symlinked socket (zero token leak to attacker socket) & regular files', async () => {
      const nhHome = makeShortTmpDir('fuin-nh-iso-');
      const nhUserData = process.platform === 'darwin'
        ? path.join(nhHome, 'Library', 'Application Support', 'Fuin')
        : path.join(nhHome, 'Fuin');
      fs.mkdirSync(nhUserData, { recursive: true, mode: 0o700 });

      const testToken = crypto.randomBytes(32).toString('hex');
      const tokenFile = path.join(nhUserData, 'fuin.ext-token');
      fs.writeFileSync(tokenFile, testToken, { mode: 0o600, encoding: 'utf8' });
      fs.chmodSync(tokenFile, 0o600);

      const sockPath = path.join(nhUserData, 'fuin-ext.sock');
      const attackerSock = path.join(nhHome, 'attacker.sock');
      let attackerConnections = 0;

      const attackerServer = net.createServer((conn) => {
        attackerConnections++;
        conn.end();
      });
      await new Promise((resolve) => attackerServer.listen(attackerSock, resolve));

      function callNativeHost(payloadObj) {
        return new Promise((resolve, reject) => {
          const child = spawn(process.execPath, [path.join(__dirname, 'native-host', 'host.js')], {
            env: { ...process.env, HOME: nhHome, XDG_CONFIG_HOME: nhHome }
          });
          let outBuf = Buffer.alloc(0);
          const timer = setTimeout(() => {
            try { child.kill(); } catch {}
            reject(new Error('native-host timed out'));
          }, 4000);
          child.stdout.on('data', (c) => {
            outBuf = Buffer.concat([outBuf, c]);
            if (outBuf.length >= 4) {
              const len = outBuf.readUInt32LE(0);
              if (outBuf.length >= 4 + len) {
                clearTimeout(timer);
                const resp = JSON.parse(outBuf.slice(4, 4 + len).toString('utf8'));
                child.stdin.end();
                resolve(resp);
              }
            }
          });
          child.on('error', (err) => { clearTimeout(timer); reject(err); });
          const body = Buffer.from(JSON.stringify(payloadObj), 'utf8');
          const hdr = Buffer.alloc(4);
          hdr.writeUInt32LE(body.length, 0);
          child.stdin.write(Buffer.concat([hdr, body]));
        });
      }

      try {
        // Attack A: Symlink fuin-ext.sock -> attacker.sock
        fs.symlinkSync(attackerSock, sockPath);
        const symRes = await callNativeHost({ type: 'ping' });
        assert.strictEqual(symRes.error, 'socket-path-invalid', 'Symlinked socket must fail closed with socket-path-invalid');
        assert.strictEqual(attackerConnections, 0, 'Attacker socket must NEVER receive a connection or token');
        fs.unlinkSync(sockPath);

        // Attack B: Regular file at fuin-ext.sock
        fs.writeFileSync(sockPath, 'not-a-socket', { mode: 0o600 });
        const fileRes = await callNativeHost({ type: 'ping' });
        assert.strictEqual(fileRes.error, 'socket-path-invalid', 'Regular file at socket path must fail closed');
        fs.unlinkSync(sockPath);

        // Legitimate socket at fuin-ext.sock
        const legitServer = net.createServer((conn) => {
          let b = '';
          conn.on('data', (chunk) => {
            b += chunk.toString('utf8');
            const nl = b.indexOf('\n');
            if (nl >= 0) {
              const parsed = JSON.parse(b.slice(0, nl));
              conn.write(JSON.stringify({ id: parsed.id, ok: true, pong: true }) + '\n');
            }
          });
        });
        await new Promise((resolve) => legitServer.listen(sockPath, resolve));
        try {
          const okRes = await callNativeHost({ type: 'ping' });
          assert.strictEqual(okRes.ok, true);
          assert.strictEqual(okRes.pong, true);
        } finally {
          await new Promise((resolve) => legitServer.close(resolve));
        }
      } finally {
        await new Promise((resolve) => attackerServer.close(resolve));
        fs.rmSync(nhHome, { recursive: true, force: true });
      }
    });
  }

  // ── 5. main.js BrowserWindow Isolation, CSP/Security Headers & userData 0o700
  console.log('\n[5. main.js BrowserWindow Isolation, CSP/Headers & userData Startup Hardening]');

  test('5.1 Static audit of EVERY new BrowserWindow(...) call in main.js enforces full sandbox & isolation flags', () => {
    const mainSrc = fs.readFileSync(path.join(__dirname, 'main.js'), 'utf8');
    const bwMatches = [...mainSrc.matchAll(/new\s+BrowserWindow\s*\(/g)];
    assert.ok(bwMatches.length >= 1, 'main.js must create at least one BrowserWindow');

    for (const m of bwMatches) {
      const slice = mainSrc.slice(m.index, m.index + 650);
      for (const reqFlag of [
        'nodeIntegration: false',
        'contextIsolation: true',
        'sandbox: true',
        'webSecurity: true',
        'allowRunningInsecureContent: false',
        'webviewTag: false',
        'navigateOnDragDrop: false',
      ]) {
        assert.ok(slice.includes(reqFlag), `BrowserWindow at offset ${m.index} missing ${reqFlag}`);
      }
    }

    assert.ok(mainSrc.includes('mainWindow.setContentProtection(!allowDevScreenshots)'), 'Must enforce setContentProtection(!allowDevScreenshots)');
    assert.ok(mainSrc.includes("'will-navigate'"), 'Must block will-navigate');
    assert.ok(mainSrc.includes("'will-redirect'"), 'Must block will-redirect');
    assert.ok(mainSrc.includes("'will-attach-webview'"), 'Must block will-attach-webview');
    assert.ok(mainSrc.includes("setWindowOpenHandler?.(() => ({ action: 'deny' }))"), 'Must deny window open handler');
  });

  await testAsync('5.2 Runtime startup of main.js enforces userData 0o700, BrowserWindow webPreferences, navigation guards & CSP/headers', async () => {
    const tmpRoot = makeShortTmpDir('fuin-iso-main-');
    const mockApp = makeMockApp(tmpRoot);
    fs.mkdirSync(mockApp._dirs.userDataDir, { recursive: true, mode: 0o755 });
    if (process.platform !== 'win32') {
      fs.chmodSync(mockApp._dirs.userDataDir, 0o755);
    }

    const captured = {
      bwOptions: [],
      contentProtectionCalls: [],
      wcEvents: {},
      windowOpenHandler: null,
      permRequestHandler: null,
      permCheckHandler: null,
      headersHandler: null,
      appEvents: {},
    };

    const origRequire = Module.prototype.require;
    const mainResolved = require.resolve('./main.js');
    delete require.cache[mainResolved];

    const prevDevEnv = process.env.FUIN_DEV_SCREENSHOTS;
    delete process.env.FUIN_DEV_SCREENSHOTS;

    Module.prototype.require = function (id) {
      if (id === 'electron') {
        return {
          app: {
            getPath: (name) => mockApp.getPath(name),
            getVersion: () => '1.0.0-test',
            isPackaged: false,
            setAppUserModelId: () => {},
            quit: () => {},
            whenReady: () => Promise.resolve(),
            on: (ev, fn) => { captured.appEvents[ev] = fn; },
          },
          session: {
            defaultSession: {
              setPermissionRequestHandler: (fn) => { captured.permRequestHandler = fn; },
              setPermissionCheckHandler: (fn) => { captured.permCheckHandler = fn; },
              webRequest: {
                onHeadersReceived: (fn) => { captured.headersHandler = fn; },
              },
            },
          },
          BrowserWindow: class {
            constructor(opts) {
              captured.bwOptions.push(opts);
              return {
                webContents: {
                  send: () => {},
                  on: (ev, fn) => { captured.wcEvents[ev] = fn; },
                  setWindowOpenHandler: (fn) => { captured.windowOpenHandler = fn; },
                },
                on: () => {},
                setContentProtection: (val) => { captured.contentProtectionCalls.push(val); },
                loadFile: () => {},
                show: () => {},
                hide: () => {},
                isVisible: () => true,
                isDestroyed: () => false,
              };
            }
          },
          ipcMain: { handle: () => {}, on: () => {} },
          dialog: {},
          clipboard: { writeText: () => {}, readText: () => '' },
          powerMonitor: { on: () => {}, getSystemIdleTime: () => 0 },
          shell: { openPath: async () => '', openExternal: () => {} },
          Tray: class {
            setToolTip() {}
            popUpContextMenu() {}
            setContextMenu() {}
            on() {}
          },
          Menu: { buildFromTemplate: () => ({}) },
          nativeImage: { createFromPath: () => ({ resize: () => ({}) }) },
          systemPreferences: { canPromptTouchID: () => false },
          safeStorage: { isEncryptionAvailable: () => false },
          Notification: class { static isSupported() { return false; } show() {} },
        };
      }
      return origRequire.apply(this, arguments);
    };

    try {
      require('./main.js');
      // Wait for whenReady microtasks to settle
      await new Promise(r => setTimeout(r, 80));

      // 1. userData tightened to 0o700 on POSIX
      if (process.platform !== 'win32') {
        const mode = fs.lstatSync(mockApp._dirs.userDataDir).mode & 0o777;
        assert.strictEqual(mode, 0o700, `Expected userData 0o700 after startup, got 0o${mode.toString(8)}`);
      }

      // 2. BrowserWindow runtime options
      assert.strictEqual(captured.bwOptions.length, 1, 'Expected mainWindow creation');
      const wp = captured.bwOptions[0].webPreferences;
      assert.strictEqual(wp.nodeIntegration, false);
      assert.strictEqual(wp.contextIsolation, true);
      assert.strictEqual(wp.sandbox, true);
      assert.strictEqual(wp.webSecurity, true);
      assert.strictEqual(wp.allowRunningInsecureContent, false);
      assert.strictEqual(wp.webviewTag, false);
      assert.strictEqual(wp.navigateOnDragDrop, false);

      // 3. Screen protection & navigation/popup/permission blocks
      assert.deepStrictEqual(captured.contentProtectionCalls, [true], 'setContentProtection(true) must be enabled by default');
      assert.strictEqual(typeof captured.wcEvents['will-navigate'], 'function');
      assert.strictEqual(typeof captured.wcEvents['will-redirect'], 'function');
      assert.strictEqual(typeof captured.wcEvents['will-attach-webview'], 'function');
      for (const evName of ['will-navigate', 'will-redirect', 'will-attach-webview']) {
        let prevented = false;
        captured.wcEvents[evName]({ preventDefault: () => { prevented = true; } });
        assert.strictEqual(prevented, true, `${evName} must call preventDefault()`);
      }
      assert.deepStrictEqual(captured.windowOpenHandler({ url: 'https://evil.example' }), { action: 'deny' });

      let permAllowed = null;
      captured.permRequestHandler({}, 'media', (allow) => { permAllowed = allow; });
      assert.strictEqual(permAllowed, false, 'Permission requests must be denied');
      assert.strictEqual(captured.permCheckHandler(), false, 'Permission checks must return false');

      // 4. CSP & security headers on local file:// renderer load
      assert.strictEqual(typeof captured.headersHandler, 'function', 'onHeadersReceived must be registered');
      let localRes = null;
      captured.headersHandler(
        { url: 'file:///Applications/Fuin.app/renderer/index.html', responseHeaders: {} },
        (res) => { localRes = res; }
      );
      assert.ok(localRes && localRes.responseHeaders, 'Must return responseHeaders for file://');
      assert.deepStrictEqual(localRes.responseHeaders['X-Content-Type-Options'], ['nosniff']);
      assert.deepStrictEqual(localRes.responseHeaders['X-Frame-Options'], ['DENY']);
      const csp = (localRes.responseHeaders['Content-Security-Policy'] || [])[0] || '';
      for (const directive of [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        'connect-src https://api.github.com https://api.pwnedpasswords.com',
        "object-src 'none'",
        "base-uri 'self'",
        "frame-ancestors 'none'",
        "form-action 'none'",
      ]) {
        assert.ok(csp.includes(directive), `Renderer CSP missing directive: ${directive}`);
      }

      // 5. Remote API fetch headers (GitHub / HIBP) are preserved cleanly without breaking
      let apiRes = null;
      captured.headersHandler(
        {
          url: 'https://api.pwnedpasswords.com/range/21BD1',
          responseHeaders: { 'content-type': ['text/plain'], 'x-content-type-options': ['nosniff'] }
        },
        (res) => { apiRes = res; }
      );
      assert.deepStrictEqual(apiRes.responseHeaders['content-type'], ['text/plain']);
      assert.strictEqual(apiRes.responseHeaders['X-Frame-Options'], undefined, 'Remote API fetch should not get local X-Frame-Options override');
      assert.strictEqual(apiRes.responseHeaders['X-Content-Type-Options'], undefined, 'Should not duplicate existing lowercase x-content-type-options');
    } finally {
      extBridge.stopExtensionBridge();
      Module.prototype.require = origRequire;
      delete require.cache[mainResolved];
      if (prevDevEnv !== undefined) process.env.FUIN_DEV_SCREENSHOTS = prevDevEnv;
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    }
  });

  console.log('\n══════════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL ISOLATION HARDENING CHECKS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${failedTests}`);
  console.log('══════════════════════════════════════════════════════════════════════════════');
  if (failedTests > 0) {
    process.exit(1);
  }
  console.log('\nALL LOCAL ISOLATION & BOUNDARY HARDENING CHECKS PASSED (100%)!\n');
}

runAll().catch((err) => {
  console.error(err);
  process.exit(1);
});
