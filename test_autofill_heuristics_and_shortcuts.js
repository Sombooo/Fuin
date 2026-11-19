'use strict';

/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN TEST: AUTOFILL PHASE 1 HEURISTICS, SHORTCUTS & EXTENSION MANAGER
 * test_autofill_heuristics_and_shortcuts.js
 * ═══════════════════════════════════════════════════════════════════════════════
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const vm = require('vm');

let passed = 0;
let failed = 0;

function report(name, ok, details = '') {
  if (ok) {
    passed++;
    console.log(`  ✓ [PASS] ${name}${details ? ` (${details})` : ''}`);
  } else {
    failed++;
    console.error(`  ✗ [FAIL] ${name} ${details}`);
  }
}

console.log('═══════════════════════════════════════════════════════════════════════════');
console.log('FUIN TEST: AUTOFILL PHASE 1 (SPLIT LOGIN, SHORTCUTS & IN-APP REGISTRATION)');
console.log('═══════════════════════════════════════════════════════════════════════════\n');

// ── 1. MANIFEST & KEYBOARD SHORTCUT AUDIT ─────────────────────────────────────
console.log('[1. Manifest & Keyboard Shortcut Audit]');

const manifestPath = path.join(__dirname, 'browser-extension/manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

report('1.1 Manifest defines commands.autofill-credential', Boolean(manifest.commands?.['autofill-credential']));
report('1.2 Default shortcut is Ctrl+Shift+L', manifest.commands?.['autofill-credential']?.suggested_key?.default === 'Ctrl+Shift+L');
report('1.3 macOS shortcut is Command+Shift+L', manifest.commands?.['autofill-credential']?.suggested_key?.mac === 'Command+Shift+L');

const bgJs = fs.readFileSync(path.join(__dirname, 'browser-extension/background.js'), 'utf8');
report('1.4 background.js binds chrome.commands listener to fuin-trigger-fill',
  bgJs.includes("command === 'autofill-credential'") && bgJs.includes("{ type: 'fuin-trigger-fill' }"));

// ── 2. SPLIT LOGIN HEURISTICS & SHADOW DOM ───────────────────────────────────
console.log('\n[2. Split Login Heuristics & Shadow DOM Encapsulation]');

const contentJs = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');

report('2.1 content.js implements split-login detection (findStandaloneUsernameFields)',
  contentJs.includes('findStandaloneUsernameFields()'));

report('2.2 content.js inspects username, email, identifier, login attributes',
  contentJs.includes('autocomplete.includes(\'username\')') && contentJs.includes('idNameRegex.test'));

report('2.3 content.js applies Fuin Warm Dark palette tokens (#222019, #3d3830, #5a9a6e)',
  contentJs.includes('#222019') && contentJs.includes('#3d3830') && contentJs.includes('#5a9a6e'));

report('2.4 content.js strictly maintains closed Shadow DOM boundary',
  contentJs.includes("attachShadow({ mode: 'closed' })") && !contentJs.includes("attachShadow({ mode: 'open' })"));

// ── 3. IN-APP CHROME EXTENSION REGISTRATION ──────────────────────────────────
console.log('\n[3. Desktop In-App Extension Manager & Origin Registration]');

const extBridge = require('./main/extensionBridge.js');

// Mock electron app for testing in isolated os.tmpdir
const os = require('os');
const mockSandboxDir = path.join(os.tmpdir(), `fuin-autofill-test-${Date.now()}`);
if (!fs.existsSync(mockSandboxDir)) fs.mkdirSync(mockSandboxDir, { recursive: true });

const mockApp = {
  getPath: (name) => path.join(mockSandboxDir, name),
};

try {
  // Test invalid extension ID formats
  const inv1 = extBridge.registerChromeOrigin(mockApp, '');
  report('3.1 Rejects empty extension ID', inv1.ok === false && inv1.error === 'invalid-id');

  const inv2 = extBridge.registerChromeOrigin(mockApp, 'ABCDEF');
  report('3.2 Rejects short or uppercase extension ID', inv2.ok === false && inv2.error === 'invalid-format');

  const inv3 = extBridge.registerChromeOrigin(mockApp, '12345678901234567890123456789012');
  report('3.3 Rejects non-alphabetic characters (outside a-p)', inv3.ok === false && inv3.error === 'invalid-format');

  // Test valid 32-char extension ID
  const validId = 'abcdefghijklmnopabcdefghijklmnop';
  const regRes = extBridge.registerChromeOrigin(mockApp, validId);
  report('3.4 Successfully registers valid 32-char extension ID', regRes.ok === true && regRes.origin === `chrome-extension://${validId}/`);

  const known = extBridge.getKnownExtensionIds(mockApp);
  report('3.5 getKnownExtensionIds loads persistent registered origin', known.chromeOrigins.includes(`chrome-extension://${validId}/`));
} finally {
  try {
    fs.rmSync(mockSandboxDir, { recursive: true, force: true });
  } catch {}
}

// ── 4. NATIVE HOST STDIO FIELD-WHITELIST & SAVE PAYLOAD INTEGRITY ────────────
console.log('\n[4. Native Host Stdio Framing & Save Credential Field Integrity]');

async function runNativeHostAndSuppressionTests() {
  if (process.platform !== 'win32') {
    const net = require('net');
    const crypto = require('crypto');
    const { spawn } = require('child_process');

    const shortTmpBase = fs.existsSync('/tmp') ? '/tmp' : os.tmpdir();
    const nhHome = fs.mkdtempSync(path.join(shortTmpBase, 'fuin-nh-'));
    const nhUserData = process.platform === 'darwin'
      ? path.join(nhHome, 'Library', 'Application Support', 'Fuin')
      : path.join(nhHome, 'Fuin');
    fs.mkdirSync(nhUserData, { recursive: true, mode: 0o700 });

    const testToken = crypto.randomBytes(32).toString('hex');
    const tokenFile = path.join(nhUserData, 'fuin.ext-token');
    fs.writeFileSync(tokenFile, testToken, { mode: 0o600, encoding: 'utf8' });
    fs.chmodSync(tokenFile, 0o600);

    const sockFile = path.join(nhUserData, 'fuin-ext.sock');
    const receivedPayloads = [];

    const mockServer = net.createServer((conn) => {
      let dataBuf = '';
      conn.on('data', (chunk) => {
        dataBuf += chunk.toString('utf8');
        const nl = dataBuf.indexOf('\n');
        if (nl >= 0) {
          const parsed = JSON.parse(dataBuf.slice(0, nl));
          receivedPayloads.push(parsed);
          conn.write(JSON.stringify({ ok: true, echoedType: parsed.type }) + '\n');
        }
      });
    });

    await new Promise((resolve) => mockServer.listen(sockFile, resolve));

    function sendViaNativeHost(inputObj) {
      return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [path.join(__dirname, 'native-host/host.js')], {
          env: { ...process.env, HOME: nhHome, XDG_CONFIG_HOME: nhHome }
        });
        let outBuf = Buffer.alloc(0);
        child.stdout.on('data', (c) => {
          outBuf = Buffer.concat([outBuf, c]);
          if (outBuf.length >= 4) {
            const len = outBuf.readUInt32LE(0);
            if (outBuf.length >= 4 + len) {
              const resp = JSON.parse(outBuf.slice(4, 4 + len).toString('utf8'));
              child.stdin.end();
              resolve(resp);
            }
          }
        });
        child.on('error', reject);
        const body = Buffer.from(JSON.stringify(inputObj), 'utf8');
        const header = Buffer.alloc(4);
        header.writeUInt32LE(body.length, 0);
        child.stdin.write(Buffer.concat([header, body]));
      });
    }

    try {
      await sendViaNativeHost({
        type: 'save-credential',
        domain: 'chess.com',
        username: 'magnus@chess.com',
        password: 'GrandmasterPassword!99',
        updateEntryId: 'entry-123',
        injectedEvilField: 'must-be-stripped'
      });

      const savedMsg = receivedPayloads[0];
      report('4.1 native-host preserves domain, username, password, updateEntryId on save-credential',
        savedMsg &&
        savedMsg.type === 'save-credential' &&
        savedMsg.domain === 'chess.com' &&
        savedMsg.username === 'magnus@chess.com' &&
        savedMsg.password === 'GrandmasterPassword!99' &&
        savedMsg.updateEntryId === 'entry-123');
      report('4.2 native-host strips non-whitelisted fields on save-credential',
        savedMsg && savedMsg.injectedEvilField === undefined);

      await sendViaNativeHost({
        type: 'check-save-candidate',
        domain: 'chess.com',
        username: 'magnus@chess.com',
        password: 'GrandmasterPassword!99'
      });
      const checkMsg = receivedPayloads[1];
      report('4.3 native-host preserves domain, username, password on check-save-candidate',
        checkMsg &&
        checkMsg.type === 'check-save-candidate' &&
        checkMsg.domain === 'chess.com' &&
        checkMsg.username === 'magnus@chess.com' &&
        checkMsg.password === 'GrandmasterPassword!99');

      await sendViaNativeHost({
        type: 'exclude-domain',
        domain: 'chess.com'
      });
      const exclMsg = receivedPayloads[2];
      report('4.4 native-host preserves domain on exclude-domain',
        exclMsg && exclMsg.type === 'exclude-domain' && exclMsg.domain === 'chess.com');
    } finally {
      await new Promise((resolve) => mockServer.close(resolve));
      fs.rmSync(nhHome, { recursive: true, force: true });
    }
  }

  // ── 5. SAVE PROMPT SUPPRESSION ("NOT NOW" & "NEVER") + SUBMIT HEURISTICS ───
  console.log('\n[5. Save Prompt Suppression & Strict Submit Heuristics]');

  report('5.1 content.js removes over-broad [class*="login"] click selector',
    !contentJs.includes('[class*="login"]'));
  report('5.2 content.js implements strict isLikelySubmitControl & markLocalDismissed',
    contentJs.includes('function isLikelySubmitControl') && contentJs.includes('function markLocalDismissed'));
  report('5.3 content.js supports "Bu Sitede Asla" (fuin-exclude-domain) & fuin-close-save-prompt',
    contentJs.includes("type: 'fuin-exclude-domain'") && contentJs.includes("msg.type === 'fuin-close-save-prompt'"));
  report('5.9 content.js avoids injecting visible inline icons over password eye buttons',
    !contentJs.includes('fuin-ext-icon') && !contentJs.includes('findLoginForms().forEach(injectIcon)'));

  // Execute background.js in VM sandbox to verify session dismissal & domain exclusion
  let onMessageHandler = null;
  const nativeCalls = [];
  const sentTabMessages = [];

  const sandbox = {
    console,
    URL,
    Date,
    Map,
    Set,
    Promise,
    setTimeout,
    clearTimeout,
    chrome: {
      runtime: {
        id: 'abcdefghijklmnopabcdefghijklmnop',
        lastError: null,
        sendNativeMessage: (host, payload, cb) => {
          nativeCalls.push(payload);
          if (payload.type === 'check-save-candidate') {
            cb({ shouldPrompt: true, action: 'save', username: payload.username });
          } else {
            cb({ ok: true });
          }
        },
        onMessage: {
          addListener: (fn) => { onMessageHandler = fn; }
        }
      },
      tabs: {
        onUpdated: { addListener: () => {} },
        onRemoved: { addListener: () => {} },
        query: () => {},
        sendMessage: (tabId, msg, cb) => {
          sentTabMessages.push({ tabId, msg });
          if (cb) cb();
        }
      },
      action: {
        setBadgeText: () => {},
        setBadgeBackgroundColor: () => {}
      },
      commands: {
        onCommand: { addListener: () => {} }
      }
    }
  };

  vm.runInNewContext(bgJs, sandbox);

  const tabSender = {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    frameId: 0,
    url: 'https://www.chess.com/login',
    tab: { id: 42, url: 'https://www.chess.com/login' }
  };

  function sendTabMsg(msg) {
    return new Promise((resolve) => {
      onMessageHandler(msg, tabSender, resolve);
    });
  }

  const sub1 = await sendTabMsg({ type: 'fuin-form-submitted', username: 'user1@chess.com', password: 'WrongPassword1!' });
  report('5.4 Initial form submit triggers save prompt candidate',
    sub1 && sub1.shouldPrompt === true && sentTabMessages.length === 1);

  await sendTabMsg({ type: 'fuin-dismiss-save', username: 'user1@chess.com', password: 'WrongPassword1!' });

  const sub2 = await sendTabMsg({ type: 'fuin-form-submitted', username: 'user1@chess.com', password: 'WrongPassword1!' });
  report('5.5 After "Şimdi Değil" (fuin-dismiss-save), same password does NOT re-prompt',
    sub2 && sub2.shouldPrompt === false && sub2.dismissed === true && sentTabMessages.length === 1);

  const pendingAfterDismiss = await sendTabMsg({ type: 'fuin-get-pending-save' });
  report('5.6 fuin-get-pending-save returns hasPending: false after dismissal',
    pendingAfterDismiss && pendingAfterDismiss.hasPending === false);

  const sub3 = await sendTabMsg({ type: 'fuin-form-submitted', username: 'user1@chess.com', password: 'DifferentPassword2!' });
  report('5.7 Submitting a different password on same domain prompts cleanly',
    sub3 && sub3.shouldPrompt === true && sentTabMessages.length === 2);

  await sendTabMsg({ type: 'fuin-exclude-domain' });
  const sub4 = await sendTabMsg({ type: 'fuin-form-submitted', username: 'newuser@chess.com', password: 'BrandNewPassword3!' });
  report('5.8 After "Bu Sitede Asla" (fuin-exclude-domain), all future prompts on domain are suppressed',
    sub4 && sub4.shouldPrompt === false && sub4.dismissed === true && nativeCalls.some(c => c.type === 'exclude-domain'));

  // Test 5.10: Cross-page split-login username staging (Step 1 username -> Step 2 password)
  const splitSender = {
    id: 'abcdefghijklmnopabcdefghijklmnop',
    frameId: 0,
    url: 'https://accounts.google.com/v3/signin/identifier',
    tab: { id: 77, url: 'https://accounts.google.com/v3/signin/identifier' }
  };
  function sendSplitMsg(msg) {
    return new Promise((resolve) => {
      onMessageHandler(msg, splitSender, resolve);
    });
  }
  const stageRes = await sendSplitMsg({ type: 'fuin-stage-username', username: 'kadir@example.com' });
  splitSender.url = 'https://accounts.google.com/v3/signin/challenge/pwd';
  splitSender.tab.url = 'https://accounts.google.com/v3/signin/challenge/pwd';
  const step2Res = await sendSplitMsg({ type: 'fuin-form-submitted', username: '', password: 'SplitLoginPass!42' });
  report('5.10 Multi-page split login merges Step-1 staged username into Step-2 password submit',
    stageRes && stageRes.ok === true && step2Res && step2Res.shouldPrompt === true && step2Res.username === 'kadir@example.com');

  // Test 5.11: Multi-password field selection (Change Password / Registration forms)
  report('5.11 content.js implements pickBestFilledPasswordInput for Change Password / Signup forms',
    contentJs.includes('function pickBestFilledPasswordInput') && contentJs.includes("ac.includes('new-password')"));

  // Test 5.12: Firefox MV3 compatibility (sender.tab.url undefined, tab.url undefined on onUpdated, and in-flight race)
  let ffOnMsg = null;
  let ffOnTabUpdated = null;
  const ffTabMessages = [];
  const ffSandbox = {
    console, URL, Date, Map, Set, Promise, setTimeout, clearTimeout,
    browser: {
      runtime: {
        id: 'fuin-app@sombo.dev',
        sendNativeMessage: (_host, payload) => {
          if (payload.type === 'check-save-candidate') {
            return new Promise((resolve) => {
              setTimeout(() => resolve({ shouldPrompt: true, action: 'save', username: payload.username }), 35);
            });
          }
          return Promise.resolve({ ok: true });
        }
      },
      tabs: {
        sendMessage: (tabId, msg) => {
          ffTabMessages.push({ tabId, msg });
          return Promise.resolve({ ok: true });
        }
      },
      action: {
        setBadgeText: () => {},
        setBadgeBackgroundColor: () => {}
      }
    },
    chrome: {
      runtime: {
        id: 'fuin-app@sombo.dev',
        lastError: null,
        onMessage: { addListener: (fn) => { ffOnMsg = fn; } }
      },
      tabs: {
        onUpdated: { addListener: (fn) => { ffOnTabUpdated = fn; } },
        onRemoved: { addListener: () => {} }
      },
      action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
      commands: { onCommand: { addListener: () => {} } }
    }
  };
  vm.runInNewContext(bgJs, ffSandbox);

  const sendFromFirefoxTab = (url, msg, tabId = 88) => new Promise((resolve) => {
    ffOnMsg(msg, { id: 'fuin-app@sombo.dev', frameId: 0, url, tab: { id: tabId } }, resolve);
  });

  // Trigger submit and immediately query fuin-get-pending-save before the 35ms native host delay resolves
  const ffSubmitPromise = sendFromFirefoxTab('https://accounts.example.com/signin', {
    type: 'fuin-form-submitted',
    username: 'kadir@example.com',
    password: 'FirefoxTestPassword!1'
  }, 88);
  const ffRacePending = await sendFromFirefoxTab('https://accounts.example.com/dashboard', {
    type: 'fuin-get-pending-save'
  }, 88);
  const ffSubmitRes = await ffSubmitPromise;
  ffTabMessages.length = 0;
  ffOnTabUpdated(88, { status: 'complete' }, { id: 88 });
  const ffAfterUpdatedPending = await sendFromFirefoxTab('https://accounts.example.com/home', {
    type: 'fuin-get-pending-save'
  }, 88);
  const ffCrossSiteLeak = await sendFromFirefoxTab('https://evil-attacker.com/', {
    type: 'fuin-get-pending-save'
  }, 88);
  const ffAfterCrossSiteScrub = await sendFromFirefoxTab('https://accounts.example.com/home', {
    type: 'fuin-get-pending-save'
  }, 88);

  report('5.12 Firefox MV3 sender.tab.url undefined works for submit, race-condition get-pending-save & onUpdated',
    ffSubmitRes && ffSubmitRes.shouldPrompt === true &&
    ffRacePending && ffRacePending.hasPending === true &&
    ffTabMessages.length === 1 &&
    ffAfterUpdatedPending && ffAfterUpdatedPending.hasPending === true);

  report('5.13 Firefox MV3 cross-site navigation scrubs pending credential even when tab.url is undefined',
    ffCrossSiteLeak && ffCrossSiteLeak.hasPending === false &&
    ffAfterCrossSiteScrub && ffAfterCrossSiteScrub.hasPending === false);

  // Test 5.14: Turkish field & submit button heuristics + OAuth exclusion precision
  const idRegexLiteral = contentJs.match(/const idNameRegex = (\/.*\/[gimsuy]*);/);
  const nonSubmitLiteral = contentJs.match(/const nonSubmitRegex = (\/.*\/[gimsuy]*);/);
  const posSubmitLiteral = contentJs.match(/const positiveSubmitRegex = (\/.*\/[gimsuy]*);/);
  const idRe = idRegexLiteral ? vm.runInNewContext(idRegexLiteral[1]) : null;
  const nonSubRe = nonSubmitLiteral ? vm.runInNewContext(nonSubmitLiteral[1]) : null;
  const posSubRe = posSubmitLiteral ? vm.runInNewContext(posSubmitLiteral[1]) : null;

  report('5.14 Turkish identifier & button heuristics match E-posta, Kullanıcı Adı, İleri and preserve GitHub login',
    Boolean(idRe && nonSubRe && posSubRe) &&
    idRe.test('E-posta') &&
    idRe.test('Kullanıcı Adı') &&
    posSubRe.test('İleri') &&
    posSubRe.test('Kaydet') &&
    !nonSubRe.test('Sign in to GitHub') &&
    posSubRe.test('Sign in to GitHub') &&
    nonSubRe.test('Continue with Google') &&
    nonSubRe.test('Google ile devam'));

  // Test 5.15: Runtime VM execution of content.js (no TDZ crash, captures submit & mounts closed Shadow DOM save prompt)
  const docListeners = {};
  const winListeners = {};
  const bodyChildren = [];
  const shadowModes = [];
  const runtimeMessagesSent = [];

  function makeMockNode(tagName, attrs = {}) {
    const node = {
      tagName: tagName.toUpperCase(),
      type: attrs.type || '',
      name: attrs.name || '',
      id: attrs.id || '',
      value: attrs.value || '',
      textContent: attrs.textContent || '',
      style: {},
      children: [],
      parentNode: null,
      parentElement: null,
      isConnected: true,
      _attrs: { ...attrs },
      setAttribute(k, v) { this._attrs[k] = String(v); },
      getAttribute(k) { return this._attrs[k] !== undefined ? String(this._attrs[k]) : null; },
      getBoundingClientRect() { return { width: 200, height: 36, top: 10, left: 10, bottom: 46, right: 210 }; },
      addEventListener() {},
      removeEventListener() {},
      appendChild(child) {
        child.parentNode = this;
        child.parentElement = this;
        child.isConnected = this.isConnected;
        this.children.push(child);
        return child;
      },
      replaceChildren(...nodes) {
        this.children = [];
        nodes.forEach(n => this.appendChild(n));
      },
      remove() {
        this.isConnected = false;
        const idx = bodyChildren.indexOf(this);
        if (idx >= 0) bodyChildren.splice(idx, 1);
      },
      contains(target) {
        if (target === this) return true;
        return this.children.some(c => c.contains && c.contains(target));
      },
      closest(sel) {
        if (sel.includes('form') && formEl.contains(this)) return formEl;
        if (sel.includes('button') && (this.tagName === 'BUTTON' || this.tagName === 'INPUT')) return this;
        return null;
      },
      querySelector(sel) {
        return this.querySelectorAll(sel)[0] || null;
      },
      querySelectorAll(sel) {
        const list = [];
        const walk = (n) => {
          for (const ch of (n.children || [])) {
            if (sel.includes('password') && ch.type === 'password') list.push(ch);
            else if (sel === 'input' && ch.tagName === 'INPUT') list.push(ch);
            else if (sel.includes('input[type="email"]') && ch.tagName === 'INPUT' && ch.type !== 'password') list.push(ch);
            walk(ch);
          }
        };
        walk(this);
        return list;
      },
      attachShadow(opts) {
        shadowModes.push(opts?.mode);
        const root = makeMockNode('#shadow-root');
        root.host = this;
        return root;
      }
    };
    return node;
  }

  const formEl = makeMockNode('form');
  const userInputEl = makeMockNode('input', { type: 'text', name: 'login', id: 'login_field', autocomplete: 'username' });
  const pwInputEl = makeMockNode('input', { type: 'password', name: 'password', id: 'password' });
  const submitBtnEl = makeMockNode('button', { type: 'submit', textContent: 'Sign in' });
  formEl.appendChild(userInputEl);
  formEl.appendChild(pwInputEl);
  formEl.appendChild(submitBtnEl);

  const mockBody = makeMockNode('body');
  mockBody.appendChild(formEl);
  const origAppend = mockBody.appendChild.bind(mockBody);
  mockBody.appendChild = (ch) => {
    bodyChildren.push(ch);
    return origAppend(ch);
  };
  const mockDocEl = makeMockNode('html');
  mockDocEl.appendChild(mockBody);

  let contentBootError = null;
  const contentSandbox = {
    window: {
      addEventListener: (ev, fn) => {
        if (!winListeners[ev]) winListeners[ev] = [];
        winListeners[ev].push(fn);
      },
      removeEventListener: () => {}
    },
    document: {
      documentElement: mockDocEl,
      body: mockBody,
      activeElement: null,
      addEventListener: (ev, fn) => {
        if (!docListeners[ev]) docListeners[ev] = [];
        docListeners[ev].push(fn);
      },
      removeEventListener: () => {},
      querySelectorAll: (sel) => mockDocEl.querySelectorAll(sel),
      createElement: (tag) => makeMockNode(tag),
      createElementNS: (_ns, tag) => makeMockNode(tag)
    },
    MutationObserver: class { observe() {} },
    WeakSet, WeakMap, Set, Map, Date, Object, Array, String, Number, Boolean, Promise, RegExp, Math,
    setTimeout, clearTimeout, navigator: { language: 'tr-TR' },
    location: { protocol: 'https:', hostname: 'github.com' },
    chrome: {
      i18n: { getUILanguage: () => 'tr' },
      runtime: {
        lastError: null,
        onMessage: { addListener: () => {} },
        sendMessage: (payload, cb) => {
          runtimeMessagesSent.push(payload);
          if (payload.type === 'fuin-get-pending-save') {
            if (cb) cb({ hasPending: false });
          } else if (payload.type === 'fuin-form-submitted') {
            if (cb) cb({ shouldPrompt: true, action: 'save', username: payload.username });
          } else if (cb) {
            cb({ ok: true });
          }
        }
      }
    }
  };

  try {
    vm.runInNewContext(contentJs, contentSandbox);
    userInputEl.value = 'kadir@example.com';
    (docListeners.input || []).forEach(fn => fn({ isTrusted: true, target: userInputEl }));
    pwInputEl.value = 'RealLoginPass!9';
    (docListeners.input || []).forEach(fn => fn({ isTrusted: true, target: pwInputEl }));
    (winListeners.click || []).forEach(fn => fn({ isTrusted: true, target: submitBtnEl }));
    await new Promise(r => setTimeout(r, 20));
  } catch (err) {
    contentBootError = err;
  }

  const submittedMsg = runtimeMessagesSent.find(m => m.type === 'fuin-form-submitted');
  const promptMounted = bodyChildren.some(el => el.tagName === 'FUIN-SAVE-PROMPT');
  report('5.15 Runtime content.js boots cleanly without TDZ error, captures submit, and mounts closed Shadow DOM save prompt',
    !contentBootError &&
    submittedMsg && submittedMsg.username === 'kadir@example.com' && submittedMsg.password === 'RealLoginPass!9' &&
    promptMounted && shadowModes.includes('closed'));

  console.log('\n═══════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL AUDIT CHECKS: ${passed + failed} | PASSED: ${passed} | FAILED: ${failed}`);
  console.log('═══════════════════════════════════════════════════════════════════════════');

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\nALL AUTOFILL SPECIFICATION & SAVE-PROMPT SUPPRESSION CHECKS PASSED CLEANLY!\n');
    process.exit(0);
  }
}

runNativeHostAndSuppressionTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
