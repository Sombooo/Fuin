'use strict';

/**
 * FUIN DESKTOP — CHANGE MASTER PASSWORD UNIT & INTEGRATION TEST SUITE
 * Verifies:
 *  1. DOM IDs, modal structure, and TR/EN i18n parity in index.html, i18n.js, app.js.
 *  2. Validation & defense-in-depth guards in handleChangeMasterPw().
 *  3. Atomic vault re-encryption, in-memory master update, and Touch ID synchronization.
 *  4. Recovery key preservation (cached kit path) & safe rotation (legacy uncached path).
 *  5. lock() memory/DOM scrubbing for all Change Master Password inputs & overlay.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

console.log('═'.repeat(75));
console.log('FUIN TEST: DESKTOP CHANGE MASTER PASSWORD');
console.log('═'.repeat(75));

let passes = 0;
let failures = 0;

function test(desc, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${desc}`);
    console.error(`    ${err.stack || err.message}`);
    failures++;
  }
}

async function testAsync(desc, fn) {
  try {
    await fn();
    console.log(`  ✓ [PASS] ${desc}`);
    passes++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${desc}`);
    console.error(`    ${err.stack || err.message}`);
    failures++;
  }
}

const rootDir = __dirname;
const htmlContent = fs.readFileSync(path.join(rootDir, 'renderer', 'index.html'), 'utf8');
const i18nContent = fs.readFileSync(path.join(rootDir, 'renderer', 'i18n.js'), 'utf8');
const recoveryCtrlContent = fs.readFileSync(path.join(rootDir, 'renderer', 'modules', 'recoveryController.js'), 'utf8');
const appJsContent = fs.readFileSync(path.join(rootDir, 'renderer', 'app.js'), 'utf8');
const cssContent = fs.readFileSync(path.join(rootDir, 'renderer', 'style.css'), 'utf8');

// ── REAL AES-256-GCM HELPER FOR SANDBOXED API ────────────────────────
function deriveTestKey(secret, salt) {
  return crypto.scryptSync(String(secret), salt, 32);
}

function realEncrypt(payloadObj, secret) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveTestKey(secret, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    v: 'test-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    ct: ct.toString('base64'),
  });
}

function realDecrypt(encStr, secret) {
  const env = JSON.parse(encStr);
  const salt = Buffer.from(env.salt, 'base64');
  const iv = Buffer.from(env.iv, 'base64');
  const tag = Buffer.from(env.tag, 'base64');
  const ct = Buffer.from(env.ct, 'base64');
  const key = deriveTestKey(secret, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return JSON.parse(pt.toString('utf8'));
}

// ── MINIMAL DOM & BROWSER HARNESS FOR renderer/app.js ────────────────
function createElement(id, tag = 'div') {
  const classes = new Set();
  const listeners = new Map();
  const attrs = new Map();
  const el = {
    id,
    tagName: tag.toUpperCase(),
    value: '',
    type: tag === 'input' ? 'password' : '',
    textContent: '',
    innerText: '',
    innerHTML: '',
    placeholder: '',
    title: '',
    disabled: false,
    checked: false,
    focused: false,
    style: {},
    dataset: {},
    classList: {
      add: (...c) => c.forEach(x => classes.add(x)),
      remove: (...c) => c.forEach(x => classes.delete(x)),
      contains: (c) => classes.has(c),
      toggle: (c, force) => {
        if (force === undefined) {
          if (classes.has(c)) classes.delete(c);
          else classes.add(c);
        } else if (force) {
          classes.add(c);
        } else {
          classes.delete(c);
        }
      },
    },
    set className(val) {
      classes.clear();
      String(val || '').split(/\s+/).filter(Boolean).forEach(x => classes.add(x));
    },
    get className() {
      return Array.from(classes).join(' ');
    },
    addEventListener(ev, fn) {
      if (!listeners.has(ev)) listeners.set(ev, []);
      listeners.get(ev).push(fn);
    },
    dispatchEvent(ev, payload = {}) {
      const list = listeners.get(ev) || [];
      list.forEach(fn => fn({ target: el, currentTarget: el, ...payload }));
    },
    focus() { el.focused = true; },
    select() {},
    setAttribute(k, v) { attrs.set(k, String(v)); },
    getAttribute(k) { return attrs.get(k) || null; },
    removeAttribute(k) { attrs.delete(k); },
    appendChild() {},
    replaceChildren() {},
    querySelector: () => null,
    querySelectorAll: () => [],
  };
  return el;
}

function createSandbox(opts = {}) {
  const storage = new Map();
  const localStorage = {
    getItem: (k) => (storage.has(k) ? storage.get(k) : null),
    setItem: (k, v) => { storage.set(k, String(v)); },
    removeItem: (k) => { storage.delete(k); },
    clear: () => { storage.clear(); },
  };
  if (opts.lang) localStorage.setItem('fuin-lang', opts.lang);
  if (opts.touchIdEnabled) localStorage.setItem('fuin-touchid-enabled', 'true');

  const elements = new Map();
  const ensureEl = (id, tag = 'div') => {
    if (!elements.has(id)) elements.set(id, createElement(id, tag));
    return elements.get(id);
  };

  // Seed the exact DOM element IDs present in renderer/index.html
  for (const m of htmlContent.matchAll(/<([a-zA-Z0-9-]+)[^>]*\bid=["']([^"']+)["']/g)) {
    const [, tag, id] = m;
    ensureEl(id, tag.toLowerCase());
  }

  const state = {
    vaultEnc: opts.initialVaultEnc || null,
    recoveryEnc: opts.initialRecoveryEnc || null,
    masterEnc: opts.initialMasterEnc || null,
    saveDataCalls: 0,
    saveTouchIdCalls: [],
    clearTouchIdCalls: 0,
    unlockStateCalls: [],
    extResponses: [],
    copySecureCalls: [],
    saveRecoveryPairCalls: 0,
    checkRecoveryStatusCalls: 0,
    toasts: [],
    extHandlers: {},
  };

  const apiMock = {
    platform: 'darwin',
    onClipboardCleared: () => {},
    onAutoLockWarning: () => {},
    onAutoLockWarningCancel: () => {},
    onForceLock: () => {},
    onExtLookupRequest: (fn) => { state.extHandlers.lookup = fn; },
    onExtListVaultItemsRequest: (fn) => { state.extHandlers.listVaultItems = fn; },
    onExtRevealRequest: (fn) => { state.extHandlers.reveal = fn; },
    onExtCopySecureRequest: (fn) => { state.extHandlers.copySecure = fn; },
    onExtExcludeDomainRequest: (fn) => { state.extHandlers.excludeDomain = fn; },
    onExtCheckSaveCandidateRequest: (fn) => { state.extHandlers.checkSaveCandidate = fn; },
    onExtSaveCredentialRequest: (fn) => { state.extHandlers.saveCredential = fn; },
    extRespond: (requestId, payload) => {
      state.extResponses.push({ requestId, payload });
    },
    onSyncChunksReady: () => {},
    onSyncError: () => {},
    onSyncKeyExpired: () => {},
    onLanSyncApplied: () => {},
    onLanSyncClosed: () => {},
    onLanDevicePaired: () => {},
    cryptoInfo: async () => ({ argon2: true }),
    dataExists: async () => Boolean(state.vaultEnc),
    loadData: async () => state.vaultEnc,
    saveData: async (enc) => {
      state.saveDataCalls++;
      state.vaultEnc = enc;
    },
    encrypt: async (obj, pw) => realEncrypt(obj, pw),
    decrypt: async (enc, pw) => realDecrypt(enc, pw),
    loadRecovery: async () => state.recoveryEnc,
    loadMasterEnc: async () => state.masterEnc,
    saveRecoveryPair: async (recEnc, masterEnc) => {
      state.saveRecoveryPairCalls++;
      state.recoveryEnc = recEnc;
      state.masterEnc = masterEnc;
    },
    getRecoveryStatus: async () => {
      state.checkRecoveryStatusCalls++;
      return { exists: Boolean(state.recoveryEnc), legacyBound: false };
    },
    saveTouchIdKey: async (pw) => {
      state.saveTouchIdCalls.push(pw);
      if (opts.saveTouchIdThrows) throw new Error('keychain-write-failed');
      return opts.saveTouchIdResult !== undefined ? opts.saveTouchIdResult : true;
    },
    clearTouchIdKey: async () => {
      state.clearTouchIdCalls++;
      return true;
    },
    checkTouchId: async () => false,
    setUnlockState: (unlocked) => {
      state.unlockStateCalls.push(Boolean(unlocked));
    },
    cancelClipboardClear: () => {},
    setIdleLock: () => {},
    setLanguage: () => {},
    copySecure: async (text, durationMs) => {
      state.copySecureCalls.push({ text, durationMs });
    },
    zxcvbn: () => ({ score: 3 }),
  };

  const document = {
    readyState: 'complete',
    documentElement: { lang: opts.lang || 'tr', dataset: {} },
    body: createElement('body', 'body'),
    getElementById: (id) => elements.get(id) || null,
    querySelector: () => null,
    querySelectorAll: () => [],
    addEventListener: () => {},
    createElement: (tag) => createElement(`dyn-${Math.random()}`, tag),
    createElementNS: (_ns, tag) => createElement(`svg-${Math.random()}`, tag),
  };

  const windowObj = {
    kekkai: apiMock,
    matchMedia: () => ({ matches: true }),
    addEventListener: () => {},
  };

  const context = {
    window: windowObj,
    globalThis: windowObj,
    document,
    localStorage,
    crypto: crypto.webcrypto,
    TextEncoder,
    TextDecoder,
    console: { log: () => {}, warn: () => {}, error: () => {} },
    setTimeout: (fn) => { if (typeof fn === 'function') fn(); return 1; },
    clearTimeout: () => {},
    setInterval: () => 1,
    clearInterval: () => {},
    confirm: () => true,
    alert: () => {},
    URL,
    Blob,
  };
  windowObj.document = document;
  windowObj.localStorage = localStorage;
  windowObj.crypto = crypto.webcrypto;

  vm.createContext(context);
  vm.runInContext(i18nContent, context, { filename: 'renderer/i18n.js' });
  vm.runInContext(recoveryCtrlContent, context, { filename: 'renderer/modules/recoveryController.js' });
  vm.runInContext(appJsContent, context, { filename: 'renderer/app.js' });

  // Hook toast to record emitted messages cleanly
  const origToast = context.toast;
  context.toast = (msg) => {
    state.toasts.push(msg);
    if (typeof origToast === 'function') origToast(msg);
  };

  // Helper to configure unlocked session state inside vm lexical scope
  const setSession = vm.runInContext(`
    (async function __testSetSession(pw, plainEntries) {
      sessionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      master = pw;
      entries = await Promise.all((plainEntries || []).map(e => hydrateEntryMemory(e, e.id)));
    })
  `, context);

  const getMaster = vm.runInContext(`(() => master)`, context);

  return { context, elements, localStorage, state, apiMock, setSession, getMaster };
}

// ── 1. STATIC STRUCTURE, DOM IDS & I18N PARITY ───────────────────────
console.log('\n[SUITE 1] DOM Structure, Design Tokens & i18n TR/EN Parity');

test('1.1 All Change Master Password DOM IDs exist and are strictly unique in renderer/index.html', () => {
  const requiredIds = [
    'changePwSettingCard',
    'btnOpenChangePw',
    'changePwOverlay',
    'btnCloseChangePw',
    'curPwInp',
    'btnEyeCurPw',
    'newMasterPwInp',
    'btnEyeNewMasterPw',
    'newMasterPwConfirmInp',
    'btnEyeConfirmMasterPw',
    'changePwMsg',
    'btnCancelChangePw',
    'btnConfirmChangePw',
  ];
  for (const id of requiredIds) {
    const matches = htmlContent.match(new RegExp(`id=["']${id}["']`, 'g')) || [];
    assert.strictEqual(matches.length, 1, `DOM ID "${id}" must appear exactly once, found ${matches.length}`);
  }
});

test('1.2 #changePwSettingCard is placed directly above #recoverySettingCard and #changePwOverlay uses Fuin modal classes', () => {
  const cardIdx = htmlContent.indexOf('id="changePwSettingCard"');
  const recIdx = htmlContent.indexOf('id="recoverySettingCard"');
  assert.ok(cardIdx !== -1 && recIdx !== -1 && cardIdx < recIdx, '#changePwSettingCard must precede #recoverySettingCard');

  const modalStart = htmlContent.indexOf('id="changePwOverlay"');
  const modalEnd = htmlContent.indexOf('id="backupHistoryOverlay"');
  assert.ok(modalStart !== -1 && modalEnd !== -1 && modalStart < modalEnd, '#changePwOverlay must be before #backupHistoryOverlay');
  const modalHtml = htmlContent.slice(modalStart, modalEnd);

  const expectedClasses = [
    'modal', 'modal-head', 'modal-title', 'modal-close', 'modal-body',
    'verify-modal-desc', 'fg', 'inp-wrap', 'fi', 'eye-btn', 'forgot-msg',
    'modal-footer', 'modal-footer-split', 'btn-cancel', 'btn-save',
  ];
  for (const cls of expectedClasses) {
    assert.ok(modalHtml.includes(cls), `#changePwOverlay must reuse class .${cls}`);
    assert.ok(cssContent.includes(`.${cls}`), `Class .${cls} must exist in renderer/style.css`);
  }
});

test('1.3 All Change Master Password i18n keys have 1:1 TR/EN parity', () => {
  const ctx = {
    document: {
      documentElement: { lang: 'tr' },
      querySelectorAll: () => [],
      getElementById: () => null,
    },
    localStorage: { getItem: () => 'tr', setItem: () => {} },
    window: {},
  };
  vm.createContext(ctx);
  vm.runInContext(i18nContent + '\nthis.__TRANSLATIONS = TRANSLATIONS;', ctx);
  const tr = ctx.__TRANSLATIONS.tr;
  const en = ctx.__TRANSLATIONS.en;

  const keys = [
    'settingChangePwTitle',
    'settingChangePwSub',
    'btnChangeMasterPw',
    'changePwModalTitle',
    'changePwModalDesc',
    'changePwCurrentLabel',
    'changePwCurrentPh',
    'changePwNewLabel',
    'changePwNewPh',
    'changePwConfirmLabel',
    'changePwConfirmPh',
    'btnSaveNewMasterPw',
    'changePwWrongCurrent',
    'changePwMismatch',
    'changePwSameAsOld',
    'changePwFailed',
    'toastMasterPwChanged',
  ];

  for (const k of keys) {
    assert.strictEqual(typeof tr[k], 'string', `Missing TR key: ${k}`);
    assert.strictEqual(typeof en[k], 'string', `Missing EN key: ${k}`);
    assert.ok(tr[k].trim().length > 0, `Empty TR key: ${k}`);
    assert.ok(en[k].trim().length > 0, `Empty EN key: ${k}`);
    assert.notStrictEqual(tr[k], en[k], `EN value for ${k} should be translated from TR`);
  }
});

test('1.4 app.js registers Change Master Password listeners and scrubs state in lock()', () => {
  assert.ok(appJsContent.includes('function openChangeMasterPwModal()'));
  assert.ok(appJsContent.includes('function closeChangeMasterPwModal()'));
  assert.ok(appJsContent.includes('function showChangePwMsg('));
  assert.ok(appJsContent.includes('async function handleChangeMasterPw()'));
  assert.ok(appJsContent.includes("getElementById('btnOpenChangePw')?.addEventListener('click', openChangeMasterPwModal)"));
  assert.ok(appJsContent.includes("getElementById('btnConfirmChangePw')?.addEventListener('click', handleChangeMasterPw)"));
  assert.ok(appJsContent.includes("'changePwMsg'"), 'lock() must scrub changePwMsg');
});

// ── 2. RUNTIME BEHAVIOR TESTS (SANDBOXED PRODUCTION app.js) ──────────
(async () => {
  console.log('\n[SUITE 2] Sandboxed Execution of handleChangeMasterPw() & lock()');

  await testAsync('2.1 Guard: rejects when vault is locked (!master) without touching disk', async () => {
    const sb = createSandbox({ lang: 'en' });
    await sb.context.handleChangeMasterPw();
    assert.strictEqual(sb.state.saveDataCalls, 0);
    assert.ok(sb.state.toasts.includes(sb.context.t('toastLoginFirst')));
  });

  await testAsync('2.2 Rejects wrong current password without calling saveData', async () => {
    const oldPw = 'OldMasterPass#2026';
    const initialEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [] }, oldPw);
    const sb = createSandbox({ lang: 'en', initialVaultEnc: initialEnc });
    await sb.setSession(oldPw, [{ id: 'e1', type: 'login', site: 'GitHub', username: 'kadir', password: 'secret-value' }]);

    sb.elements.get('curPwInp').value = 'WrongCurrentPass!';
    sb.elements.get('newMasterPwInp').value = 'NewMasterPass#2026';
    sb.elements.get('newMasterPwConfirmInp').value = 'NewMasterPass#2026';

    await sb.context.handleChangeMasterPw();

    assert.strictEqual(sb.state.saveDataCalls, 0, 'Must NOT call saveData on wrong current password');
    assert.strictEqual(sb.getMaster(), oldPw, 'Active master must remain unchanged');
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, sb.context.t('changePwWrongCurrent'));
    assert.strictEqual(sb.elements.get('curPwInp').focused, true, 'Should focus current password field');
  });

  await testAsync('2.3 Rejects short (<8 chars), mismatched confirm, and same-as-current passwords', async () => {
    const oldPw = 'OldMasterPass#2026';
    const initialEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [] }, oldPw);
    const sb = createSandbox({ lang: 'en', initialVaultEnc: initialEnc });
    await sb.setSession(oldPw, []);

    // Case A: short (< 8 chars)
    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = 'short7!';
    sb.elements.get('newMasterPwConfirmInp').value = 'short7!';
    await sb.context.handleChangeMasterPw();
    assert.strictEqual(sb.state.saveDataCalls, 0);
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, sb.context.t('toastMinChars'));

    // Case B: mismatched confirm
    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = 'ValidNewPass#111';
    sb.elements.get('newMasterPwConfirmInp').value = 'ValidNewPass#222';
    await sb.context.handleChangeMasterPw();
    assert.strictEqual(sb.state.saveDataCalls, 0);
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, sb.context.t('changePwMismatch'));

    // Case C: same as current
    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = oldPw;
    sb.elements.get('newMasterPwConfirmInp').value = oldPw;
    await sb.context.handleChangeMasterPw();
    assert.strictEqual(sb.state.saveDataCalls, 0);
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, sb.context.t('changePwSameAsOld'));
  });

  await testAsync('2.4 Defense-in-depth: aborts if on-disk ciphertext fails decrypt with current password', async () => {
    const oldPw = 'OldMasterPass#2026';
    const mismatchedDiskEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [] }, 'DifferentDiskKey#999');
    const sb = createSandbox({ lang: 'en', initialVaultEnc: mismatchedDiskEnc });
    await sb.setSession(oldPw, []);

    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = 'BrandNewMaster#2026';
    sb.elements.get('newMasterPwConfirmInp').value = 'BrandNewMaster#2026';

    await sb.context.handleChangeMasterPw();

    assert.strictEqual(sb.state.saveDataCalls, 0, 'Must abort before overwriting disk vault');
    assert.strictEqual(sb.getMaster(), oldPw, 'Active master must remain unchanged');
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, sb.context.t('changePwWrongCurrent'));
  });

  await testAsync('2.5 Happy path (cached recovery key): re-encrypts vault, updates master & Touch ID, preserves existing recovery key', async () => {
    const oldPw = 'OldMasterPass#2026';
    const newPw = 'NewStrongMaster#2026!';
    const existingRecKey = 'AABBCCDD-11223344-55667788-9900AABB-CCDDEEFF-11223344-55667788-99AABBCC';
    const recClean = existingRecKey.replace(/-/g, '');

    const plainEntries = [
      { id: 'login-1', type: 'login', site: 'GitHub', username: 'kadir', password: 'gh-secret-password', totp: 'JBSWY3DPEHPK3PXP', history: [{ password: 'old-gh-password', date: 1700000000000 }] },
      { id: 'card-1', type: 'card', site: 'Bank', cardNumber: '4111222233334444', cardCvv: '987', cardPin: '4321' },
      { id: 'note-1', type: 'note', site: 'SSH Key', secureNote: 'PRIVATE-KEY-CONTENT' },
    ];
    const initialVaultEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: plainEntries }, oldPw);
    const initialRecoveryEnc = realEncrypt({ key: existingRecKey, verified: true }, recClean);
    const initialMasterEnc = realEncrypt({ master: oldPw }, recClean);

    const sb = createSandbox({
      lang: 'en',
      touchIdEnabled: true,
      initialVaultEnc,
      initialRecoveryEnc,
      initialMasterEnc,
    });
    // Cache encrypted recovery kit under old master (standard post-unlock state)
    sb.localStorage.setItem('fuin-recovery-kit-enc', realEncrypt({ key: existingRecKey, updatedAt: Date.now() }, oldPw));
    await sb.setSession(oldPw, plainEntries);

    sb.context.openChangeMasterPwModal();
    assert.strictEqual(sb.elements.get('changePwOverlay').classList.contains('open'), true);

    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = newPw;
    sb.elements.get('newMasterPwConfirmInp').value = newPw;

    await sb.context.handleChangeMasterPw();

    // 1) Vault re-encrypted atomically with newPw
    assert.strictEqual(sb.state.saveDataCalls, 1, 'saveData must be called exactly once');
    assert.throws(() => realDecrypt(sb.state.vaultEnc, oldPw), 'Old password must no longer decrypt vault');
    const decryptedVault = realDecrypt(sb.state.vaultEnc, newPw);
    assert.strictEqual(decryptedVault.type, 'fuin/vault');
    assert.ok(Array.isArray(decryptedVault.categories), 'Vault payload must preserve categories array');
    assert.strictEqual(decryptedVault.entries.length, 3);
    assert.strictEqual(decryptedVault.entries[0].password, 'gh-secret-password');
    assert.strictEqual(decryptedVault.entries[0].totp, 'JBSWY3DPEHPK3PXP');
    assert.strictEqual(decryptedVault.entries[0].history[0].password, 'old-gh-password');
    assert.strictEqual(decryptedVault.entries[1].cardNumber, '4111222233334444');
    assert.strictEqual(decryptedVault.entries[1].cardCvv, '987');
    assert.strictEqual(decryptedVault.entries[1].cardPin, '4321');
    assert.strictEqual(decryptedVault.entries[2].secureNote, 'PRIVATE-KEY-CONTENT');

    // 2) Active master updated in memory
    assert.strictEqual(sb.getMaster(), newPw);

    // 3) Touch ID updated because fuin-touchid-enabled === 'true'
    assert.deepStrictEqual(sb.state.saveTouchIdCalls, [newPw]);

    // 4) Recovery key preserved & master.enc + recovery-kit cache re-encrypted under newPw
    assert.strictEqual(sb.state.saveRecoveryPairCalls, 1);
    const recCheck = realDecrypt(sb.state.recoveryEnc, recClean);
    assert.strictEqual(recCheck.key, existingRecKey, 'Existing recovery key must be preserved');
    const masterEncCheck = realDecrypt(sb.state.masterEnc, recClean);
    assert.strictEqual(masterEncCheck.master, newPw, 'fuin.master.enc must now contain newPw');
    const kitCacheCheck = realDecrypt(sb.localStorage.getItem('fuin-recovery-kit-enc'), newPw);
    assert.strictEqual(kitCacheCheck.key, existingRecKey, 'Cached recovery kit envelope must be re-encrypted under newPw');
    assert.strictEqual(sb.elements.get('recoveryOverlay').classList.contains('open'), false, 'Should NOT force recovery rotation modal when existing key was preserved');

    // 5) Modal closed, inputs scrubbed, status checked, toast shown
    assert.strictEqual(sb.elements.get('changePwOverlay').classList.contains('open'), false);
    assert.strictEqual(sb.elements.get('curPwInp').value, '');
    assert.strictEqual(sb.elements.get('newMasterPwInp').value, '');
    assert.strictEqual(sb.elements.get('newMasterPwConfirmInp').value, '');
    assert.strictEqual(sb.elements.get('btnConfirmChangePw').disabled, false);
    assert.ok(sb.state.checkRecoveryStatusCalls >= 1);
    assert.ok(sb.state.toasts.includes(sb.context.t('toastMasterPwChanged')));
  });

  await testAsync('2.6 Legacy path (no cached recovery key): rotates fresh recovery key under newPw and opens #recoveryOverlay', async () => {
    const oldPw = 'LegacyMaster#2026';
    const newPw = 'UpdatedMaster#2026!';
    const initialVaultEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [{ id: 'e1', type: 'login', site: 'Mail', password: 'pw1' }] }, oldPw);

    const sb = createSandbox({
      lang: 'tr',
      touchIdEnabled: false,
      initialVaultEnc,
      initialRecoveryEnc: realEncrypt({ key: 'OLD-UNAVAILABLE-KEY', verified: true }, 'OLDUNAVAILABLEKEY'),
      initialMasterEnc: realEncrypt({ master: oldPw }, 'OLDUNAVAILABLEKEY'),
    });
    // No fuin-recovery-kit-enc in localStorage and empty recoveryKeyDisplay
    await sb.setSession(oldPw, [{ id: 'e1', type: 'login', site: 'Mail', password: 'pw1' }]);

    sb.elements.get('curPwInp').value = oldPw;
    sb.elements.get('newMasterPwInp').value = newPw;
    sb.elements.get('newMasterPwConfirmInp').value = newPw;

    await sb.context.handleChangeMasterPw();

    // Touch ID should NOT be called when disabled
    assert.strictEqual(sb.state.saveTouchIdCalls.length, 0);

    // Vault decrypted cleanly with newPw
    const decryptedVault = realDecrypt(sb.state.vaultEnc, newPw);
    assert.strictEqual(decryptedVault.entries[0].password, 'pw1');
    assert.strictEqual(sb.getMaster(), newPw);

    // Fresh recovery key generated, saved with newPw, and #recoveryOverlay opened
    assert.strictEqual(sb.elements.get('recoveryOverlay').classList.contains('open'), true, 'Legacy path must open #recoveryOverlay so user saves rotated recovery key');
    const freshKey = sb.elements.get('recoveryKeyDisplay').textContent;
    assert.ok(freshKey.length >= 32, 'Fresh recovery key must be displayed');
    const freshClean = freshKey.replace(/-/g, '');
    const masterData = realDecrypt(sb.state.masterEnc, freshClean);
    assert.strictEqual(masterData.master, newPw, 'Rotated fuin.master.enc must unlock with fresh key and yield newPw');
    const kitData = realDecrypt(sb.localStorage.getItem('fuin-recovery-kit-enc'), newPw);
    assert.strictEqual(kitData.key, freshKey);
  });

  await testAsync('2.7 lock() scrubs curPwInp, newMasterPwInp, newMasterPwConfirmInp, changePwMsg, and closes changePwOverlay', async () => {
    const sb = createSandbox({ lang: 'en' });
    await sb.setSession('ActiveMaster#2026', []);

    sb.elements.get('changePwOverlay').classList.add('open');
    sb.elements.get('curPwInp').value = 'secret-cur';
    sb.elements.get('curPwInp').type = 'text';
    sb.elements.get('newMasterPwInp').value = 'secret-new';
    sb.elements.get('newMasterPwInp').type = 'text';
    sb.elements.get('newMasterPwConfirmInp').value = 'secret-confirm';
    sb.elements.get('newMasterPwConfirmInp').type = 'text';
    sb.context.showChangePwMsg('Some error message', 'red');

    sb.context.lock();

    assert.strictEqual(sb.getMaster(), null);
    assert.strictEqual(sb.elements.get('curPwInp').value, '');
    assert.strictEqual(sb.elements.get('newMasterPwInp').value, '');
    assert.strictEqual(sb.elements.get('newMasterPwConfirmInp').value, '');
    assert.strictEqual(sb.elements.get('curPwInp').type, 'password');
    assert.strictEqual(sb.elements.get('newMasterPwInp').type, 'password');
    assert.strictEqual(sb.elements.get('newMasterPwConfirmInp').type, 'password');
    assert.strictEqual(sb.elements.get('changePwMsg').textContent, '');
    assert.strictEqual(sb.elements.get('changePwMsg').style.display, 'none');
    assert.strictEqual(sb.elements.get('changePwOverlay').classList.contains('open'), false);
  });

  console.log('\n[SUITE 3] Security Audit Remediations (CRYPTO-01, CRYPTO-05, CRYPTO-06, CRYPTO-07 & EXT-04 Runtime)');

  await testAsync('3.1 CRYPTO-01: renderList() escapes malicious cardBrand HTML and safely handles missing/non-string e.site', async () => {
    const sb = createSandbox({ lang: 'en' });
    await sb.setSession('MasterPass#2026', [
      {
        id: 'card-evil',
        type: 'card',
        site: 'Injected Card',
        cardNumber: '4111222233334444',
        cardLastFour: '4444',
        cardBrand: '<button data-action="perm-del-pw" data-val="e1">HIJACK</button>',
      },
      {
        id: 'login-nosite',
        type: 'login',
        site: undefined,
        username: 'ghost',
        password: 'Password!123',
      },
      {
        id: 'login-numsite',
        type: 'login',
        site: 4242,
        username: 'num',
        password: 'Password!123',
      },
    ]);

    await sb.context.renderList();
    const html = sb.elements.get('pwList').innerHTML;
    assert.ok(html.includes('&lt;BUTTON DATA-ACTION=&quot;PERM-DEL-PW&quot;'), 'Malicious cardBrand must be HTML-escaped');
    assert.ok(!html.includes('<BUTTON DATA-ACTION='), 'Unescaped <BUTTON DATA-ACTION> must NEVER appear in pwList');
    assert.ok(html.includes('login-nosite'), 'Entry with missing site must render without throwing TypeError');
    assert.ok(html.includes('>42<'), 'Non-string site must be coerced safely to string');
  });

  await testAsync('3.2 CRYPTO-05: handleForgot() clears recovery/newPw DOM inputs, clears stale Touch ID key, and calls setUnlockState(false)', async () => {
    const oldPw = 'OldMasterPass#2026';
    const newPw = 'RecoveredMaster#2026!';
    const recKey = '11223344-55667788-9900AABB-CCDDEEFF-11223344-55667788-9900AABB-CCDDEEFF';
    const recClean = recKey.replace(/-/g, '');

    const initialVaultEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [{ id: 'e1', type: 'login', site: 'Bank', password: 'pw1' }] }, oldPw);
    const initialRecoveryEnc = realEncrypt({ key: recKey, verified: true }, recClean);
    const initialMasterEnc = realEncrypt({ master: oldPw }, recClean);

    const sb = createSandbox({
      lang: 'en',
      initialVaultEnc,
      initialRecoveryEnc,
      initialMasterEnc,
    });

    // Step 1: Verify recovery key
    sb.elements.get('recoveryInp').value = recKey;
    await sb.context.handleForgot();
    assert.strictEqual(sb.elements.get('newPwGroup').style.display, 'block');

    // Step 2: Submit new password (with exposed type="text" to test reset)
    sb.elements.get('newPwInp').type = 'text';
    sb.elements.get('newPwInp').value = newPw;
    await sb.context.handleForgot();

    assert.strictEqual(sb.elements.get('recoveryInp').value, '', '#recoveryInp must be scrubbed');
    assert.strictEqual(sb.elements.get('newPwInp').value, '', '#newPwInp must be scrubbed');
    assert.strictEqual(sb.elements.get('newPwInp').type, 'password', '#newPwInp type must reset to password');
    assert.strictEqual(sb.elements.get('recoveryKeyDisplay').textContent, '', '#recoveryKeyDisplay must be scrubbed');
    assert.ok(sb.state.clearTouchIdCalls >= 1, 'handleForgot must clear stale Touch ID key');
    assert.strictEqual(sb.state.unlockStateCalls[sb.state.unlockStateCalls.length - 1], false, 'handleForgot must enforce setUnlockState(false)');
  });

  await testAsync('3.3 CRYPTO-06: lock() scrubs card/note/recovery/TOTP DOM values, resets input types, clears _lastGenRes, and openPwHistory omits plaintext title tooltip', async () => {
    const sb = createSandbox({ lang: 'en' });
    await sb.setSession('ActiveMaster#2026', [
      {
        id: 'hist-1',
        type: 'login',
        site: 'GitHub',
        username: 'kadir',
        password: 'CurrentPassword!1',
        history: [{ password: 'PlaintextHistorySecret!99', date: Date.now() }],
      }
    ]);

    // Populate sensitive DOM fields and _lastGenRes
    sb.elements.get('f-card-number').value = '4111 2222 3333 4444';
    sb.elements.get('f-card-cvv').value = '987';
    sb.elements.get('f-card-cvv').type = 'text';
    sb.elements.get('f-card-pin').value = '4321';
    sb.elements.get('f-card-pin').type = 'text';
    sb.elements.get('f-secure-note').value = 'PRIVATE-SEED-PHRASE';
    sb.elements.get('f-pw').value = 'VisiblePass!1';
    sb.elements.get('f-pw').type = 'text';
    sb.elements.get('recoveryInp').value = 'AAAA-BBBB-CCCC';
    sb.elements.get('newPwInp').value = 'NewPass!1';
    sb.elements.get('newPwInp').type = 'text';
    sb.elements.get('totpCode').textContent = '123 456';
    vm.runInContext('_lastGenRes = { password: "GeneratedSecret!42" }; editId = "hist-1";', sb.context);

    await sb.context.openPwHistory();
    const histHtml = sb.elements.get('pwHistoryList').innerHTML;
    assert.ok(!histHtml.includes('PlaintextHistorySecret!99'), 'openPwHistory must NEVER expose plaintext password in title tooltip');
    assert.ok(!histHtml.includes('title='), 'pw-hist-val must not carry plaintext title attribute');

    sb.context.lock();

    assert.strictEqual(sb.elements.get('f-card-number').value, '');
    assert.strictEqual(sb.elements.get('f-card-cvv').value, '');
    assert.strictEqual(sb.elements.get('f-card-cvv').type, 'password');
    assert.strictEqual(sb.elements.get('f-card-pin').value, '');
    assert.strictEqual(sb.elements.get('f-card-pin').type, 'password');
    assert.strictEqual(sb.elements.get('f-secure-note').value, '');
    assert.strictEqual(sb.elements.get('f-pw').value, '');
    assert.strictEqual(sb.elements.get('f-pw').type, 'password');
    assert.strictEqual(sb.elements.get('recoveryInp').value, '');
    assert.strictEqual(sb.elements.get('newPwInp').value, '');
    assert.strictEqual(sb.elements.get('newPwInp').type, 'password');
    assert.strictEqual(sb.elements.get('totpCode').textContent, '');
    assert.strictEqual(vm.runInContext('_lastGenRes', sb.context), null, '_lastGenRes must be nulled on lock()');
  });

  await testAsync('3.4 CRYPTO-07: handleChangeMasterPw() calls clearTouchIdKey() when saveTouchIdKey returns false or throws', async () => {
    const oldPw = 'OldMasterPass#2026';
    const newPw = 'NewMasterPass#2026!';
    const initialVaultEnc = realEncrypt({ type: 'fuin/vault', categories: [], entries: [] }, oldPw);

    // Case A: saveTouchIdKey returns false
    const sbFalse = createSandbox({ lang: 'en', touchIdEnabled: true, initialVaultEnc, saveTouchIdResult: false });
    await sbFalse.setSession(oldPw, []);
    sbFalse.elements.get('curPwInp').value = oldPw;
    sbFalse.elements.get('newMasterPwInp').value = newPw;
    sbFalse.elements.get('newMasterPwConfirmInp').value = newPw;
    await sbFalse.context.handleChangeMasterPw();
    assert.strictEqual(sbFalse.state.clearTouchIdCalls, 1, 'clearTouchIdKey must be called when saveTouchIdKey returns false');

    // Case B: saveTouchIdKey throws
    const sbThrow = createSandbox({ lang: 'en', touchIdEnabled: true, initialVaultEnc, saveTouchIdThrows: true });
    await sbThrow.setSession(oldPw, []);
    sbThrow.elements.get('curPwInp').value = oldPw;
    sbThrow.elements.get('newMasterPwInp').value = newPw;
    sbThrow.elements.get('newMasterPwConfirmInp').value = newPw;
    await sbThrow.context.handleChangeMasterPw();
    assert.strictEqual(sbThrow.state.clearTouchIdCalls, 1, 'clearTouchIdKey must be called when saveTouchIdKey throws');
  });

  await testAsync('3.5 EXT-04 runtime: approveExtReveal & onExtCopySecureRequest enforce Master Password reprompt on reprompt:true entries and use Desktop copySecure', async () => {
    const masterPw = 'StrongMaster#2026!';
    const sb = createSandbox({ lang: 'en' });
    await sb.setSession(masterPw, [
      { id: 'sec-1', type: 'login', site: 'bank.com', url: 'https://bank.com', username: 'alice', password: 'BankSecret!99', reprompt: true }
    ]);

    // 1) Reveal request opens extRevealOverlay
    await sb.state.extHandlers.reveal({ requestId: 'req-rev-1', entryId: 'sec-1', domain: 'bank.com' });
    assert.strictEqual(sb.elements.get('extRevealOverlay').classList.contains('open'), true);
    assert.strictEqual(sb.state.extResponses.length, 0, 'Must not reveal before approval');

    // Clicking Approve must open #repromptOverlay and NOT respond yet
    const approvePromise1 = sb.context.approveExtReveal();
    assert.strictEqual(sb.elements.get('repromptOverlay').classList.contains('open'), true, 'Must prompt for Master Password');
    assert.strictEqual(sb.state.extResponses.length, 0, 'Must NOT respond before Master Password verified');

    // Cancelling reprompt denies reveal
    sb.context.cancelReprompt();
    await approvePromise1;
    assert.strictEqual(sb.state.extResponses[0].requestId, 'req-rev-1');
    assert.strictEqual(sb.state.extResponses[0].payload.error, 'denied');

    // 2) Copy-secure request on reprompt:true entry requires approval + Master Password, then copies via Desktop copySecure (30s)
    await sb.state.extHandlers.copySecure({ requestId: 'req-copy-1', entryId: 'sec-1', domain: 'bank.com', field: 'password' });
    assert.strictEqual(sb.elements.get('extRevealOverlay').classList.contains('open'), true);
    const approvePromise2 = sb.context.approveExtReveal();
    assert.strictEqual(sb.elements.get('repromptOverlay').classList.contains('open'), true);

    // Wrong password rejected
    sb.elements.get('repromptPwInp').value = 'WrongPass!';
    await sb.context.verifyReprompt();
    assert.strictEqual(sb.state.copySecureCalls.length, 0);

    // Correct Master Password succeeds and copies via Desktop copySecure (30s auto-clear)
    sb.elements.get('repromptPwInp').value = masterPw;
    await sb.context.verifyReprompt();
    await approvePromise2;

    assert.strictEqual(sb.state.copySecureCalls.length, 1);
    assert.strictEqual(sb.state.copySecureCalls[0].text, 'BankSecret!99');
    assert.strictEqual(sb.state.copySecureCalls[0].durationMs, 30000);
    assert.strictEqual(sb.state.extResponses[1].requestId, 'req-copy-1');
    assert.strictEqual(sb.state.extResponses[1].payload.ok, true);
  });

  console.log('\n' + '═'.repeat(75));
  console.log(`CHANGE MASTER PASSWORD RESULT: ${passes} PASSED, ${failures} FAILED`);
  console.log('═'.repeat(75));

  if (failures > 0) process.exit(1);
})();
