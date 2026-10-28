'use strict';

const fs = require('fs');
const path = require('path');
const assert = require('assert');
const vm = require('vm');

console.log('══════════════════════════════════════════════════════════════════════════════');
console.log('FUIN BROWSER EXTENSION & API PRIVACY DEEP SECURITY AUDIT SUITE');
console.log('Firefox / Chrome MV3 Security & Privacy Invariants Verification');
console.log('══════════════════════════════════════════════════════════════════════════════\n');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function check(title, fn) {
  totalTests++;
  try {
    fn();
    console.log(`  [PASS] ${title}`);
    passedTests++;
  } catch (err) {
    console.error(`  [FAIL] ${title}: ${err.message}`);
    failedTests++;
  }
}

// ── 1. MANIFEST & PERMISSIONS AUDIT (FIREFOX + CHROME MV3) ───────────────────
console.log('[1. Manifest & Permissions Audit]');

const manifestPath = path.join(__dirname, 'browser-extension/manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

check('1.1 Manifest is valid MV3 with standard dual-engine background config', () => {
  assert.strictEqual(manifest.manifest_version, 3, 'Must be Manifest V3');
  assert.strictEqual(manifest.background.service_worker, 'background.js', 'Chrome service worker set');
  assert.deepStrictEqual(manifest.background.scripts, ['background.js'], 'Firefox background scripts set');
});

check('1.2 Firefox Gecko configuration has valid ID and broad compatibility strict_min_version', () => {
  const gecko = manifest.browser_specific_settings?.gecko;
  assert.ok(gecko, 'gecko settings present');
  assert.strictEqual(gecko.id, 'fuin-app@sombo.dev', 'Valid AMO registered ID');
  assert.strictEqual(gecko.strict_min_version, '109.0', 'Must be compatible with Firefox 109+');
});

check('1.3 Zero invasive permissions (Only minimal nativeMessaging and activeTab)', () => {
  const allowedPerms = new Set(['nativeMessaging', 'activeTab']);
  for (const p of manifest.permissions) {
    assert.ok(allowedPerms.has(p), `Unexpected permission requested: ${p}`);
  }
  assert.strictEqual(manifest.permissions.length, 2);
});

check('1.4 Host permissions strictly restricted to https://*/*', () => {
  assert.deepStrictEqual(manifest.host_permissions, ['https://*/*']);
  assert.deepStrictEqual(manifest.content_scripts[0].matches, ['https://*/*']);
  assert.strictEqual(manifest.content_scripts[0].all_frames, undefined, 'Must not inject into all frames by default');
});

// ── 2. STATIC INJECTION & SCRIPT SECURITY AUDIT ──────────────────────────────
console.log('\n[2. Static Code & Injection Security Audit]');

const contentJs = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
const backgroundJs = fs.readFileSync(path.join(__dirname, 'browser-extension/background.js'), 'utf8');
const popupJs = fs.readFileSync(path.join(__dirname, 'browser-extension/popup.js'), 'utf8');

check('2.1 Zero innerHTML / outerHTML / document.write in all extension scripts', () => {
  for (const [name, code] of [['content.js', contentJs], ['background.js', backgroundJs], ['popup.js', popupJs]]) {
    assert.ok(!code.includes('innerHTML'), `${name} must not contain innerHTML`);
    assert.ok(!code.includes('outerHTML'), `${name} must not contain outerHTML`);
    assert.ok(!code.includes('document.write'), `${name} must not contain document.write`);
    assert.ok(!code.includes('eval('), `${name} must not contain eval`);
  }
});

check('2.2 Zero network calls (fetch / XMLHttpRequest / WebSocket) in extension', () => {
  for (const [name, code] of [['content.js', contentJs], ['background.js', backgroundJs], ['popup.js', popupJs]]) {
    assert.ok(!code.includes('fetch('), `${name} must not call fetch`);
    assert.ok(!code.includes('XMLHttpRequest'), `${name} must not use XMLHttpRequest`);
    assert.ok(!code.includes('WebSocket'), `${name} must not use WebSocket`);
  }
});

// ── 3. CROSS-FRAME / IFRAME IMPERSONATION DEFENSE ────────────────────────────
console.log('\n[3. Cross-Frame / iFrame Impersonation Defense]');

check('3.1 background.js enforces sender.frameId === 0 to reject subframes', () => {
  assert.ok(backgroundJs.includes('if (sender.frameId !== undefined && sender.frameId !== 0) return;'),
    'Must strictly reject subframe messages');
});

check('3.2 background.js enforces sender.url origin alignment with tab origin', () => {
  assert.ok(backgroundJs.includes('parsedSenderUrl.origin !== parsedTabUrl.origin'),
    'Must verify sender.url origin matches tab.url origin');
});

check('3.3 iFrame rejection simulation: subframe cannot spoof top-level tab domain', () => {
  let askedPayload = null;
  function askFuinMock(payload) {
    askedPayload = payload;
    return Promise.resolve({ matches: [] });
  }

  function handleMessageSim(msg, sender) {
    if (!sender.tab?.url) return { rejected: true, reason: 'no-tab-url' };
    if (sender.frameId !== undefined && sender.frameId !== 0) return { rejected: true, reason: 'subframe' };

    let actualDomain;
    try {
      const parsedTabUrl = new URL(sender.tab.url);
      if (sender.url) {
        const parsedSenderUrl = new URL(sender.url);
        if (parsedSenderUrl.origin !== parsedTabUrl.origin) return { rejected: true, reason: 'cross-origin-frame' };
      }
      actualDomain = parsedTabUrl.hostname;
    } catch {
      return { rejected: true, reason: 'invalid-url' };
    }

    if (msg.type === 'fuin-lookup') {
      askFuinMock({ type: 'lookup', domain: actualDomain });
      return { accepted: true, domain: actualDomain };
    }
  }

  // Attack scenario 1: An ad or tracking iframe (frameId=2) tries to request vault credentials
  const res1 = handleMessageSim(
    { type: 'fuin-lookup', domain: 'mybank.com' },
    { frameId: 2, tab: { url: 'https://mybank.com' }, url: 'https://evil-ad.com' }
  );
  assert.strictEqual(res1.rejected, true);
  assert.strictEqual(res1.reason, 'subframe');
  assert.strictEqual(askedPayload, null, 'Must not send query to native host');

  // Attack scenario 2: Subframe spoofing frameId=0 but mismatched sender.url
  const res2 = handleMessageSim(
    { type: 'fuin-lookup', domain: 'mybank.com' },
    { frameId: 0, tab: { url: 'https://mybank.com' }, url: 'https://evil-spoof.com' }
  );
  assert.strictEqual(res2.rejected, true);
  assert.strictEqual(res2.reason, 'cross-origin-frame');
  assert.strictEqual(askedPayload, null);

  // Legitimate top-level page
  const res3 = handleMessageSim(
    { type: 'fuin-lookup', domain: 'mybank.com' },
    { frameId: 0, tab: { url: 'https://mybank.com/login' }, url: 'https://mybank.com/login' }
  );
  assert.strictEqual(res3.accepted, true);
  assert.strictEqual(res3.domain, 'mybank.com');
  assert.deepStrictEqual(askedPayload, { type: 'lookup', domain: 'mybank.com' });
});

// ── 4. DOMAIN SPOOFING & SYNTHETIC CLICK PREVENTION ──────────────────────────
console.log('\n[4. Domain Spoofing & Synthetic Click Prevention]');

check('4.1 background.js ignores client msg.domain and strictly uses verified sender.tab.url', () => {
  const bgCode = backgroundJs;
  const lookupBlockIdx = bgCode.indexOf("if (msg.type === 'fuin-lookup')");
  const lookupBlock = bgCode.slice(lookupBlockIdx, lookupBlockIdx + 250);
  assert.ok(lookupBlock.includes('domain: actualDomain'), 'Must use actualDomain, not msg.domain');
  assert.ok(!lookupBlock.includes('domain: msg.domain'), 'Must never pass msg.domain from content script');
});

check('4.2 content.js strictly verifies e.isTrusted on user clicks', () => {
  assert.ok(contentJs.includes('if (!e.isTrusted) return;'), 'Must reject untrusted/synthetic mouse events');
});

check('4.3 Popup enforces HTTPS and disables trigger on unprivileged or HTTP tabs', () => {
  assert.ok(popupJs.includes("parsedUrl.protocol !== 'https:'"), 'Must verify https protocol');
  assert.ok(popupJs.includes('fillBtn.disabled = true;'), 'Must disable fill button on non-https');
});

// ── 5. DUAL FIREFOX / CHROME NATIVE MESSAGING COMPATIBILITY ──────────────────
console.log('\n[5. Dual Firefox / Chrome Native Messaging Compatibility]');

check('5.1 askFuin supports both callback style (Chrome) and Promise returns (Firefox)', () => {
  assert.ok(backgroundJs.includes('typeof browser !== \'undefined\''), 'Detects browser namespace');
  assert.ok(backgroundJs.includes('typeof p.then === \'function\''), 'Handles Promise returned by browser.runtime');
  assert.ok(backgroundJs.includes('safeResolve'), 'Guards against double-resolve between callback and Promise');
});

// ── 6. API PRIVACY & K-ANONYMITY AUDIT ────────────────────────────────────────
console.log('\n[6. API Privacy & K-Anonymity Audit]');

const healthScannerJs = fs.readFileSync(path.join(__dirname, 'renderer/modules/healthScanner.js'), 'utf8');
const appJs = fs.readFileSync(path.join(__dirname, 'renderer/app.js'), 'utf8');
const mobileHealthPath = path.join(__dirname, '../FuinMobile/src/screens/HealthModal.js');
const targets = [['healthScanner.js', healthScannerJs], ['app.js', appJs]];
if (fs.existsSync(mobileHealthPath)) {
  targets.push(['Mobile HealthModal.js', fs.readFileSync(mobileHealthPath, 'utf8')]);
}

check('6.1 HIBP check strictly sends 5-character SHA-1 prefix only (k-anonymity)', () => {
  for (const [name, code] of targets) {
    const hasSlice = /h(?:ash)?\.slice\(0,\s*5\)/.test(code);
    assert.ok(hasSlice, `${name} must extract 5-char prefix`);
    assert.ok(code.includes('/range/${pre}'), `${name} must query /range/\${pre}`);
    assert.ok(!code.includes('/range/${h}') && !code.includes('/range/${hash}'), `${name} must NEVER send full hash`);
  }
});

check('6.2 HIBP check sends Add-Padding: true to prevent response size leakage', () => {
  for (const [name, code] of targets) {
    assert.ok(code.includes("'Add-Padding': 'true'"), `${name} must send Add-Padding header`);
  }
});

check('6.3 HIBP check specifies cache: "no-store" to prevent disk cache hash retention', () => {
  for (const [name, code] of targets) {
    assert.ok(code.includes("cache: 'no-store'"), `${name} must set cache: no-store`);
  }
});

// ── 7. ADVERSARIAL AUTOFILL, SITE ISOLATION & BRIDGE HARDENING AUDIT ─────────
console.log('\n[7. Adversarial Autofill, Site Isolation & Bridge Hardening Audit]');

check('7.1 content.js blocks zero-click synthetic KeyboardEvent autofill & synthetic input events', () => {
  const keydownIdx = contentJs.indexOf("window.addEventListener('keydown', (e) => {");
  assert.ok(keydownIdx !== -1, 'Shortcut keydown listener must exist');
  const keydownSlice = contentJs.slice(keydownIdx, keydownIdx + 180);
  assert.ok(keydownSlice.includes('if (!e.isTrusted) return;'), 'Shortcut keydown listener MUST verify e.isTrusted');

  const inputIdx = contentJs.indexOf("document.addEventListener('input', (e) => {");
  assert.ok(inputIdx !== -1 && contentJs.slice(inputIdx, inputIdx + 120).includes('if (!e.isTrusted) return;'),
    'Document input listener MUST verify e.isTrusted');
});

check('7.2 content.js blocks hidden password trap when user has not typed (_passwordDirty guard)', () => {
  assert.ok(contentJs.includes('const hiddenDirtyPw = _passwordDirty ?'),
    'captureFormCredentials must guard hidden password fields behind _passwordDirty');
});

check('7.3 renderer/app.js enforces domainMatches on updateEntryId, reprompt guard, and zero username leak', () => {
  assert.ok(appJs.includes('Boolean(entry.reprompt)'), 'onExtRevealRequest must enforce approval on reprompt entries');
  assert.ok(appJs.includes("if (!domainMatches(byId, req.domain))"), 'onExtSaveCredentialRequest must enforce domainMatches on updateEntryId');
  assert.ok(appJs.includes("error: 'reprompt-protected'"), 'onExtSaveCredentialRequest must protect reprompt entries from silent overwrite');
  assert.ok(!appJs.includes('username: matchingEntries[0].username'), 'onExtCheckSaveCandidateRequest must never leak vault username on empty input');
});

check('7.4 extensionBridge.js & native-host/host.js enforce rate limits, type allowlist, and length caps', () => {
  const extBridgeJs = fs.readFileSync(path.join(__dirname, 'main/extensionBridge.js'), 'utf8');
  const hostJs = fs.readFileSync(path.join(__dirname, 'native-host/host.js'), 'utf8');
  assert.ok(extBridgeJs.includes('function checkRateLimit(') && extBridgeJs.includes("error: 'rate-limited'"),
    'extensionBridge.js must enforce sliding-window rate limiting');
  assert.ok(hostJs.includes('ALLOWED_TYPES') && hostJs.includes('clampField('),
    'native-host/host.js must enforce strict message type allowlist and field length clamping');
});

check('7.5 Extension UI uses crisp createElementNS vector SVGs with zero cartoon emojis', () => {
  const popupHtml = fs.readFileSync(path.join(__dirname, 'browser-extension/popup.html'), 'utf8');
  for (const [name, code] of [['content.js', contentJs], ['popup.js', popupJs], ['popup.html', popupHtml]]) {
    const nonCommentLines = code.split('\n').filter(l => !l.trim().startsWith('//')).join('\n');
    assert.ok(!/[\u{1F300}-\u{1FAFF}]/u.test(nonCommentLines), `${name} must not contain cartoon emojis`);
  }
  assert.ok(contentJs.includes("createElementNS(ns, 'svg')") && popupJs.includes("createElementNS(ns, 'svg')"),
    'Extension scripts must build vector SVGs via safe createElementNS');
});

async function runAsyncSiteIsolationAudit() {
  let onMsg = null;
  let onTabUpd = null;
  const tabMessages = [];

  const sb = {
    console, URL, Date, Map, Set, Promise, setTimeout, clearTimeout,
    chrome: {
      runtime: {
        id: 'abcdefghijklmnopabcdefghijklmnop',
        lastError: null,
        sendNativeMessage: (_h, payload, cb) => {
          if (payload.type === 'check-save-candidate') {
            cb({ shouldPrompt: true, action: 'save', username: payload.username });
          } else {
            cb({ ok: true });
          }
        },
        onMessage: { addListener: (fn) => { onMsg = fn; } }
      },
      tabs: {
        onUpdated: { addListener: (fn) => { onTabUpd = fn; } },
        onRemoved: { addListener: () => {} },
        query: () => {},
        sendMessage: (tabId, msg, cb) => { tabMessages.push({ tabId, msg }); if (cb) cb(); }
      },
      action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
      commands: { onCommand: { addListener: () => {} } }
    }
  };

  vm.runInNewContext(backgroundJs, sb);

  const sendFromTab = (url, msg, tabId = 99) => new Promise((resolve) => {
    onMsg(msg, { id: 'abcdefghijklmnopabcdefghijklmnop', frameId: 0, url, tab: { id: tabId, url } }, resolve);
  });

  // Scenario A: Submit on mybank.com, then same tab navigates to evil-news.com -> MUST scrub & block!
  await sendFromTab('https://login.mybank.com/auth', { type: 'fuin-form-submitted', username: 'kadir', password: 'TopSecretBankPassword!' }, 99);
  tabMessages.length = 0;
  onTabUpd(99, { status: 'complete', url: 'https://evil-news.com/' }, { id: 99, url: 'https://evil-news.com/' });
  const leakCheck1 = await sendFromTab('https://evil-news.com/', { type: 'fuin-get-pending-save' }, 99);

  check('7.6 Cross-site navigation scrubs pending credential (zero Site Isolation leak to evil-news.com)', () => {
    assert.strictEqual(tabMessages.length, 0, 'Must NOT push save prompt to cross-site tab');
    assert.strictEqual(leakCheck1.hasPending, false, 'evil-news.com must NOT read mybank.com pending credential');
  });

  // Scenario B: Multi-tenant isolation (alice.github.io -> bob.github.io in same tab) -> MUST scrub & block!
  await sendFromTab('https://alice.github.io/login', { type: 'fuin-form-submitted', username: 'alice', password: 'AliceTenantSecret!' }, 101);
  tabMessages.length = 0;
  onTabUpd(101, { status: 'complete', url: 'https://bob.github.io/' }, { id: 101, url: 'https://bob.github.io/' });
  const leakCheck2 = await sendFromTab('https://bob.github.io/', { type: 'fuin-get-pending-save' }, 101);

  check('7.7 Multi-tenant navigation scrubs pending credential (alice.github.io -> bob.github.io isolated)', () => {
    assert.strictEqual(tabMessages.length, 0, 'Must NOT push save prompt across github.io tenants');
    assert.strictEqual(leakCheck2.hasPending, false, 'bob.github.io must NOT read alice.github.io pending credential');
  });

  // Scenario C: Legitimate post-login redirect on same site (login.chess.com -> www.chess.com/home) -> preserved!
  await sendFromTab('https://login.chess.com/', { type: 'fuin-form-submitted', username: 'gm', password: 'ValidRedirectPassword!' }, 102);
  const legitRedirect = await sendFromTab('https://www.chess.com/home', { type: 'fuin-get-pending-save' }, 102);

  check('7.8 Legitimate same-site redirect (login.chess.com -> www.chess.com) preserves pending save', () => {
    assert.strictEqual(legitRedirect.hasPending, true, 'Same-site HTTPS redirect must preserve save prompt');
  });

  // ── FINAL SUMMARY ──────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL SECURITY CHECKS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${failedTests}`);
  console.log('══════════════════════════════════════════════════════════════════════════════');

  if (failedTests > 0) {
    process.exit(1);
  } else {
    console.log('\nALL EXTENSION & API PRIVACY SECURITY AUDIT CHECKS PASSED (100%)!\n');
  }
}

runAsyncSiteIsolationAudit().catch((e) => {
  console.error(e);
  process.exit(1);
});
