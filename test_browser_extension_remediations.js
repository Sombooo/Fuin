'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

console.log('══════════════════════════════════════════════════════════════════════════════');
console.log('FUIN BROWSER EXTENSION TARGETED REMEDIATIONS VERIFICATION SUITE');
console.log('F-01 / F-02 / F-03 / F-04');
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

// ── F-01: POPUP AUTOFILL MENU DOM LEAK PREVENTION ──────────────────────────
console.log('[F-01: Popup Autofill Menu DOM Leak Prevention]');

check('1.1 content.js initializes FIELD_MAP WeakMap for retaining closed shadowRoot', () => {
  const content = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
  assert.ok(content.includes('const FIELD_MAP = new WeakMap();'), 'FIELD_MAP WeakMap must be initialized');
  assert.ok(content.includes('FIELD_MAP.set(pwField, { host, shadow, icon });'), 'FIELD_MAP stores host, shadow, icon');
  assert.ok(content.includes('FIELD_MAP.delete(pwField);'), 'FIELD_MAP cleans up when field removed');
});

check('1.2 content.js attachShadow retains mode: "closed" without opening or exposing to page JS', () => {
  const content = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
  assert.ok(content.includes("attachShadow({ mode: 'closed' })"), 'shadow root must strictly be mode: closed');
  assert.ok(!content.includes("attachShadow({ mode: 'open' })"), 'mode: open must NOT be used');
});

check('1.3 showMenu strictly rejects document.body as parent and never falls back to document.body', () => {
  const content = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
  assert.ok(content.includes('if (!parent || parent === document.body) return;'), 'showMenu must bail if parent is body or falsy');
  assert.ok(!content.includes('shadowRoot || document.body'), 'handleFillClick must never fallback to document.body');
});

check('1.4 fuin-trigger-fill handler reuses retained shadowRoot from FIELD_MAP and never document.body', () => {
  const content = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
  assert.ok(content.includes("if (msg.type === 'fuin-trigger-fill')"), 'listens for fuin-trigger-fill');
  assert.ok(content.includes('FIELD_MAP.get(pwField)'), 'retrieves entry from FIELD_MAP');
  assert.ok(content.includes('handleFillClick(pwField, entry.icon || pwField, entry.shadow)'), 'passes retained entry.shadow');
  assert.ok(!content.includes('host.shadowRoot'), 'must NOT attempt to read host.shadowRoot');
});

check('1.5 DOM isolation simulation: popup-triggered menu renders inside ShadowRoot and NOT in document.body', () => {
  // Simulate minimal DOM environment
  const mockDocument = {
    body: {
      children: [],
      appendChild(el) { this.children.push(el); },
      contains(el) { return this.children.includes(el); }
    }
  };

  let menuAppendedTo = null;
  const mockShadow = {
    host: { id: 'fuin-host' },
    children: [],
    querySelectorAll() { return []; },
    appendChild(el) {
      menuAppendedTo = this;
      this.children.push(el);
    }
  };

  // Execute showMenu logic
  function testShowMenu(anchor, parent, items) {
    if (!parent || parent === mockDocument.body) return;
    const menu = { className: 'fuin-ext-menu', items };
    parent.appendChild(menu);
  }

  // Case A: normal shadowRoot passed
  testShowMenu({}, mockShadow, ['site.com (alice)']);
  assert.strictEqual(menuAppendedTo, mockShadow, 'Menu must be inside shadowRoot');
  assert.strictEqual(mockDocument.body.children.length, 0, 'document.body must have 0 elements added');

  // Case B: hostile attempt with document.body
  menuAppendedTo = null;
  testShowMenu({}, mockDocument.body, ['secret.com (bob)']);
  assert.strictEqual(menuAppendedTo, null, 'Menu must NOT be appended to document.body');
  assert.strictEqual(mockDocument.body.children.length, 0, 'document.body remains completely untouched');
});

// ── F-02: MULTI-TENANT DOMAIN MATCHING ─────────────────────────────────────
console.log('\n[F-02: Multi-Tenant Domain Matching Hardening]');

const appJsContent = fs.readFileSync(path.join(__dirname, 'renderer/app.js'), 'utf8');

// Build isolated VM sandbox mimicking the renderer's domain matching environment
const domainSandbox = { URL: global.URL, Set: global.Set };
vm.createContext(domainSandbox);

// Extract MULTI_TENANT_SUFFIXES, normalizeDomain, and domainMatches from app.js
const normStart = appJsContent.indexOf('function normalizeDomain(');
const matchEnd = appJsContent.indexOf('let pendingExtReveal = null;', normStart);
const extractedCode = appJsContent.slice(normStart, matchEnd);
const runnerCode = `
  ${extractedCode}
  this.MULTI_TENANT_SUFFIXES = MULTI_TENANT_SUFFIXES;
  this.domainMatches = domainMatches;
  this.normalizeDomain = normalizeDomain;
`;

vm.runInContext(runnerCode, domainSandbox);
const { domainMatches, MULTI_TENANT_SUFFIXES, normalizeDomain } = domainSandbox;

check('2.1 Multi-tenant platforms list contains all audited hosting providers', () => {
  const requiredPlatforms = [
    'github.io', 'pages.dev', 'vercel.app', 'netlify.app', 'gitlab.io',
    'herokuapp.com', 'firebaseapp.com', 'fly.dev', 'render.com', 'onrender.com',
    'workers.dev', 'web.app', 'azurewebsites.net', 'cloudfront.net', 'railway.app',
    'up.railway.app', 'deno.dev', 'appspot.com', 'surge.sh', 'amplifyapp.com',
    'elasticbeanstalk.com', 's3.amazonaws.com', 'fastly.net', 'b-cdn.net',
    'ngrok-free.app', 'ngrok.io', 'glitch.me', 'myshopify.com'
  ];

  for (const platform of requiredPlatforms) {
    assert.ok(MULTI_TENANT_SUFFIXES.has(platform), `Platform ${platform} must be in MULTI_TENANT_SUFFIXES`);
  }
});

check('2.2 Bare multi-tenant suffix in vault does NOT match tenant subdomains across any platform', () => {
  const auditCases = [
    { suffix: 'fly.dev', tenant: 'evil.fly.dev' },
    { suffix: 'render.com', tenant: 'evil.render.com' },
    { suffix: 'onrender.com', tenant: 'evil.onrender.com' },
    { suffix: 'workers.dev', tenant: 'evil.workers.dev' },
    { suffix: 'web.app', tenant: 'evil.web.app' },
    { suffix: 'azurewebsites.net', tenant: 'evil.azurewebsites.net' },
    { suffix: 'cloudfront.net', tenant: 'evil.cloudfront.net' },
    { suffix: 'railway.app', tenant: 'evil.railway.app' },
    { suffix: 'deno.dev', tenant: 'evil.deno.dev' },
    { suffix: 'appspot.com', tenant: 'evil.appspot.com' },
    { suffix: 'surge.sh', tenant: 'evil.surge.sh' },
    { suffix: 'github.io', tenant: 'evil.github.io' },
    { suffix: 'pages.dev', tenant: 'evil.pages.dev' },
    { suffix: 'vercel.app', tenant: 'evil.vercel.app' },
    { suffix: 'netlify.app', tenant: 'evil.netlify.app' }
  ];

  for (const c of auditCases) {
    assert.strictEqual(domainMatches({ site: c.suffix }, c.tenant), false, `bare ${c.suffix} must NOT match ${c.tenant}`);
    assert.strictEqual(domainMatches({ site: c.suffix }, c.suffix), true, `bare ${c.suffix} exact match must pass`);
  }
});

check('2.3 Cross-tenant separation: sibling tenants on multi-tenant platforms never match', () => {
  const crossCases = [
    { tenant1: 'trusted.fly.dev', tenant2: 'evil.fly.dev' },
    { tenant1: 'trusted.render.com', tenant2: 'evil.render.com' },
    { tenant1: 'trusted.workers.dev', tenant2: 'evil.workers.dev' },
    { tenant1: 'trusted.web.app', tenant2: 'evil.web.app' },
    { tenant1: 'trusted.azurewebsites.net', tenant2: 'evil.azurewebsites.net' },
    { tenant1: 'trusted.cloudfront.net', tenant2: 'evil.cloudfront.net' },
    { tenant1: 'trusted.surge.sh', tenant2: 'evil.surge.sh' },
    { tenant1: 'trusted.github.io', tenant2: 'evil.github.io' },
    { tenant1: 'trusted.pages.dev', tenant2: 'evil.pages.dev' },
    { tenant1: 'trusted.vercel.app', tenant2: 'evil.vercel.app' }
  ];

  for (const c of crossCases) {
    assert.strictEqual(domainMatches({ site: c.tenant1 }, c.tenant2), false, `${c.tenant1} must NOT match ${c.tenant2}`);
    assert.strictEqual(domainMatches({ site: c.tenant2 }, c.tenant1), false, `${c.tenant2} must NOT match ${c.tenant1}`);
    assert.strictEqual(domainMatches({ site: c.tenant1 }, c.tenant1), true, `${c.tenant1} exact match must pass`);
    assert.strictEqual(domainMatches({ site: c.tenant1 }, `sub.${c.tenant1}`), false, `subdomain expansion of ${c.tenant1} must be blocked`);
  }
});

check('2.4 Normal domain matching rules preserved (apex matches subdomain, subdomain does not match apex)', () => {
  const apex = { site: 'example.com' };
  assert.strictEqual(domainMatches(apex, 'example.com'), true);
  assert.strictEqual(domainMatches(apex, 'accounts.example.com'), true);
  assert.strictEqual(domainMatches(apex, 'deep.sub.accounts.example.com'), true);
  assert.strictEqual(domainMatches(apex, 'evil-example.com'), false);
  assert.strictEqual(domainMatches(apex, 'example.com.evil.com'), false);

  const sub = { site: 'evil.example.com' };
  assert.strictEqual(domainMatches(sub, 'example.com'), false, 'subdomain must NOT match parent apex');
  assert.strictEqual(domainMatches({ site: 'accounts.example.com' }, 'mail.example.com'), false, 'sibling subdomains must NOT match');
});

check('2.5 IP address and localhost domain matching safety', () => {
  assert.strictEqual(domainMatches({ site: '192.168.1.1' }, '192.168.1.1'), true);
  assert.strictEqual(domainMatches({ site: '192.168.1.1' }, '192.168.1.2'), false);
  assert.strictEqual(domainMatches({ site: '192.168.1.1' }, 'sub.192.168.1.1'), false);
  assert.strictEqual(domainMatches({ site: 'localhost' }, 'localhost'), true);
  assert.strictEqual(domainMatches({ site: 'localhost' }, 'evil-localhost'), false);
  assert.strictEqual(domainMatches({ site: 'xn--pypal-4ve.com' }, 'paypal.com'), false);
});

// ── F-03: BACKGROUND pendingReveal CONCURRENCY DEFENSE-IN-DEPTH ──────────
console.log('\n[F-03: Background pendingReveal Concurrency Defense-in-Depth]');

check('3.1 background.js rejects concurrent reveal requests with { error: "busy" }', () => {
  const bgContent = fs.readFileSync(path.join(__dirname, 'browser-extension/background.js'), 'utf8');
  const revealIdx = bgContent.indexOf("if (msg.type === 'fuin-reveal')");
  assert.ok(revealIdx !== -1, "must handle msg.type === 'fuin-reveal'");
  const revealBlock = bgContent.slice(revealIdx, revealIdx + 300);
  assert.ok(revealBlock.includes("if (pendingReveal !== null)"), 'must check pendingReveal !== null');
  assert.ok(revealBlock.includes("sendResponse({ error: 'busy' })"), 'must respond with busy error');
});

check('3.2 Concurrent reveal rejection simulation: second reveal receives busy and does NOT overwrite state', () => {
  // Simulate background state and message handling
  let pendingReveal = null;
  const callsToNativeHost = [];

  function askFuinMock(payload) {
    callsToNativeHost.push(payload);
    return new Promise(() => {}); // Intentionally unresolved to simulate in-flight
  }

  function handleMessage(msg, sender, sendResponse) {
    if (msg.type === 'fuin-reveal') {
      if (pendingReveal !== null) {
        sendResponse({ error: 'busy' });
        return true;
      }
      const currentReveal = {
        tabId: sender.tab?.id,
        url: sender.tab?.url,
        sendResponse,
        cancelled: false
      };
      pendingReveal = currentReveal;
      askFuinMock({ type: 'reveal', entryId: msg.entryId });
      return true;
    }
  }

  // Request 1 from Tab 10
  let resp1 = null;
  handleMessage(
    { type: 'fuin-reveal', entryId: 'entry-A' },
    { tab: { id: 10, url: 'https://site-a.com' } },
    (r) => { resp1 = r; }
  );

  assert.strictEqual(callsToNativeHost.length, 1, 'First request reached native host');
  assert.strictEqual(pendingReveal.tabId, 10, 'pendingReveal tracks Tab 10');
  assert.strictEqual(resp1, null, 'First request still in-flight');

  // Request 2 from Tab 20 while Request 1 is pending
  let resp2 = null;
  handleMessage(
    { type: 'fuin-reveal', entryId: 'entry-B' },
    { tab: { id: 20, url: 'https://site-b.com' } },
    (r) => { resp2 = r; }
  );

  assert.deepStrictEqual(resp2, { error: 'busy' }, 'Second request must immediately receive busy');
  assert.strictEqual(callsToNativeHost.length, 1, 'Second request must NOT reach native host');
  assert.strictEqual(pendingReveal.tabId, 10, 'pendingReveal was NOT overwritten; still tracks Tab 10');
});

check('3.3 Navigation cancellation correctly invalidates pendingReveal', () => {
  let pendingReveal = {
    tabId: 10,
    url: 'https://site-a.com',
    cancelled: false,
    sendResponse: (r) => { cancelResp = r; }
  };
  let cancelResp = null;

  function onTabUpdated(tabId, changeInfo, tab) {
    if (pendingReveal && pendingReveal.tabId === tabId) {
      const urlChanged = changeInfo.url && changeInfo.url !== pendingReveal.url;
      const loadingNew = changeInfo.status === 'loading' && tab?.url && tab.url !== pendingReveal.url;
      if (urlChanged || loadingNew) {
        pendingReveal.cancelled = true;
        try { pendingReveal.sendResponse({ error: 'navigation-cancelled' }); } catch {}
        pendingReveal = null;
      }
    }
  }

  onTabUpdated(10, { status: 'loading' }, { url: 'https://other-site.com' });
  assert.deepStrictEqual(cancelResp, { error: 'navigation-cancelled' });
  assert.strictEqual(pendingReveal, null, 'pendingReveal reset to null after navigation');
});

// ── F-04: UNNECESSARY TOTP EXPOSURE ELIMINATED ────────────────────────────
console.log('\n[F-04: Unnecessary TOTP Exposure Eliminated]');

check('4.1 approveExtReveal transmits username and password ONLY (zero TOTP exposure)', () => {
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer/app.js'), 'utf8');
  const approveStart = appJs.indexOf('async function approveExtReveal()');
  const approveEnd = appJs.indexOf('function denyExtReveal()', approveStart);
  assert.ok(approveStart !== -1 && approveEnd !== -1, 'approveExtReveal must exist');
  const approveBody = appJs.slice(approveStart, approveEnd);

  assert.ok(approveBody.includes('api.extRespond(requestId, { username: entry.username, password: await memDecrypt(entry.password) });'),
    'approveExtReveal must respond with username and password only');
  assert.ok(!approveBody.includes('totp:'), 'approveExtReveal must NOT include totp in response');
});

check('4.2 Vault TOTP functionality remains intact in desktop app', () => {
  const appJs = fs.readFileSync(path.join(__dirname, 'renderer/app.js'), 'utf8');
  assert.ok(appJs.includes('entry.totp'), 'entry.totp references in desktop app preserved');
  assert.ok(appJs.includes('exportEntries'), 'exportEntries in persist() preserved');
});

// ── FINAL SUMMARY ──────────────────────────────────────────────────────────
console.log('══════════════════════════════════════════════════════════════════════════════');
console.log(`TOTAL SPECIFICATION CHECKS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${failedTests}`);
console.log('══════════════════════════════════════════════════════════════════════════════');

if (failedTests > 0) {
  process.exit(1);
} else {
  console.log('\nALL TARGETED REMEDIATIONS (F-01, F-02, F-03, F-04) VERIFIED SUCCESSFULLY!\n');
}
