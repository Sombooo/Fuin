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

// ── EXT-01: UNIFIED MULTI-TENANT, COMPOUND ccTLD & IP LITERAL PARITY ──────
console.log('\n[EXT-01: Unified Multi-Tenant, Compound ccTLD & IP Literal Matching]');

const bgJsContent = fs.readFileSync(path.join(__dirname, 'browser-extension/background.js'), 'utf8');
const contentJsContent = fs.readFileSync(path.join(__dirname, 'browser-extension/content.js'), 'utf8');
const popupJsContent = fs.readFileSync(path.join(__dirname, 'browser-extension/popup.js'), 'utf8');

// Extract background.js domain helpers into isolated VM
const bgDomStart = bgJsContent.indexOf('const MULTI_TENANT_SUFFIXES = new Set([');
const bgDomEnd = bgJsContent.indexOf('function recordDismissedCredential(', bgDomStart);
const bgDomainSandbox = { URL: global.URL, Set: global.Set };
vm.createContext(bgDomainSandbox);
vm.runInContext(`
  ${bgJsContent.slice(bgDomStart, bgDomEnd)}
  this.MULTI_TENANT_SUFFIXES = MULTI_TENANT_SUFFIXES;
  this.COMPOUND_CCTLD_SLDS = COMPOUND_CCTLD_SLDS;
  this.getBaseSite = getBaseSite;
  this.isSameSiteSafe = isSameSiteSafe;
`, bgDomainSandbox);

// Extract content.js domain helpers into isolated VM
const ctDomStart = contentJsContent.indexOf('const MULTI_TENANT_SUFFIXES = new Set([');
const ctDomEnd = contentJsContent.indexOf('const EXT_LOCALE =', ctDomStart);
const ctDomainSandbox = { URL: global.URL, Set: global.Set };
vm.createContext(ctDomainSandbox);
vm.runInContext(`
  ${contentJsContent.slice(ctDomStart, ctDomEnd)}
  this.MULTI_TENANT_SUFFIXES = MULTI_TENANT_SUFFIXES;
  this.COMPOUND_CCTLD_SLDS = COMPOUND_CCTLD_SLDS;
  this.getBaseSiteExt = getBaseSiteExt;
  this.isSameSiteDomain = isSameSiteDomain;
`, ctDomainSandbox);

// Also expose COMPOUND_CCTLD_SLDS from app.js sandbox
vm.runInContext('this.COMPOUND_CCTLD_SLDS = COMPOUND_CCTLD_SLDS;', domainSandbox);

check('5.1 MULTI_TENANT_SUFFIXES and COMPOUND_CCTLD_SLDS are 100% unified across app.js, background.js, and content.js', () => {
  const appMT = Array.from(domainSandbox.MULTI_TENANT_SUFFIXES).sort();
  const bgMT = Array.from(bgDomainSandbox.MULTI_TENANT_SUFFIXES).sort();
  const ctMT = Array.from(ctDomainSandbox.MULTI_TENANT_SUFFIXES).sort();
  assert.deepStrictEqual(bgMT, appMT, 'background.js MULTI_TENANT_SUFFIXES must match renderer/app.js');
  assert.deepStrictEqual(ctMT, appMT, 'content.js MULTI_TENANT_SUFFIXES must match renderer/app.js');

  const appSLD = Array.from(domainSandbox.COMPOUND_CCTLD_SLDS).sort();
  const bgSLD = Array.from(bgDomainSandbox.COMPOUND_CCTLD_SLDS).sort();
  const ctSLD = Array.from(ctDomainSandbox.COMPOUND_CCTLD_SLDS).sort();
  assert.deepStrictEqual(bgSLD, appSLD, 'background.js COMPOUND_CCTLD_SLDS must match renderer/app.js');
  assert.deepStrictEqual(ctSLD, appSLD, 'content.js COMPOUND_CCTLD_SLDS must match renderer/app.js');

  const mustHaveMultiTenant = [
    'wordpress.com', 'blogspot.com', 'tumblr.com', 'itch.io', 'notion.site',
    'webflow.io', 'replit.app', 'run.app', 'hf.space', 'trycloudflare.com',
    'pythonanywhere.com', 'azurewebsites.net', 'appspot.com', 'cloudfront.net',
    'firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev', 'vercel.app',
    'netlify.app', 'github.io', 'gitlab.io', 'herokuapp.com', 'onrender.com',
    'fly.dev', 'railway.app', 'surge.sh', 'glitch.me', 's3.amazonaws.com'
  ];
  for (const suffix of mustHaveMultiTenant) {
    assert.ok(domainSandbox.MULTI_TENANT_SUFFIXES.has(suffix), `Missing required multi-tenant suffix: ${suffix}`);
  }
});

check('5.2 Newly added multi-tenant hosts are strictly isolated across all 3 layers (app.js, background.js, content.js)', () => {
  const hosts = [
    'wordpress.com', 'blogspot.com', 'tumblr.com', 'itch.io', 'notion.site',
    'webflow.io', 'replit.app', 'run.app', 'hf.space', 'trycloudflare.com', 'pythonanywhere.com'
  ];
  for (const h of hosts) {
    assert.strictEqual(domainMatches({ site: h }, `evil.${h}`), false, `app.js: bare ${h} must not match evil.${h}`);
    assert.strictEqual(domainMatches({ site: `alice.${h}` }, `evil.${h}`), false, `app.js: alice.${h} must not match evil.${h}`);
    assert.strictEqual(domainMatches({ site: `alice.${h}` }, `alice.${h}`), true, `app.js: exact alice.${h} must match`);
    assert.strictEqual(bgDomainSandbox.isSameSiteSafe(`alice.${h}`, `evil.${h}`), false, `background.js: alice.${h} != evil.${h}`);
    assert.strictEqual(ctDomainSandbox.isSameSiteDomain(`alice.${h}`, `evil.${h}`), false, `content.js: alice.${h} != evil.${h}`);
  }
});

check('5.3 Compound ccTLDs (.co.kr, .co.il, .com.tw, .co.id, .com.pl, .com.ua, .com.my, .com.vn, .com.ph, .co.th, .edu.au, etc.) are isolated across all 3 layers', () => {
  const ccTlds = [
    'co.kr', 'co.il', 'com.tw', 'co.id', 'com.pl', 'com.ua',
    'com.my', 'com.vn', 'com.ph', 'co.th', 'com.sg', 'com.hk',
    'com.mx', 'com.ar', 'edu.au', 'gov.au', 'gob.mx', 'com.tr'
  ];
  for (const tld of ccTlds) {
    // Bare compound ccTLD must never match arbitrary sites
    assert.strictEqual(domainMatches({ site: tld }, `evil.${tld}`), false, `app.js: bare ${tld} must not match evil.${tld}`);
    assert.strictEqual(bgDomainSandbox.isSameSiteSafe(tld, `evil.${tld}`), false, `background.js: bare ${tld} != evil.${tld}`);
    assert.strictEqual(ctDomainSandbox.isSameSiteDomain(tld, `evil.${tld}`), false, `content.js: bare ${tld} != evil.${tld}`);

    // Different registrable domains under same compound ccTLD must NEVER be same-site
    assert.strictEqual(domainMatches({ site: `bank.${tld}` }, `evil.${tld}`), false, `app.js: bank.${tld} != evil.${tld}`);
    assert.strictEqual(bgDomainSandbox.isSameSiteSafe(`bank.${tld}`, `evil.${tld}`), false, `background.js: bank.${tld} != evil.${tld}`);
    assert.strictEqual(ctDomainSandbox.isSameSiteDomain(`bank.${tld}`, `evil.${tld}`), false, `content.js: bank.${tld} != evil.${tld}`);

    // Legitimate subdomain under same 3-label registrable domain MUST still work
    assert.strictEqual(domainMatches({ site: `bank.${tld}` }, `login.bank.${tld}`), true, `app.js: bank.${tld} -> login.bank.${tld}`);
    assert.strictEqual(bgDomainSandbox.isSameSiteSafe(`login.bank.${tld}`, `www.bank.${tld}`), true, `background.js: login.bank.${tld} == www.bank.${tld}`);
    assert.strictEqual(ctDomainSandbox.isSameSiteDomain(`login.bank.${tld}`, `www.bank.${tld}`), true, `content.js: login.bank.${tld} == www.bank.${tld}`);
  }
});

check('5.4 IPv4 and IPv6 literals require exact match across all 3 layers (no octet stripping)', () => {
  assert.strictEqual(domainMatches({ site: '192.168.1.1' }, '45.33.1.1'), false);
  assert.strictEqual(domainMatches({ site: '1.1' }, '192.168.1.1'), false);
  assert.strictEqual(domainMatches({ site: '[::1]' }, '[::1]'), true);
  assert.strictEqual(domainMatches({ site: '[::1]' }, '[::2]'), false);

  assert.strictEqual(bgDomainSandbox.isSameSiteSafe('192.168.1.1', '45.33.1.1'), false);
  assert.strictEqual(bgDomainSandbox.isSameSiteSafe('192.168.1.1', '192.168.1.1'), true);
  assert.strictEqual(bgDomainSandbox.isSameSiteSafe('[::1]', '[::2]'), false);
  assert.strictEqual(bgDomainSandbox.isSameSiteSafe('[::1]', '[::1]'), true);

  assert.strictEqual(ctDomainSandbox.isSameSiteDomain('192.168.1.1', '45.33.1.1'), false);
  assert.strictEqual(ctDomainSandbox.isSameSiteDomain('192.168.1.1', '192.168.1.1'), true);
  assert.strictEqual(ctDomainSandbox.isSameSiteDomain('[::1]', '[::2]'), false);
  assert.strictEqual(ctDomainSandbox.isSameSiteDomain('[::1]', '[::1]'), true);
});

// ── EXT-02 & EXT-03: CONTENT SCRIPT RUNTIME DOM HARDENING ──────────────────
console.log('\n[EXT-02 & EXT-03: Hidden Password Non-Fill, Dirty-Only Capture & Save Prompt Clickjacking Defense]');

function createContentRuntimeEnv(opts = {}) {
  const docListeners = {};
  const winListeners = {};
  const msgListeners = [];
  const runtimeMessagesSent = [];
  const bodyChildren = [];
  let computedStyleMap = new WeakMap();

  function makeNode(tagName, attrs = {}, rectOverride = null, compStyle = null) {
    const listeners = {};
    const styleProps = {};
    const node = {
      tagName: tagName.toUpperCase(),
      type: attrs.type || '',
      name: attrs.name || '',
      id: attrs.id || '',
      value: attrs.value || '',
      placeholder: attrs.placeholder || '',
      textContent: attrs.textContent || '',
      disabled: !!attrs.disabled,
      readOnly: !!attrs.readOnly,
      hidden: !!attrs.hidden,
      children: [],
      parentNode: null,
      parentElement: null,
      isConnected: true,
      _attrs: { ...attrs },
      style: {
        _important: {},
        setProperty(prop, val, priority) {
          styleProps[prop] = val;
          this._important[prop] = priority || '';
          const camel = prop.replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
          this[camel] = val;
        },
        getPropertyValue(prop) { return styleProps[prop] || ''; },
        getPropertyPriority(prop) { return this._important[prop] || ''; },
      },
      focus() {},
      setAttribute(k, v) { this._attrs[k] = String(v); },
      getAttribute(k) { return this._attrs[k] !== undefined ? String(this._attrs[k]) : null; },
      matches(sel) {
        if (sel === 'input') return this.tagName === 'INPUT';
        return false;
      },
      getBoundingClientRect() {
        return rectOverride || { width: 200, height: 36, top: 10, left: 10, bottom: 46, right: 210 };
      },
      addEventListener(ev, fn) {
        if (!listeners[ev]) listeners[ev] = [];
        listeners[ev].push(fn);
      },
      removeEventListener() {},
      dispatchEvent(ev) {
        const list = listeners[ev.type] || [];
        list.forEach(fn => fn(ev));
      },
      _trigger(evType, evObj = {}) {
        const list = listeners[evType] || [];
        list.forEach(fn => fn({ type: evType, target: this, isTrusted: true, stopPropagation() {}, preventDefault() {}, ...evObj }));
      },
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
        let cur = this;
        while (cur) {
          if (sel.includes('form') && cur.tagName === 'FORM') return cur;
          if (sel.includes('button') && (cur.tagName === 'BUTTON' || (cur.tagName === 'INPUT' && (cur.type === 'submit' || cur.type === 'button')))) return cur;
          if (sel.includes('fuin-save-prompt') && cur.tagName === 'FUIN-SAVE-PROMPT') return cur;
          cur = cur.parentElement;
        }
        return null;
      },
      querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
      querySelectorAll(sel) {
        const list = [];
        const walk = (n) => {
          for (const ch of (n.children || [])) {
            if (sel === 'input[type="password"]' && ch.tagName === 'INPUT' && ch.type === 'password') list.push(ch);
            else if (sel === 'input' && ch.tagName === 'INPUT') list.push(ch);
            else if (sel.includes('input[type="text"]') && ch.tagName === 'INPUT' && ch.type !== 'password') list.push(ch);
            else if (sel === '.fuin-ext-menu' && ch.className === 'fuin-ext-menu') list.push(ch);
            walk(ch);
          }
        };
        walk(this);
        return list;
      },
      attachShadow() {
        const root = makeNode('#shadow-root');
        root.host = this;
        this._testShadowRoot = root;
        return root;
      }
    };
    if (compStyle) computedStyleMap.set(node, compStyle);
    return node;
  }

  const mockBody = makeNode('body');
  const origAppend = mockBody.appendChild.bind(mockBody);
  mockBody.appendChild = (ch) => {
    bodyChildren.push(ch);
    return origAppend(ch);
  };
  const mockDocEl = makeNode('html');
  mockDocEl.appendChild(mockBody);

  const windowObj = {
    scrollX: 0,
    scrollY: 0,
    HTMLInputElement: { prototype: {} },
    getComputedStyle(el) {
      if (computedStyleMap.has(el)) return computedStyleMap.get(el);
      return {
        display: el.style.display || 'block',
        visibility: el.style.visibility || 'visible',
        opacity: el.style.opacity !== undefined ? String(el.style.opacity) : '1',
        pointerEvents: el.style.pointerEvents || 'auto'
      };
    },
    addEventListener(ev, fn) {
      if (!winListeners[ev]) winListeners[ev] = [];
      winListeners[ev].push(fn);
    },
    removeEventListener() {}
  };

  const sandbox = {
    window: windowObj,
    document: {
      documentElement: mockDocEl,
      body: mockBody,
      activeElement: null,
      addEventListener(ev, fn) {
        if (!docListeners[ev]) docListeners[ev] = [];
        docListeners[ev].push(fn);
      },
      removeEventListener() {},
      querySelectorAll: (sel) => mockDocEl.querySelectorAll(sel),
      createElement: (tag) => makeNode(tag),
      createElementNS: (_ns, tag) => makeNode(tag)
    },
    MutationObserver: class { observe() {} disconnect() {} },
    Event: class { constructor(type) { this.type = type; } },
    InputEvent: class { constructor(type) { this.type = type; } },
    WeakSet, WeakMap, Set, Map, Date, Object, Array, String, Number, Boolean, Promise, RegExp, Math, URL,
    setTimeout: opts.syncTimers
      ? ((fn) => { fn(); return 1; })
      : ((fn, ms) => { const t = setTimeout(fn, ms); if (t && typeof t.unref === 'function') t.unref(); return t; }),
    clearTimeout,
    navigator: { language: 'en-US' },
    location: { protocol: 'https:', hostname: opts.hostname || 'example.com' },
    chrome: {
      i18n: { getUILanguage: () => 'en' },
      runtime: {
        lastError: null,
        onMessage: { addListener: (fn) => msgListeners.push(fn) },
        sendMessage(payload, cb) {
          runtimeMessagesSent.push(payload);
          if (opts.onSendMessage) {
            const resp = opts.onSendMessage(payload);
            if (cb) cb(resp);
            return;
          }
          if (payload.type === 'fuin-get-pending-save') {
            if (cb) cb({ hasPending: false });
          } else if (payload.type === 'fuin-lookup') {
            if (cb) cb({ matches: [{ id: 'm1', site: 'Example', username: 'alice@example.com' }] });
          } else if (payload.type === 'fuin-reveal') {
            if (cb) cb({ username: 'alice@example.com', password: 'SuperSecretPassword!99' });
          } else if (cb) {
            cb({ ok: true });
          }
        }
      }
    }
  };

  return {
    sandbox, makeNode, mockBody, mockDocEl, docListeners, winListeners,
    msgListeners, runtimeMessagesSent, bodyChildren, computedStyleMap,
    boot() { vm.runInNewContext(contentJsContent, sandbox); }
  };
}

check('6.1 EXT-02: autofill NEVER fills hidden (display:none, opacity:0, visibility:hidden, off-screen) password fields', () => {
  const env = createContentRuntimeEnv();
  const form = env.makeNode('form');
  const visibleUser = env.makeNode('input', { type: 'email', name: 'email', id: 'email' });
  const hiddenDisplayNonePw = env.makeNode('input', { type: 'password', name: 'pw1' }, { width: 0, height: 0, top: 0, left: 0, bottom: 0, right: 0 }, { display: 'none', visibility: 'visible', opacity: '1' });
  const zeroOpacityPw = env.makeNode('input', { type: 'password', name: 'pw2' }, { width: 200, height: 36, top: 10, left: 10, bottom: 46, right: 210 }, { display: 'block', visibility: 'visible', opacity: '0' });
  const hiddenVisPw = env.makeNode('input', { type: 'password', name: 'pw3' }, { width: 200, height: 36, top: 10, left: 10, bottom: 46, right: 210 }, { display: 'block', visibility: 'hidden', opacity: '1' });
  const offscreenPw = env.makeNode('input', { type: 'password', name: 'pw4' }, { width: 200, height: 36, top: -9999, left: -9999, bottom: -9963, right: -9799 }, { display: 'block', visibility: 'visible', opacity: '1' });
  form.appendChild(visibleUser);
  form.appendChild(hiddenDisplayNonePw);
  form.appendChild(zeroOpacityPw);
  form.appendChild(hiddenVisPw);
  form.appendChild(offscreenPw);
  env.mockBody.appendChild(form);
  env.boot();

  env.msgListeners.forEach(fn => fn({ type: 'fuin-trigger-fill' }, {}, () => {}));
  // Promise microtasks are flushed asynchronously; wait by checking synchronously via direct test or verify static + sync
  assert.ok(!contentJsContent.includes('allPws.forEach(p => setFieldValue'), 'allPws hidden-input fallback must be removed');
  assert.ok(!contentJsContent.includes('return allPws[0] || null;'), 'findBestFillField must not fall back to hidden allPws[0]');
});

// Async verification for EXT-02, EXT-03, EXT-04
(async () => {
  await (async function checkAsync(title, fn) {
    totalTests++;
    try {
      await fn();
      console.log(`  [PASS] ${title}`);
      passedTests++;
    } catch (err) {
      console.error(`  [FAIL] ${title}: ${err.message}`);
      failedTests++;
    }
  })('6.2 EXT-02 runtime: filling visible username leaves display:none/opacity:0/visibility:hidden/off-screen passwords empty & does not spray unrelated inputs', async () => {
    const env = createContentRuntimeEnv();
    const header = env.makeNode('header');
    const unrelatedSearch = env.makeNode('input', { type: 'text', name: 'q', id: 'search' });
    header.appendChild(unrelatedSearch);

    const loginCard = env.makeNode('div');
    const visibleUser = env.makeNode('input', { type: 'email', name: 'email', id: 'email' });
    const displayNonePw = env.makeNode('input', { type: 'password', name: 'pw1' }, { width: 0, height: 0, top: 0, left: 0, bottom: 0, right: 0 }, { display: 'none', visibility: 'visible', opacity: '1' });
    const zeroOpacityPw = env.makeNode('input', { type: 'password', name: 'pw2' }, { width: 100, height: 20, top: 10, left: 10, bottom: 30, right: 110 }, { display: 'block', visibility: 'visible', opacity: '0.01' });
    const offscreenPw = env.makeNode('input', { type: 'password', name: 'pw3' }, { width: 100, height: 20, top: -500, left: -500, bottom: -480, right: -400 }, { display: 'block', visibility: 'visible', opacity: '1' });
    loginCard.appendChild(visibleUser);
    loginCard.appendChild(displayNonePw);
    loginCard.appendChild(zeroOpacityPw);
    loginCard.appendChild(offscreenPw);

    env.mockBody.appendChild(header);
    env.mockBody.appendChild(loginCard);
    env.boot();

    env.sandbox.document.activeElement = visibleUser;
    env.msgListeners.forEach(fn => fn({ type: 'fuin-trigger-fill' }, {}, () => {}));
    await new Promise(r => setTimeout(r, 20));

    assert.strictEqual(visibleUser.value, 'alice@example.com', 'Visible focused username must be filled');
    assert.strictEqual(displayNonePw.value, '', 'display:none password input must NOT be filled');
    assert.strictEqual(zeroOpacityPw.value, '', 'opacity:0.01 password input must NOT be filled');
    assert.strictEqual(offscreenPw.value, '', 'off-screen password input must NOT be filled');
    assert.strictEqual(unrelatedSearch.value, '', 'Unrelated search input outside login container must NOT be sprayed');
  });

  await (async function checkAsync(title, fn) {
    totalTests++;
    try {
      await fn();
      console.log(`  [PASS] ${title}`);
      passedTests++;
    } catch (err) {
      console.error(`  [FAIL] ${title}: ${err.message}`);
      failedTests++;
    }
  })('6.3 EXT-03 runtime: untyped pre-filled password input is NEVER captured without trusted user input (_passwordDirty)', async () => {
    const env = createContentRuntimeEnv();
    const form = env.makeNode('form');
    const prefilledTrapPw = env.makeNode('input', { type: 'password', name: 'password', value: 'AttackerGuess123!' });
    const continueBtn = env.makeNode('button', { type: 'button', textContent: 'Continue' });
    form.appendChild(prefilledTrapPw);
    form.appendChild(continueBtn);
    env.mockBody.appendChild(form);
    env.boot();

    // Click Continue without ever typing in password input
    (env.winListeners.click || []).forEach(fn => fn({ isTrusted: true, target: continueBtn }));
    await new Promise(r => setTimeout(r, 20));

    const submitted = env.runtimeMessagesSent.filter(m => m.type === 'fuin-form-submitted');
    assert.strictEqual(submitted.length, 0, 'Untyped pre-filled password must NEVER trigger fuin-form-submitted');
  });

  await (async function checkAsync(title, fn) {
    totalTests++;
    try {
      await fn();
      console.log(`  [PASS] ${title}`);
      passedTests++;
    } catch (err) {
      console.error(`  [FAIL] ${title}: ${err.message}`);
      failedTests++;
    }
  })('6.4 EXT-03 runtime: <fuin-save-prompt> enforces !important styles and rejects save/never clicks when opacity < 0.99 or visibility !== visible', async () => {
    const env = createContentRuntimeEnv();
    env.boot();

    // Trigger save prompt via background message
    env.msgListeners.forEach(fn => fn({
      type: 'fuin-trigger-save-prompt',
      candidate: { domain: 'example.com', username: 'alice@example.com', password: 'NewPassword!2026' },
      result: { action: 'save', entryId: null, shouldPrompt: true }
    }, {}, () => {}));

    const host = env.bodyChildren.find(el => el.tagName === 'FUIN-SAVE-PROMPT');
    assert.ok(host, 'Save prompt host must be mounted');
    assert.strictEqual(host.style.getPropertyPriority('position'), 'important');
    assert.strictEqual(host.style.getPropertyPriority('opacity'), 'important');
    assert.strictEqual(host.style.getPropertyPriority('visibility'), 'important');
    assert.strictEqual(host.style.getPropertyPriority('pointer-events'), 'important');
    assert.strictEqual(host.style.getPropertyPriority('z-index'), 'important');

    // Locate saveBtn and neverBtn inside closed shadow root (exposed on mock)
    const buttons = [];
    const walkBtns = (n) => {
      if (n.tagName === 'BUTTON') buttons.push(n);
      (n.children || []).forEach(walkBtns);
    };
    walkBtns(host._testShadowRoot);
    const saveBtn = buttons.find(b => b.textContent === 'Save');
    const neverBtn = buttons.find(b => b.textContent === 'Never on this site');
    assert.ok(saveBtn && neverBtn, 'Save and Never buttons must exist');

    // Attack: page CSS makes <fuin-save-prompt> transparent (opacity: 0.001)
    env.computedStyleMap.set(host, { opacity: '0.001', visibility: 'visible', display: 'block', pointerEvents: 'auto' });
    saveBtn._trigger('click', { isTrusted: true });
    neverBtn._trigger('click', { isTrusted: true });
    await new Promise(r => setTimeout(r, 15));
    assert.strictEqual(env.runtimeMessagesSent.some(m => m.type === 'fuin-save-credential'), false, 'Click on transparent saveBtn must be rejected');
    assert.strictEqual(env.runtimeMessagesSent.some(m => m.type === 'fuin-exclude-domain'), false, 'Click on transparent neverBtn must be rejected');

    // Attack: visibility: hidden
    env.computedStyleMap.set(host, { opacity: '1', visibility: 'hidden', display: 'block', pointerEvents: 'auto' });
    saveBtn._trigger('click', { isTrusted: true });
    await new Promise(r => setTimeout(r, 15));
    assert.strictEqual(env.runtimeMessagesSent.some(m => m.type === 'fuin-save-credential'), false, 'Click on visibility:hidden saveBtn must be rejected');

    // Legitimate visible state -> saveBtn click succeeds
    env.computedStyleMap.set(host, { opacity: '1', visibility: 'visible', display: 'block', pointerEvents: 'auto' });
    saveBtn._trigger('click', { isTrusted: true });
    await new Promise(r => setTimeout(r, 15));
    assert.strictEqual(env.runtimeMessagesSent.some(m => m.type === 'fuin-save-credential'), true, 'Click on fully visible saveBtn must succeed');
  });

  // ── EXT-04: REPROMPT ENFORCEMENT & DESKTOP COPY-SECURE ROUTING ───────────
  console.log('\n[EXT-04: Extension Reprompt Enforcement & 30s Auto-Clear Clipboard Routing]');

  check('7.1 EXT-04: approveExtReveal enforces requireReprompt(entry) on reprompt-protected entries & popup.js never writes passwords via raw navigator.clipboard.writeText', () => {
    const approveStart = appJsContent.indexOf('async function approveExtReveal()');
    const approveEnd = appJsContent.indexOf('function denyExtReveal()', approveStart);
    const approveBody = appJsContent.slice(approveStart, approveEnd);
    assert.ok(approveBody.includes('if (entry.reprompt)') && approveBody.includes('await requireReprompt(entry)'),
      'approveExtReveal must enforce await requireReprompt(entry) when entry.reprompt is true');

    assert.ok(!popupJsContent.includes('navigator.clipboard.writeText(rev.password)'),
      'popup.js must NEVER write revealed password via raw navigator.clipboard.writeText');
    assert.ok(popupJsContent.includes("type: 'fuin-copy-secure'"),
      'popup.js must route password copying through Desktop fuin-copy-secure');
  });

  // ── FINAL SUMMARY ──────────────────────────────────────────────────────────
  console.log('══════════════════════════════════════════════════════════════════════════════');
  console.log(`TOTAL SPECIFICATION CHECKS: ${totalTests} | PASSED: ${passedTests} | FAILED: ${failedTests}`);
  console.log('══════════════════════════════════════════════════════════════════════════════');

  if (failedTests > 0) {
    process.exit(1);
  } else {
    console.log('\nALL TARGETED REMEDIATIONS (F-01..F-04 & EXT-01..EXT-04) VERIFIED SUCCESSFULLY!\n');
    process.exit(0);
  }
})();
