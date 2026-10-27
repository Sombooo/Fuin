'use strict';

/**
 * FUIN UI Polish Sprint — Challenger 1 Adversarial Verification Suite
 * Verifies Desktop UI changes in renderer/index.html and renderer/app.js.
 */

const fs = require('fs');
const path = require('path');
const assert = require('assert');

console.log('═══════════════════════════════════════════════════════════════');
console.log('FUIN UI POLISH — CHALLENGER 1 DESKTOP UI VERIFICATION');
console.log('═══════════════════════════════════════════════════════════════\n');

let passCount = 0;
let failCount = 0;

function test(description, fn) {
  try {
    fn();
    console.log(`  ✓ ${description}`);
    passCount++;
  } catch (err) {
    console.error(`  ✗ ${description}`);
    console.error(`    Error: ${err.message}`);
    failCount++;
  }
}

const htmlPath = path.join(__dirname, 'renderer', 'index.html');
const appJsPath = path.join(__dirname, 'renderer', 'app.js');
const cssPath = path.join(__dirname, 'renderer', 'style.css');

const htmlContent = fs.readFileSync(htmlPath, 'utf8');
const appJsContent = fs.readFileSync(appJsPath, 'utf8');
const cssContent = fs.readFileSync(cssPath, 'utf8');

// ── 1. HTML STRUCTURE VERIFICATION ──────────────────────────────────────────

console.log('[SUITE 1] HTML Structure of #overlaySyncPass');

const overlayStart = htmlContent.indexOf('<div id="overlaySyncPass"');
const overlayEnd = htmlContent.indexOf('<script src="./app.js">');
assert(overlayStart !== -1 && overlayEnd !== -1, '#overlaySyncPass container block must exist in index.html');
const overlayHtml = htmlContent.slice(overlayStart, overlayEnd);

test('Contains #overlaySyncPass container element', () => {
  assert.ok(htmlContent.includes('id="overlaySyncPass"'));
  assert.ok(overlayHtml.includes('class="overlay"'));
});

test('Contains .modal child container', () => {
  assert.ok(/class="[^"]*\bmodal\b[^"]*"/.test(overlayHtml), 'Must contain .modal');
});

test('Contains .modal-head child container with title and close button', () => {
  assert.ok(/class="[^"]*\bmodal-head\b[^"]*"/.test(overlayHtml), 'Must contain .modal-head');
  assert.ok(overlayHtml.includes('SENKRONİZASYON ŞİFRESİ'), 'Must contain header title');
});

test('Contains .modal-body child container', () => {
  assert.ok(/class="[^"]*\bmodal-body\b[^"]*"/.test(overlayHtml), 'Must contain .modal-body');
});

test('Contains .fg form group container', () => {
  assert.ok(/class="[^"]*\bfg\b[^"]*"/.test(overlayHtml), 'Must contain .fg');
  assert.ok(
    overlayHtml.includes('<label for="syncPasswordInput">') ||
    /<label[^>]*for="syncPasswordInput"[^>]*>/.test(overlayHtml),
    'Must contain label for syncPasswordInput'
  );
});

test('Contains .pw-row container', () => {
  assert.ok(/class="[^"]*\bpw-row\b[^"]*"/.test(overlayHtml), 'Must contain .pw-row');
});

test('Contains .fi standard input field', () => {
  assert.ok(/class="[^"]*\bfi\b[^"]*"/.test(overlayHtml), 'Must contain .fi');
  assert.ok(overlayHtml.includes('id="syncPasswordInput"'), 'Must have id="syncPasswordInput"');
});

test('Contains #btnEyeSyncPass toggle button with .icon-btn', () => {
  assert.ok(overlayHtml.includes('id="btnEyeSyncPass"'), 'Must contain id="btnEyeSyncPass"');
  assert.ok(/class="[^"]*\bicon-btn\b[^"]*"/.test(overlayHtml), 'Must use .icon-btn class');
});

test('Contains .modal-footer container', () => {
  assert.ok(/class="[^"]*\bmodal-footer\b[^"]*"/.test(overlayHtml), 'Must contain .modal-footer');
});

test('Contains .btn-cancel element with id="btnCancelSyncPass"', () => {
  assert.ok(/class="[^"]*\bbtn-cancel\b[^"]*"/.test(overlayHtml), 'Must contain .btn-cancel');
  assert.ok(overlayHtml.includes('id="btnCancelSyncPass"'), 'Must contain id="btnCancelSyncPass"');
});

test('Contains .btn-save element with id="btnConfirmSyncPass"', () => {
  assert.ok(/class="[^"]*\bbtn-save\b[^"]*"/.test(overlayHtml), 'Must contain .btn-save');
  assert.ok(overlayHtml.includes('id="btnConfirmSyncPass"'), 'Must contain id="btnConfirmSyncPass"');
});

// ── 2. CRITICAL DOM IDS VERIFICATION ────────────────────────────────────────

console.log('\n[SUITE 2] 5 Critical DOM IDs Presence and Uniqueness');

const criticalIds = [
  'overlaySyncPass',
  'syncPasswordInput',
  'btnCloseSyncPass',
  'btnCancelSyncPass',
  'btnConfirmSyncPass'
];

criticalIds.forEach(id => {
  test(`DOM ID "${id}" is present and strictly unique in index.html`, () => {
    const regex = new RegExp(`id=["']${id}["']`, 'g');
    const matches = htmlContent.match(regex) || [];
    assert.strictEqual(matches.length, 1, `DOM ID "${id}" must appear exactly once in index.html, found ${matches.length}`);
  });
});

// ── 3. AESTHETICS & NOVELTY STYLING CHECK ────────────────────────────────────

console.log('\n[SUITE 3] Aesthetic Purity & Novelty Styling Checks');

test('No gradients (linear, radial, conic) present in #overlaySyncPass', () => {
  const gradientMatch = overlayHtml.match(/gradient/i);
  assert.strictEqual(gradientMatch, null, `Found unwanted gradient: ${gradientMatch}`);
});

test('No heavy box-shadow or novelty glows in #overlaySyncPass', () => {
  const shadowMatch = overlayHtml.match(/box-shadow/i);
  assert.strictEqual(shadowMatch, null, `Found unwanted box-shadow in overlay: ${shadowMatch}`);
});

test('No novelty animations, transforms, or keyframes in #overlaySyncPass inline styles', () => {
  const animMatch = overlayHtml.match(/animation|keyframes|transform:\s*scale/i);
  assert.strictEqual(animMatch, null, `Found unwanted animation/transform: ${animMatch}`);
});

test('Theme variable conformance: uses standard FUIN design tokens (--mono, --mu, --amber, --ac)', () => {
  assert.ok(overlayHtml.includes('var(--mono)'), 'Must use --mono for typography');
  assert.ok(overlayHtml.includes('var(--mu)'), 'Must use --mu for muted text');
  assert.ok(overlayHtml.includes('var(--amber)'), 'Must use --amber for warning accent');
  assert.ok(overlayHtml.includes('var(--ac)'), 'Must use --ac for header title');
});

test('Classes used in #overlaySyncPass are formally defined in renderer/style.css', () => {
  const classMatches = [...overlayHtml.matchAll(/class=["']([^"']+)["']/g)];
  const usedClasses = new Set();
  classMatches.forEach(m => m[1].split(/\s+/).forEach(c => c && usedClasses.add(c)));

  const expectedDefinedClasses = ['overlay', 'modal', 'modal-head', 'modal-title', 'modal-close', 'modal-body', 'fg', 'pw-row', 'fi', 'pw-row-btns', 'icon-btn', 'modal-footer', 'btn-cancel', 'btn-save'];
  for (const cls of expectedDefinedClasses) {
    assert.ok(usedClasses.has(cls), `Expected class .${cls} to be used in overlay`);
    assert.ok(cssContent.includes(`.${cls}`), `Class .${cls} must be defined in style.css`);
  }
});

// ── 4. RENDERER CONTROLLER & BEHAVIOR CHECK ─────────────────────────────────

console.log('\n[SUITE 4] Renderer Controller (app.js) Logic & Ergonomics');

test('app.js initializes inputSyncPass.type to "password" and resets value on open', () => {
  assert.ok(appJsContent.includes("inputSyncPass.type = 'password'"));
  assert.ok(appJsContent.includes("inputSyncPass.value = ''"));
});

test('app.js cleanup resets display, value, and restores type="password"', () => {
  const cleanupFn = appJsContent.match(/const cleanup = \(\) => \{([\s\S]*?)\};/);
  assert.ok(cleanupFn, 'cleanup function must exist');
  assert.ok(cleanupFn[1].includes("overlaySyncPass.style.display = 'none'"));
  assert.ok(cleanupFn[1].includes("inputSyncPass.value = ''"));
  assert.ok(cleanupFn[1].includes("inputSyncPass.type = 'password'"));
});

test('app.js binds close and cancel buttons to cleanup', () => {
  assert.ok(appJsContent.includes("document.getElementById('btnCloseSyncPass').onclick = cleanup"));
  assert.ok(appJsContent.includes("document.getElementById('btnCancelSyncPass').onclick = cleanup"));
});

test('app.js binds eye toggle to toggleEye("syncPasswordInput")', () => {
  assert.ok(appJsContent.includes("toggleEye('syncPasswordInput')"));
  assert.ok(appJsContent.includes("btnEyeSyncPass.onclick = () => toggleEye('syncPasswordInput')"));
});

test('app.js supports keyboard ergonomics: Enter confirms, Escape cancels', () => {
  assert.ok(appJsContent.includes("e.key === 'Enter'"));
  assert.ok(appJsContent.includes("document.getElementById('btnConfirmSyncPass').click()"));
  assert.ok(appJsContent.includes("e.key === 'Escape'"));
  assert.ok(appJsContent.includes("cleanup()"));
});

test('app.js validates sync password requirement before initiating sync', () => {
  assert.ok(appJsContent.includes("!syncPassword || syncPassword.trim().length === 0"));
  assert.ok(
    appJsContent.includes("toast(t('toastSyncPassRequired')") ||
    appJsContent.includes("toast('Sync şifresi gereklidir.')")
  );
});

// ── SUMMARY ─────────────────────────────────────────────────────────────────

console.log('\n═══════════════════════════════════════════════════════════════');
console.log(`CHALLENGER 1 RESULT: ${passCount} PASSED, ${failCount} FAILED`);
console.log('═══════════════════════════════════════════════════════════════\n');

if (failCount > 0) {
  process.exit(1);
}
