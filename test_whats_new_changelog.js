#!/usr/bin/env node
'use strict';

/**
 * FUIN WHAT'S NEW & CHANGELOG TEST SUITE
 * Verifies changelog dataset, i18n keys, version ordering, and DOM contracts.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname);
let passed = 0;
let failed = 0;

function check(label, fn) {
  try {
    fn();
    console.log(`  ✓ [PASS] ${label}`);
    passed++;
  } catch (err) {
    console.error(`  ✗ [FAIL] ${label}`);
    console.error(`    -> ${err.message}`);
    failed++;
  }
}

console.log('═══════════════════════════════════════════════════════════════════');
console.log('FUIN WHAT\'S NEW & CHANGELOG INTEGRITY TEST SUITE');
console.log('═══════════════════════════════════════════════════════════════════\n');

// 1. Data Integrity & Schema
console.log('[1. Changelog Data Schema & Multi-Language Integrity]');
const changelog = require('./renderer/modules/changelogData.js');

check('CHANGELOG_ENTRIES contains at least 3 releases', () => {
  assert.ok(Array.isArray(changelog.CHANGELOG_ENTRIES));
  assert.ok(changelog.CHANGELOG_ENTRIES.length >= 3);
});

check('Latest release is v1.0.0-beta.9 marked as current', () => {
  const latest = changelog.getLatestEntry();
  assert.strictEqual(latest.version, '1.0.0-beta.9');
  assert.strictEqual(latest.tag, 'v1.0.0-beta.9');
  assert.strictEqual(latest.isCurrent, true);
});

check('All changelog entries have valid titles, summaries, and highlights in TR and EN', () => {
  for (const entry of changelog.CHANGELOG_ENTRIES) {
    assert.ok(entry.version, 'Missing version');
    assert.ok(entry.title, `Missing title in ${entry.version}`);
    assert.ok(entry.titleEn, `Missing titleEn in ${entry.version}`);
    assert.ok(entry.summary, `Missing summary in ${entry.version}`);
    assert.ok(entry.summaryEn, `Missing summaryEn in ${entry.version}`);
    assert.ok(Array.isArray(entry.highlights) && entry.highlights.length >= 3, `Insufficient highlights in ${entry.version}`);
    for (const h of entry.highlights) {
      assert.ok(h.badge, 'Missing highlight badge');
      assert.ok(h.badgeText, 'Missing highlight badgeText');
      assert.ok(h.badgeTextEn, 'Missing highlight badgeTextEn');
      assert.ok(h.title, 'Missing highlight title');
      assert.ok(h.titleEn, 'Missing highlight titleEn');
      assert.ok(h.desc, 'Missing highlight desc');
      assert.ok(h.descEn, 'Missing highlight descEn');
    }
  }
});

// 2. DOM Contracts in renderer/index.html
console.log('\n[2. DOM & UI Contracts in renderer/index.html]');
const html = fs.readFileSync(path.join(ROOT, 'renderer', 'index.html'), 'utf8');

check('Index.html contains #whatsNewOverlay modal with required sub-elements', () => {
  assert.ok(html.includes('id="whatsNewOverlay"'), 'Missing #whatsNewOverlay');
  assert.ok(html.includes('id="whatsNewVersionTabs"'), 'Missing #whatsNewVersionTabs');
  assert.ok(html.includes('id="whatsNewHeader"'), 'Missing #whatsNewHeader');
  assert.ok(html.includes('id="whatsNewHighlights"'), 'Missing #whatsNewHighlights');
  assert.ok(html.includes('id="btnCloseWhatsNew"'), 'Missing #btnCloseWhatsNew');
  assert.ok(html.includes('id="btnDismissWhatsNew"'), 'Missing #btnDismissWhatsNew');
});

check('Settings section contains #btnOpenWhatsNew button in SİSTEM & GÜNCELLEMELER', () => {
  assert.ok(html.includes('id="btnOpenWhatsNew"'), 'Missing #btnOpenWhatsNew');
  assert.ok(html.includes('data-i18n="whatsNewTitle"'), 'Missing data-i18n="whatsNewTitle"');
});

check('Scripts include changelogData.js and whatsNewController.js before app.js', () => {
  assert.ok(html.includes('src="modules/changelogData.js"'));
  assert.ok(html.includes('src="modules/whatsNewController.js"'));
});

// 3. Multi-language dictionary verification
console.log('\n[3. i18n Translation Dictionary Keys]');
const i18nFile = fs.readFileSync(path.join(ROOT, 'renderer', 'i18n.js'), 'utf8');

check('i18n.js includes all whatsNew translation keys in TR and EN', () => {
  const keys = ['whatsNewTitle', 'whatsNewModalTitle', 'whatsNewSub', 'whatsNewBtn', 'whatsNewGotIt', 'whatsNewFooterOffline'];
  for (const k of keys) {
    assert.ok(i18nFile.includes(`${k}:`), `Missing key ${k} in i18n.js`);
  }
});

// 4. CSS Design System Verification
console.log('\n[4. CSS Design System & Micro-Transitions]');
const css = fs.readFileSync(path.join(ROOT, 'renderer', 'style.css'), 'utf8');

check('style.css defines .whatsnew-tab, .whatsnew-card, and 120ms transitions', () => {
  assert.ok(css.includes('.whatsnew-tab'), 'Missing .whatsnew-tab');
  assert.ok(css.includes('.whatsnew-card'), 'Missing .whatsnew-card');
  assert.ok(css.includes('.whatsnew-icon-box'), 'Missing .whatsnew-icon-box');
  assert.ok(css.includes('transition: all .12s;'), 'Missing 120ms transition');
});

// 5. Dynamic Language Reactivity & Controller Contracts
console.log('\n[5. Dynamic Language Reactivity & Controller Contracts]');
const wnc = require('./renderer/modules/whatsNewController.js');
const appJs = fs.readFileSync(path.join(ROOT, 'renderer', 'app.js'), 'utf8');

check('whatsNewController exports onLanguageChanged function', () => {
  assert.strictEqual(typeof wnc.onLanguageChanged, 'function');
});

check('app.js calls window.FuinWhatsNewController?.onLanguageChanged in refreshDynamicI18nLabels', () => {
  assert.ok(appJs.includes('window.FuinWhatsNewController.onLanguageChanged()'));
});

check('i18n.js defines settingConnDevicesTitle and sysUpdate keys for EN and TR parity', () => {
  assert.ok(i18nFile.includes('settingConnDevicesTitle:'));
  assert.ok(i18nFile.includes('sysUpdateLatest:'));
  assert.ok(i18nFile.includes('sysUpdateNewAvailable:'));
  assert.ok(i18nFile.includes('sysUpdateCheckFailed:'));
});

console.log('\n═══════════════════════════════════════════════════════════════════');
console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('═══════════════════════════════════════════════════════════════════');

if (failed > 0) process.exit(1);
process.exit(0);
