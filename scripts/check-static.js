#!/usr/bin/env node
'use strict';

/**
 * Fuin Static Code & Packaging Integrity Checker
 * Fast, zero-dependency static verifier for syntax, const-reassignment,
 * script/module resolution, CSP, and electron-builder packaging coverage.
 */

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const assert = require('assert');

const ROOT = path.resolve(__dirname, '..');

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
console.log('FUIN STATIC CODE & PACKAGING INTEGRITY CHECK');
console.log('═══════════════════════════════════════════════════════════════════\n');

const JS_TARGETS = [
  'main.js',
  'preload.js',
  'sync-v2.js',
  'sync-v2-crypto.js',
  'sync-v2-payload.js',
  'sync-v2-transport.js',
  'sync-lan.js',
  'main/trayManager.js',
  'main/powerMonitor.js',
  'main/extensionBridge.js',
  'services/passwordGenerator.js',
  'services/totpEngine.js',
  'services/importers/detector.js',
  'services/importers/csvImporter.js',
  'services/importers/jsonImporter.js',
  'services/importers/index.js',
  'renderer/i18n.js',
  'renderer/app.js',
  'renderer/modules/updateManager.js',
  'renderer/modules/healthScanner.js',
  'renderer/modules/syncAnimation.js',
  'renderer/modules/lanSyncController.js',
  'renderer/modules/recoveryController.js',
];

console.log('[1. JavaScript Syntax & VM Compilation]');
for (const relPath of JS_TARGETS) {
  check(`Syntax valid: ${relPath}`, () => {
    const fullPath = path.join(ROOT, relPath);
    assert.ok(fs.existsSync(fullPath), `Missing file: ${relPath}`);
    const source = fs.readFileSync(fullPath, 'utf8');
    new vm.Script(source, { filename: relPath });
  });
}

console.log('\n[2. Top-Level Const Reassignment Guard (no-const-assign)]');
for (const relPath of ['main.js', 'preload.js', 'renderer/app.js', 'sync-lan.js']) {
  check(`No top-level const reassignment in ${relPath}`, () => {
    const fullPath = path.join(ROOT, relPath);
    const lines = fs.readFileSync(fullPath, 'utf8').split('\n');
    const topConsts = [];
    lines.forEach((line, idx) => {
      const m = line.match(/^const\s+([a-zA-Z0-9_$]+)\s*=/);
      if (m) topConsts.push({ name: m[1], line: idx + 1 });
    });

    for (const c of topConsts) {
      const assignRegex = new RegExp(`\\b${c.name}\\s*=[^=]`);
      lines.forEach((line, idx) => {
        const lineNo = idx + 1;
        if (lineNo === c.line) return;
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*')) return;
        if (
          !line.includes(`const ${c.name}`) &&
          !line.includes(`let ${c.name}`) &&
          !line.includes(`var ${c.name}`) &&
          assignRegex.test(line)
        ) {
          throw new Error(
            `Const variable '${c.name}' (declared at line ${c.line}) is reassigned at line ${lineNo}: ${trimmed}`
          );
        }
      });
    }
  });
}

console.log('\n[3. Renderer HTML Script & CSP Verification]');
check('All <script src="..."> in renderer/index.html resolve to existing files', () => {
  const htmlPath = path.join(ROOT, 'renderer', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  const scriptMatches = [...html.matchAll(/<script\s+src="([^"]+)"/g)];
  assert.ok(scriptMatches.length > 0, 'Expected script tags in index.html');
  for (const m of scriptMatches) {
    const src = m[1];
    const resolved = path.resolve(path.dirname(htmlPath), src);
    assert.ok(fs.existsSync(resolved), `Broken script tag in index.html: ${src} -> ${resolved}`);
  }
});

check('CSP in renderer/index.html enforces default-src and allows data: SVG textures', () => {
  const htmlPath = path.join(ROOT, 'renderer', 'index.html');
  const html = fs.readFileSync(htmlPath, 'utf8');
  assert.ok(html.includes("default-src 'self'"), "CSP must include default-src 'self'");
  assert.ok(html.includes("img-src 'self' data:"), "CSP must include img-src 'self' data:");
});

console.log('\n[4. Electron-Builder Packaging Coverage (package.json)]');
check('package.json build.files includes main/**/*, services/**/*, and renderer/**/*', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
  const files = pkg.build && pkg.build.files ? pkg.build.files : [];
  assert.ok(files.includes('main/**/*'), 'package.json build.files must include "main/**/*"');
  assert.ok(files.includes('services/**/*'), 'package.json build.files must include "services/**/*"');
  assert.ok(files.includes('renderer/**/*'), 'package.json build.files must include "renderer/**/*"');
});

console.log('\n═══════════════════════════════════════════════════════════════════');
console.log(`STATIC CHECK SUMMARY: ${passed} PASSED, ${failed} FAILED`);
console.log('═══════════════════════════════════════════════════════════════════');

if (failed > 0) {
  process.exit(1);
}
