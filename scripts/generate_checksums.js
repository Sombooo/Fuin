#!/usr/bin/env node
'use strict';

/**
 * FUIN - Release Artifact SHA-256 Checksum Generator
 * Formats output identically to sha256sum for transparent binary verification.
 * Usage:
 *   node scripts/generate_checksums.js [directory]
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const TARGET_DIR = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, '..', 'dist');
const OUTPUT_FILE = path.join(TARGET_DIR, 'SHA256SUMS.txt');

// Installer and archive extensions to include
const ALLOWED_EXTS = new Set([
  '.dmg', '.zip', '.pkg',
  '.exe', '.msi',
  '.AppImage', '.deb', '.rpm', '.tar.gz',
  '.apk', '.aab'
]);

function computeFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', err => reject(err));
  });
}

async function main() {
  console.log('═══════════════════════════════════════════════════════════════════');
  console.log('FUIN RELEASE ARTIFACT CHECKSUM GENERATOR');
  console.log('═══════════════════════════════════════════════════════════════════\n');

  if (!fs.existsSync(TARGET_DIR)) {
    console.error(`Target directory not found: ${TARGET_DIR}`);
    console.log(`Hint: Build artifacts first with 'npm run build-mac' or create 'dist/' folder.`);
    process.exit(1);
  }

  const files = fs.readdirSync(TARGET_DIR)
    .filter(file => {
      const ext = path.extname(file).toLowerCase();
      return ALLOWED_EXTS.has(ext) && !file.startsWith('.') && !file.includes('blockmap');
    })
    .sort();

  if (files.length === 0) {
    console.log(`No release artifacts (.dmg, .exe, .zip, .apk, etc.) found in: ${TARGET_DIR}`);
    console.log(`Place release files in '${path.relative(process.cwd(), TARGET_DIR)}' and run this script again.`);
    return;
  }

  const lines = [];
  console.log(`Computing SHA-256 for ${files.length} release artifact(s) in: ${TARGET_DIR}\n`);

  for (const file of files) {
    const filePath = path.join(TARGET_DIR, file);
    const stat = fs.statSync(filePath);
    const sizeMb = (stat.size / (1024 * 1024)).toFixed(2);
    
    process.stdout.write(`► ${file} (${sizeMb} MB)... `);
    const digest = await computeFileSha256(filePath);
    console.log(`${digest}`);
    lines.push(`${digest}  ${file}`);
  }

  fs.writeFileSync(OUTPUT_FILE, lines.join('\n') + '\n', 'utf8');

  console.log('\n═══════════════════════════════════════════════════════════════════');
  console.log(`✓ Generated: ${OUTPUT_FILE}`);
  console.log(`  Users can verify with: sha256sum -c SHA256SUMS.txt`);
  console.log('═══════════════════════════════════════════════════════════════════\n');
}

main().catch(err => {
  console.error('[Error generating checksums]:', err);
  process.exit(1);
});
