'use strict';
// Tarayıcının native host ile konuşurken yaptığı şeyi birebir simüle eder.
// Kullanım: node test-native-host.js /tam/yol/host.sh
const { spawn } = require('child_process');

const hostPath = process.argv[2];
if (!hostPath) { console.error('Kullanım: node test-native-host.js /tam/yol/host.sh'); process.exit(1); }

console.log('Başlatılıyor:', hostPath);
const child = spawn(hostPath, [], { stdio: ['pipe', 'pipe', 'pipe'] });

child.on('error', (e) => console.error('✗ SPAWN HATASI (process hiç başlamadı):', e.message));
child.on('exit', (code, signal) => console.log(`(process kapandı — code=${code} signal=${signal})`));
child.stderr.on('data', (d) => console.error('✗ STDERR:', d.toString()));

let buf = Buffer.alloc(0);
child.stdout.on('data', (chunk) => {
  buf = Buffer.concat([buf, chunk]);
  if (buf.length >= 4) {
    const len = buf.readUInt32LE(0);
    if (buf.length >= 4 + len) {
      console.log('✓ CEVAP ALINDI:', JSON.parse(buf.slice(4, 4 + len).toString('utf8')));
      process.exit(0);
    }
  }
});

// Tarayıcının göndereceği ile birebir aynı formatta bir test mesajı yolla
const msg = JSON.stringify({ type: 'lookup', domain: 'test.com' });
const msgBuf = Buffer.from(msg, 'utf8');
const lenBuf = Buffer.alloc(4);
lenBuf.writeUInt32LE(msgBuf.length, 0);
child.stdin.write(Buffer.concat([lenBuf, msgBuf]));

setTimeout(() => { console.error('✗ ZAMAN AŞIMI — 5sn içinde cevap gelmedi'); process.exit(1); }, 5000);
