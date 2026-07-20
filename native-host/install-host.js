#!/usr/bin/env node
'use strict';
// ═══════════════════════════════════════════════════════════════════
// Native messaging host'unu tarayıcıya kaydeder.
// Kullanım:
//   node install-host.js --chrome-id=<eklenti_id>
//   node install-host.js --firefox-id=fuin@yourdomain.example
//
// Chrome eklenti ID'sini görmek için: chrome://extensions → Geliştirici
// Modu → eklentiyi yükle → orada gösterilen ID'yi kopyala.
// ═══════════════════════════════════════════════════════════════════
const fs = require('fs');
const os = require('os');
const path = require('path');

const HOST_NAME = 'com.fuin.nativehost';
const HOST_JS   = path.join(__dirname, 'host.js');

const args = Object.fromEntries(process.argv.slice(2).map(a => {
  const [k, v] = a.replace(/^--/, '').split('=');
  return [k, v ?? true];
}));

const chromeExtId  = args['chrome-id'];
const firefoxExtId = args['firefox-id'];

if (!chromeExtId && !firefoxExtId) {
  console.log(`
Kullanım:
  node install-host.js --chrome-id=<chrome_eklenti_id>
  node install-host.js --firefox-id=<firefox_eklenti_id>
  (İkisini birden de verebilirsin.)

Chrome eklenti ID'si: chrome://extensions sayfasında, Geliştirici Modu
açıkken "Paketlenmemiş öğe yükle" ile browser-extension/ klasörünü
yükledikten sonra orada görünür.
`);
  process.exit(1);
}

// Windows'ta host script'i doğrudan çalıştırılamaz — bir .bat sarmalayıcı gerekir.
// macOS/Linux'ta da PATH'e güvenmiyoruz: tarayıcı GUI'den başlatıldığında
// (Dock/Finder) kabuk profilindeki (zshrc/nvm vb.) PATH devreye girmez,
// bu yüzden "#!/usr/bin/env node" bazen "node bulunamadı" hatası verir.
// Bunun yerine şu an çalışan node'un TAM yolunu (process.execPath) doğrudan
// sarmalayıcıya gömüyoruz.
function ensureWrapper() {
  const nodePath = process.execPath; // örn. /usr/local/bin/node ya da nvm yolu
  if (process.platform === 'win32') {
    const batPath = path.join(__dirname, 'host.bat');
    fs.writeFileSync(batPath, `@echo off\r\n"${nodePath}" "${HOST_JS}" %*\r\n`);
    return batPath;
  }
  const shPath = path.join(__dirname, 'host.sh');
  fs.writeFileSync(shPath, `#!/bin/sh\nexec "${nodePath}" "${HOST_JS}" "$@"\n`);
  fs.chmodSync(shPath, 0o755);
  console.log('  (node yolu sabitlendi:', nodePath, ')');
  return shPath;
}

function writeManifest(targetPath, allowedKey, allowedValue) {
  const manifest = {
    name: HOST_NAME,
    description: 'Fuin Şifre Yöneticisi — Native Messaging Köprüsü',
    path: ensureWrapper(),
    type: 'stdio',
    [allowedKey]: [allowedValue],
  };
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, JSON.stringify(manifest, null, 2));
  console.log('✓ Yazıldı:', targetPath);
}

const home = os.homedir();

if (chromeExtId) {
  const origin = `chrome-extension://${chromeExtId}/`;
  const targets = {
    darwin: path.join(home, 'Library/Application Support/Google/Chrome/NativeMessagingHosts', `${HOST_NAME}.json`),
    linux:  path.join(home, '.config/google-chrome/NativeMessagingHosts', `${HOST_NAME}.json`),
    win32:  null, // Windows'ta registry kullanılır, aşağıda ayrı ele alınıyor
  };
  if (process.platform === 'win32') {
    const manifestPath = path.join(__dirname, `${HOST_NAME}.json`);
    writeManifest(manifestPath, 'allowed_origins', origin);
    console.log(`
Windows: aşağıdaki registry anahtarını elle (veya bir .reg dosyasıyla) ekle:
  [HKEY_CURRENT_USER\\Software\\Google\\Chrome\\NativeMessagingHosts\\${HOST_NAME}]
  @="${manifestPath.replace(/\\/g, '\\\\')}"
`);
  } else {
    writeManifest(targets[process.platform], 'allowed_origins', origin);
  }
  // Edge ve Brave, Chrome ile aynı Native Messaging formatını kullanır — farklı klasörler
  if (process.platform === 'darwin') {
    writeManifest(path.join(home, 'Library/Application Support/Microsoft Edge/NativeMessagingHosts', `${HOST_NAME}.json`), 'allowed_origins', origin);
    writeManifest(path.join(home, 'Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${HOST_NAME}.json`), 'allowed_origins', origin);
  } else if (process.platform === 'linux') {
    writeManifest(path.join(home, '.config/microsoft-edge/NativeMessagingHosts', `${HOST_NAME}.json`), 'allowed_origins', origin);
    writeManifest(path.join(home, '.config/BraveSoftware/Brave-Browser/NativeMessagingHosts', `${HOST_NAME}.json`), 'allowed_origins', origin);
  }
}

if (firefoxExtId) {
  // Zen Browser Firefox çekirdekli ama bilinen bir hatası var: native
  // messaging host manifestini kendi profil klasörü yerine Mozilla'nın
  // klasöründen okuyor (bkz. zen-browser/desktop #10622, #13214).
  // Bu yüzden hem Zen'e özel hem Mozilla fallback klasörüne birlikte yazıyoruz.
  const targetsByPlatform = {
    darwin: [
      path.join(home, 'Library/Application Support/zen/NativeMessagingHosts', `${HOST_NAME}.json`),
      path.join(home, 'Library/Application Support/Mozilla/NativeMessagingHosts', `${HOST_NAME}.json`),
    ],
    linux: [
      path.join(home, '.zen/native-messaging-hosts', `${HOST_NAME}.json`),
      path.join(home, '.mozilla/native-messaging-hosts', `${HOST_NAME}.json`),
    ],
  };
  if (process.platform === 'win32') {
    const manifestPath = path.join(__dirname, `${HOST_NAME}-firefox.json`);
    writeManifest(manifestPath, 'allowed_extensions', firefoxExtId);
    console.log(`
Windows (Zen/Firefox): aşağıdaki registry anahtarını ekle:
  [HKEY_CURRENT_USER\\Software\\Mozilla\\NativeMessagingHosts\\${HOST_NAME}]
  @="${manifestPath.replace(/\\/g, '\\\\')}"
(Zen de Gecko tabanlı olduğu için Mozilla anahtarını okur.)
`);
  } else {
    for (const t of (targetsByPlatform[process.platform] || [])) {
      writeManifest(t, 'allowed_extensions', firefoxExtId);
    }
  }
}

console.log('\nKurulum tamamlandı. Fuin çalışırken tarayıcıyı yeniden başlat.');
