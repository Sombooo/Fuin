'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kekkai', {
  platform:            process.platform,
  minimize:            ()               => ipcRenderer.send('win-minimize'),
  maximize:            ()               => ipcRenderer.send('win-maximize'),
  close:               ()               => ipcRenderer.send('win-close'),
  openUrl:             (url)            => ipcRenderer.send('open-url', url),
  openBackupFolder:    ()               => ipcRenderer.invoke('open-backup-folder'),

  encrypt:             (data, password) => ipcRenderer.invoke('encrypt', { data, password }),
  decrypt:             (b64, password)  => ipcRenderer.invoke('decrypt', { b64, password }),
  safeCompare:         (a, b)           => ipcRenderer.invoke('safe-compare', { a, b }),
  zxcvbn:              (pw)             => ipcRenderer.invoke('zxcvbn', pw),
  cryptoInfo:          ()               => ipcRenderer.invoke('crypto-info'),
  openSyncWindow:      (pw, enc)        => ipcRenderer.invoke('open-sync-window', { password: pw, encryptedB64: enc }),
  rebuildChunks:       (enc, size)      => ipcRenderer.invoke('rebuild-chunks', { encryptedB64: enc, chunkSize: size }),
  clearSyncKey:        ()               => ipcRenderer.invoke('clear-sync-key'),
  onSyncChunksReady:   (cb)             => ipcRenderer.on('sync-chunks-ready', (_, d) => cb(d)),
  onSyncError:         (cb)             => ipcRenderer.on('sync-error', (_, e) => cb(e)),
  onSyncKeyExpired:    (cb)             => ipcRenderer.on('sync-key-expired', cb),
  closeSyncWindow:     ()               => ipcRenderer.send('sync-win-close'),

  // Pano — main process üzerinden, 30s sonra temizlenir
  copySecure:          (text)           => ipcRenderer.invoke('copy-secure', text),
  cancelClipboardClear:()               => ipcRenderer.invoke('cancel-clipboard-clear'),
  onClipboardCleared:  (cb)             => ipcRenderer.on('clipboard-cleared', cb),

  loadData:            ()               => ipcRenderer.invoke('load-data'),
  saveData:            (enc)            => ipcRenderer.invoke('save-data', enc),
  dataExists:          ()               => ipcRenderer.invoke('data-exists'),

  saveRecovery:        (d)              => ipcRenderer.invoke('save-recovery', d),
  loadRecovery:        ()               => ipcRenderer.invoke('load-recovery'),
  recoveryExists:      ()               => ipcRenderer.invoke('recovery-exists'),

  // master.enc — şifre sıfırlamada vault'u yeniden şifrelemek için
  // localStorage yerine kullanılır; dosyaya main process yazar
  saveMasterEnc:       (d)              => ipcRenderer.invoke('save-master-enc', d),
  loadMasterEnc:       ()               => ipcRenderer.invoke('load-master-enc'),

  fullReset:           ()               => ipcRenderer.invoke('full-reset'),

  // Faz 2 — Auto-lock: idle timeout, ekran kilidi, suspend tetikleyicileri
  setUnlockState:      (u)              => ipcRenderer.invoke('set-unlock-state', u),
  onAutoLockWarning:   (cb)             => ipcRenderer.on('auto-lock-warning', (_, sec) => cb(sec)),
  onAutoLockWarningCancel: (cb)         => ipcRenderer.on('auto-lock-warning-cancel', cb),
  onForceLock:         (cb)             => ipcRenderer.on('force-lock', (_, reason) => cb(reason)),

  // Tarayıcı eklentisi köprüsü
  getExtToken:         ()               => ipcRenderer.invoke('get-ext-token'),
  extBridgeStatus:     ()               => ipcRenderer.invoke('ext-bridge-status'),
  onExtLookupRequest:  (cb)             => ipcRenderer.on('ext-lookup-request', (_, d) => cb(d)),
  onExtRevealRequest:  (cb)             => ipcRenderer.on('ext-reveal-request', (_, d) => cb(d)),
  extRespond:          (requestId, payload) => ipcRenderer.invoke('ext-response', { requestId, payload }),

  exportFile:          (opts)           => ipcRenderer.invoke('export-file', opts),
  importFile:          (opts)           => ipcRenderer.invoke('import-file', opts),
});
