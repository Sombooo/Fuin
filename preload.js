'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('kekkai', {
  platform:            process.platform,
  minimize:            ()               => ipcRenderer.send('win-minimize'),
  maximize:            ()               => ipcRenderer.send('win-maximize'),
  close:               ()               => ipcRenderer.send('win-close'),
  openUrl:             (url)            => ipcRenderer.send('open-url', url),
  openBackupFolder:    ()               => ipcRenderer.invoke('open-backup-folder'),
  getAppVersion:       ()               => ipcRenderer.invoke('get-app-version'),

  encrypt:             (data, password) => ipcRenderer.invoke('encrypt', { data, password }),
  decrypt:             (b64, password)  => ipcRenderer.invoke('decrypt', { b64, password }),
  safeCompare:         (a, b)           => ipcRenderer.invoke('safe-compare', { a, b }),
  zxcvbn:              (pw)             => ipcRenderer.invoke('zxcvbn', pw),
  cryptoInfo:          ()               => ipcRenderer.invoke('crypto-info'),
  // V2: Sync Password is separate from Vault Password (Full Vault Snapshot Only)
  openSyncWindowV2:    (syncPw, entries) => ipcRenderer.invoke('open-sync-window', { syncPassword: syncPw, entries }),
  clearSyncKey:        ()               => ipcRenderer.invoke('clear-sync-key'),
  onSyncChunksReady:   (cb)             => { const h = (_, d) => cb(d); ipcRenderer.on('sync-chunks-ready', h); return () => ipcRenderer.removeListener('sync-chunks-ready', h); },
  onSyncError:         (cb)             => { const h = (_, e) => cb(e); ipcRenderer.on('sync-error', h); return () => ipcRenderer.removeListener('sync-error', h); },
  onSyncKeyExpired:    (cb)             => { ipcRenderer.on('sync-key-expired', cb); return () => ipcRenderer.removeListener('sync-key-expired', cb); },
  closeSyncWindow:     ()               => ipcRenderer.send('sync-win-close'),

  // Pano — main process üzerinden, 30s sonra temizlenir
  copySecure:          (text)           => ipcRenderer.invoke('copy-secure', text),
  cancelClipboardClear:()               => ipcRenderer.invoke('cancel-clipboard-clear'),
  onClipboardCleared:  (cb)             => { ipcRenderer.on('clipboard-cleared', cb); return () => ipcRenderer.removeListener('clipboard-cleared', cb); },

  loadData:            ()               => ipcRenderer.invoke('load-data'),
  saveData:            (enc)            => ipcRenderer.invoke('save-data', enc),
  dataExists:          ()               => ipcRenderer.invoke('data-exists'),

  saveRecoveryPair:    (recovery, masterEnc) => ipcRenderer.invoke('save-recovery-pair', { recovery, masterEnc }),
  loadRecovery:        ()               => ipcRenderer.invoke('load-recovery'),
  recoveryExists:      ()               => ipcRenderer.invoke('recovery-exists'),
  getRecoveryStatus:   ()               => ipcRenderer.invoke('get-recovery-status'),

  // master.enc — şifre sıfırlamada vault'u yeniden şifrelemek için
  // localStorage yerine kullanılır; dosyaya main process yazar
  loadMasterEnc:       ()               => ipcRenderer.invoke('load-master-enc'),

  fullReset:           ()               => ipcRenderer.invoke('full-reset'),

  // Faz 2 — Auto-lock: idle timeout, ekran kilidi, suspend tetikleyicileri
  setUnlockState:      (u)              => ipcRenderer.invoke('set-unlock-state', u),
  onAutoLockWarning:   (cb)             => { const h = (_, sec) => cb(sec); ipcRenderer.on('auto-lock-warning', h); return () => ipcRenderer.removeListener('auto-lock-warning', h); },
  onAutoLockWarningCancel: (cb)         => { ipcRenderer.on('auto-lock-warning-cancel', cb); return () => ipcRenderer.removeListener('auto-lock-warning-cancel', cb); },
  onForceLock:         (cb)             => { const h = (_, reason) => cb(reason); ipcRenderer.on('force-lock', h); return () => ipcRenderer.removeListener('force-lock', h); },
  setIdleLock:         (s)              => ipcRenderer.invoke('set-idle-lock', s),
  checkTouchId:        ()               => ipcRenderer.invoke('check-touchid-available'),
  touchIdUnlock:       ()               => ipcRenderer.invoke('touchid-unlock'),
  saveTouchIdKey:      (k)              => ipcRenderer.invoke('save-touchid-key', k),
  clearTouchIdKey:     ()               => ipcRenderer.invoke('clear-touchid-key'),

  // Tarayıcı eklentisi köprüsü
  getExtToken:         ()               => ipcRenderer.invoke('get-ext-token-masked'),
  extBridgeStatus:     ()               => ipcRenderer.invoke('ext-bridge-status'),
  onExtLookupRequest:  (cb)             => { const h = (_, d) => cb(d); ipcRenderer.on('ext-lookup-request', h); return () => ipcRenderer.removeListener('ext-lookup-request', h); },
  onExtRevealRequest:  (cb)             => { const h = (_, d) => cb(d); ipcRenderer.on('ext-reveal-request', h); return () => ipcRenderer.removeListener('ext-reveal-request', h); },
  extRespond:          (requestId, payload) => ipcRenderer.invoke('ext-response', { requestId, payload }),

  exportFile:          (opts)           => ipcRenderer.invoke('export-file', opts),
  importFile:          (opts)           => ipcRenderer.invoke('import-file', opts),
});
