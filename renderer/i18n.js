'use strict';
// ═══════════════════════════════════════════════════════════════════
// FUIN — ÇOKLU DİL DESTEĞİ (i18n)
//
// Kullanım:
//   - Statik metin: <div data-i18n="key">...</div>  → textContent değişir
//   - Placeholder:   <input data-i18n-placeholder="key"> → placeholder değişir
//   - Title/tooltip:  <button data-i18n-title="key">  → title değişir
//   - JS içinde:      t('key')                        → çeviriyi döndürür
//
// Kapsam: Tüm UI metinleri (titlebar, kilit ekranı, kenar menü, kayıt
// listesi, ekleme/düzenleme formu, modallar, sağlık raporu, güvenlik
// bilgisi, dışa-içe aktar, sync penceresi, tarayıcı eklentisi izin
// modalı, toast mesajları, zxcvbn gücü vb.) tam olarak çevrilmiştir.
// ═══════════════════════════════════════════════════════════════════

const TRANSLATIONS = {
  tr: {
    appSubtitle: 'Şifre Yöneticisi',
    themeToggleTitle: 'Koyu/Açık mod',
    langToggleTitle: 'Dil / Language',

    lockMasterLabel: 'Ana Şifre',
    lockMasterPh: 'şifrenizi girin...',
    lockVerifying: 'doğrulanıyor...',
    lockUnlockBtn: 'AÇIK →',
    lockForgot: 'şifremi unuttum',
    lockHardReset: 'tüm verileri sıfırla',
    lockHintFirstUse: 'İlk kullanımda istediğiniz şifreyi belirleyin.',
    lockHintLocalOnly: 'Tüm veriler <em>yalnızca bu cihazda</em> saklanır.',

    navSectionView: 'Görünüm',
    navAll: 'Tüm Kayıtlar',
    navFav: 'Favoriler',
    navSectionCategories: 'Kategoriler',
    navSectionTools: 'Araçlar',
    navHealth: 'Sağlık Raporu',
    navSecurity: 'Güvenlik Bilgisi',
    navIO: 'Dışa / İçe Aktar',
    navSync: 'Air-Gap Sync',
    navLock: '◉ Kilitle',

    viewTitleAll: 'TÜM KAYITLAR',
    viewTitleFav: 'FAVORİLER',
    searchPh: 'ara...',
    btnNew: '+ YENİ',

    modalNewEntry: 'YENİ KAYIT',
    modalEditEntry: 'KAYDI DÜZENLE',
    fieldSite: 'Site / Uygulama',
    fieldSitePh: 'Gmail, GitHub...',
    fieldCategory: 'Kategori',
    fieldUser: 'Kullanıcı Adı / E-posta',
    fieldUserPh: 'kullanici@email.com',
    fieldPassword: 'Şifre',
    fieldNote: 'Not (opsiyonel)',
    fieldNotePh: 'güvenlik sorusu, ipucu...',
    fieldUrl: 'URL (opsiyonel)',
    section2FA: 'İki Faktörlü Doğrulama',
    toggle2FALabel: '2FA Kodu Sakla',
    toggle2FASub: 'TOTP secret key',
    toggleFavLabel: 'Favorilere Ekle',
    toggleFavSub: 'Kenar çubuğunda göster',
    btnCancel: 'İptal',
    btnSave: 'Kaydet',
    genPwTitle: 'Üret',
    showPwTitle: 'Göster',

    cat_social: 'Sosyal Medya', cat_email: 'E-posta', cat_finance: 'Finans',
    cat_shopping: 'Alışveriş', cat_work: 'İş / Kurumsal', cat_gaming: 'Oyun',
    cat_dev: 'Geliştirici / Araçlar', cat_other: 'Diğer',

    totpModalTitle: '2FA KODU',
    totpHint: 'koda tıkla → kopyala',

    recoveryTitle: 'KURTARMA ANAHTARI',
    recoveryBody: 'Ana şifrenizi unutursanız bu anahtar ile şifrenizi sıfırlayabilirsiniz.',
    recoveryWarn: 'Güvenli bir yere not edin. Bir daha gösterilmeyecek.',
    recoveryHint: 'anahtara tıkla → kopyala',
    recoverySavedBtn: 'Kaydettim, Kapat',

    forgotTitle: 'ŞİFRE SIFIRLAMA',
    forgotBody: 'Kurtarma anahtarınızı girin, ardından yeni şifre belirleyin.',
    forgotKeyLabel: 'Kurtarma Anahtarı',
    forgotNewPwLabel: 'Yeni Ana Şifre',
    forgotNewPwPh: 'yeni şifreniz...',
    forgotVerifyBtn: 'Doğrula',

    hardResetTitle: '⚠ UYARI: TAM SIFIRLAMA',
    hardResetBody1: 'Bu işlem <span style="color:var(--red);font-weight:600">tüm kayıtlarınızı, şifrenizi ve kurtarma anahtarınızı kalıcı olarak siler.</span>',
    hardResetBody2: 'Geri alınamaz. Devam etmek için aşağıya <span style="color:var(--red)">SIFIRLA</span> yazın.',
    hardResetConfirmLabel: 'Onay',
    hardResetBtn: 'Sıfırla',

    autoLockTitle: '⏱ HAREKETSİZLİK UYARISI',
    autoLockBody: 'Uzun süredir hareket algılanmadı.<br>Aşağıdaki sürenin sonunda otomatik kilitlenecek.',
    autoLockStillHere: 'Hâlâ Buradayım',

    extReqTitle: '⬡ TARAYICI EKLENTİSİ İSTEĞİ',
    extReqFor: 'için kimlik bilgisi isteniyor.',
    extReqSite: 'KAYIT',
    extReqUser: 'KULLANICI',
    extReqDeny: 'Reddet',
    extReqAllow: 'İzin Ver',

    healthTitle: 'SAĞLIK RAPORU',
    healthScanBtn: '⌖ Sızıntı Taraması',
    healthScanBtnAgain: '⌖ Tekrar Tara',
    healthScanning: 'taranıyor...',
    healthInfoBox: '<em>k-Anonymity:</em> Şifreleriniz hiçbir zaman gönderilmez. Yalnızca SHA-1 hash\'inin ilk 5 karakteri HaveIBeenPwned\'e gider; eşleşme kontrolü tamamen bu cihazda yapılır.',
    healthWeak: 'Zayıf', healthMedium: 'Orta', healthStrong: 'Güçlü',
    healthDup: 'Tekrarlanan', health2FA: '2FA Aktif', healthTotal: 'Toplam',
    healthWeakSection: 'Zayıf Şifreler', healthDupSection: 'Tekrarlanan Şifreler',
    healthDupTag: 'tekrarlanan', healthNoIssues: '✓ sorun bulunamadı',
    hibpAllClean: 'Tüm şifreler temiz — sızıntı bulunamadı',
    hibpBreachedSection: 'Sızıntıda Bulunanlar',
    hibpBreachedCount: '× sızdırılmış',
    hibpChangeBtn: 'Değiştir',
    hibpCheckFailed: 'kayıt kontrol edilemedi',
    hibpNoEntries: 'taranacak kayıt yok',
    hibpFoundToast: 'sızıntı bulundu',
    hibpCleanToast: 'tüm şifreler temiz',

    securityTitle: 'GÜVENLİK BİLGİSİ',
    securityInfoBox: 'Bu uygulama tüm kriptografik işlemleri Electron\'un ana procesinde Node.js <em>crypto</em> modülü ile çalıştırır. Şifreleme mantığı hiçbir zaman tarayıcı ortamına (renderer) taşınmaz.',
    secKdf: 'Anahtar Türetme', secDualKey: 'Dual Key', secDualKeySub: 'Tek master\'dan iki bağımsız anahtar',
    secEncryption: 'Şifreleme', secRamZero: 'RAM Zeroing', secRamZeroVal: 'Aktif', secRamZeroSub: 'Buffer.fill(0) her işlem sonrası',
    secTiming: 'Timing Attack', secTimingVal: 'Korumalı', secClipboard: 'Pano', secClipboardVal: '30s Auto-Clear',
    secEntropy: 'Entropi Analizi', secEntropyReal: 'Tahmin bazlı gerçek zamanlı', secEntropySimple: 'Regex tabanlı', secEntropySimpleName: 'Basit',
    secQrSync: 'QR Sync', secQrReady: 'Hazır', secQrSub: 'SyncKey ile şifreli chunk\'lar',

    ioTitle: 'DIŞA / İÇE AKTAR',
    ioExportJsonTitle: '↑ JSON Dışa Aktar', ioExportJsonSub: 'Tüm kayıtları JSON formatında kaydedin.', ioExportJsonBtn: 'JSON İndir',
    ioExportCsvTitle: '↑ CSV Dışa Aktar', ioExportCsvSub: 'Tüm kayıtları CSV olarak kaydedin.', ioExportCsvBtn: 'CSV İndir',
    ioImportJsonTitle: '↓ JSON İçe Aktar', ioImportJsonSub: 'Önceki Fuin yedeğini geri yükleyin.', ioImportJsonBtn: 'JSON Seç',
    ioImportCsvTitle: '↓ CSV İçe Aktar', ioImportCsvSub: 'site, username, password sütunlu CSV.', ioImportCsvBtn: 'CSV Seç',
    ioWarnBox: '⚠ Dışa aktarılan dosyalar şifresiz düz metin içerir. Güvenli bir konumda saklayın.',
    sysTitle: 'SİSTEM & GÜNCELLEMELER',
    sysUpdateCheckTitle: '⟳ Sürüm Kontrolü',
    sysUpdateCheckSub: 'Fuin\'in yeni bir sürümü olup olmadığını GitHub üzerinden kontrol edin. Mevcut sürüm: v1.0.0',
    sysUpdateBtn: 'Şimdi Denetle',
    sysBackupTitle: '⛁ Yedekleme Klasörü',
    sysBackupSub: 'Otomatik alınan geçmiş kasa yedeklerinize (.bak dosyaları) erişin.',
    sysBackupBtn: 'Klasörü Aç',
    slogan: 'Quietly secure.',

    toastClipCleared: 'pano temizlendi ✓',
    toastCopiedDefault: 'kopyalandı',
    toastClipTimer: 'pano {s}s sonra temizlenir',
    toastMinChars: 'en az 8 karakter girin',
    toastWrongPassword: 'yanlış şifre',
    toastExtCredSent: 'kimlik bilgisi eklentiye gönderildi',
    toastSiteRequired: 'site ve şifre zorunlu',
    toastDeleted: 'silindi',
    toastAllDataErased: 'tüm veriler silindi — yeni şifre belirleyebilirsiniz',
    toastPasswordUpdated: 'şifre güncellendi — giriş yapabilirsiniz',
    toastRecoveryCopied: 'kurtarma anahtarı kopyalandı',
    toastAppReset: 'uygulama sıfırlandı',
    toastLoginFirst: 'önce giriş yapın',
    toastSyncOpening: 'sync penceresi açılıyor...',
    toastNoDataToSync: 'senkronize edilecek veri yok',
    toastSyncFailed: 'sync başlatılamadı: ',
    toastJsonExported: 'json dışa aktarıldı',
    toastCsvExported: 'csv dışa aktarıldı',
    toastEntriesAdded: 'kayıt eklendi',
    toastInvalidFile: 'geçersiz dosya: ',
    toastEmptyFile: 'dosya boş',
    toastCsvUnreadable: 'csv okunamadı: ',
    toastStrongPwGenerated: 'güçlü şifre üretildi',
    toastUpdated: 'güncellendi',
    toastSaved: 'kaydedildi',
    toastPwCopied: 'şifre kopyalandı',
    toastTotpCopied: '2FA kodu kopyalandı',

    strengthVeryWeak: 'çok zayıf', strengthWeak: 'zayıf', strengthMedium: 'orta',
    strengthStrong: 'güçlü', strengthVeryStrong: 'çok güçlü', strengthCrackTime: 'kırılma:',

    emptyNoResults: 'sonuç bulunamadı',
    emptyNoEntries: 'henüz kayıt yok',
    emptyStartHint: '+ Yeni butonuyla başlayın',

    forgotChangePwBtn: 'Şifreyi Değiştir',
    forgotKeyVerified: '✓ Anahtar doğrulandı. Yeni şifrenizi girin.',
    forgotKeyInvalid: '✕ Geçersiz kurtarma anahtarı.',
    forgotRecoveryFailed: '✕ Veriler kurtarılamadı. "SIFIRLA" ile sıfırlayabilirsiniz.',
    forgotNoRecovery: '⚠ Kurtarma anahtarı yok. Tüm verileri silmek için "{word}" yazın.',
    hardResetConfirmHint: 'Onaylamak için tam olarak "{word}" yazın.',
    resetConfirmWord: 'SIFIRLA',

    autoLockIdle: 'hareketsizlik nedeniyle otomatik kilitlendi',
    autoLockSuspend: 'sistem uyku moduna geçti — otomatik kilitlendi',
    autoLockScreen: 'ekran kilitlendi — otomatik kilitlendi',
    autoLockGeneric: 'otomatik kilitlendi',

    syncTitle: '⬡ AIR-GAP SYNC',
    syncKeyActive: 'SyncKey Aktif',
    syncPreparing: 'PAKET HAZIRLANIYOR...',
    syncPreparingRebuild: 'PAKET YENİDEN HAZIRLANIYOR...',
    syncExpired: '⚠ Sync oturumu sona erdi<br>(5 dk zaman aşımı)<br><br>Lütfen pencereyi kapatıp<br>yeniden açın.',
    syncStatus: 'DURUM', syncStatusPreparing: 'Hazırlanıyor...',
    syncChunk: 'PARÇA', syncSpeed: 'HIZ',
    syncTransferId: 'TRANSFER ID:',
    syncSpeedLabel: 'Aktarım Hızı',
    syncSlow: 'Yavaş', syncMedium: 'Orta', syncFast: 'Hızlı',
    syncPause: '❙❙ Duraklat', syncResume: '▶ Devam Et', syncReset: '↺ Yeniden Başlat',
    syncInfoNote: 'QR kodları telefonunuzun kamerası ile okuyun.',
    syncErrorLevel: '<em>Hata Düzeltme: Level M</em> · Tüm transfer şifreli',
    syncErrorPrefix: '⚠ HATA: ',
    syncTimedOut: 'Zaman Aşımı',
    syncTransferring: 'Aktarım Devam Ediyor',
    syncPaused: 'Duraklatıldı',
  },

  en: {
    appSubtitle: 'Password Manager',
    themeToggleTitle: 'Dark/Light mode',
    langToggleTitle: 'Dil / Language',

    lockMasterLabel: 'Master Password',
    lockMasterPh: 'enter your password...',
    lockVerifying: 'verifying...',
    lockUnlockBtn: 'UNLOCK →',
    lockForgot: 'forgot my password',
    lockHardReset: 'erase all data',
    lockHintFirstUse: 'Choose your password on first use.',
    lockHintLocalOnly: 'All data is stored <em>only on this device</em>.',

    navSectionView: 'View',
    navAll: 'All Entries',
    navFav: 'Favorites',
    navSectionCategories: 'Categories',
    navSectionTools: 'Tools',
    navHealth: 'Health Report',
    navSecurity: 'Security Info',
    navIO: 'Export / Import',
    navSync: 'Air-Gap Sync',
    navLock: '◉ Lock',

    viewTitleAll: 'ALL ENTRIES',
    viewTitleFav: 'FAVORITES',
    searchPh: 'search...',
    btnNew: '+ NEW',

    modalNewEntry: 'NEW ENTRY',
    modalEditEntry: 'EDIT ENTRY',
    fieldSite: 'Site / App',
    fieldSitePh: 'Gmail, GitHub...',
    fieldCategory: 'Category',
    fieldUser: 'Username / Email',
    fieldUserPh: 'user@email.com',
    fieldPassword: 'Password',
    fieldNote: 'Note (optional)',
    fieldNotePh: 'security question, hint...',
    fieldUrl: 'URL (optional)',
    section2FA: 'Two-Factor Authentication',
    toggle2FALabel: 'Store 2FA Code',
    toggle2FASub: 'TOTP secret key',
    toggleFavLabel: 'Add to Favorites',
    toggleFavSub: 'Show in sidebar',
    btnCancel: 'Cancel',
    btnSave: 'Save',
    genPwTitle: 'Generate',
    showPwTitle: 'Show',

    cat_social: 'Social Media', cat_email: 'Email', cat_finance: 'Finance',
    cat_shopping: 'Shopping', cat_work: 'Work / Corporate', cat_gaming: 'Gaming',
    cat_dev: 'Developer / Tools', cat_other: 'Other',

    totpModalTitle: '2FA CODE',
    totpHint: 'click code → copy',

    recoveryTitle: 'RECOVERY KEY',
    recoveryBody: 'If you forget your master password, you can reset it with this key.',
    recoveryWarn: 'Write it down somewhere safe. It will not be shown again.',
    recoveryHint: 'click key → copy',
    recoverySavedBtn: "I've Saved It, Close",

    forgotTitle: 'PASSWORD RESET',
    forgotBody: 'Enter your recovery key, then choose a new password.',
    forgotKeyLabel: 'Recovery Key',
    forgotNewPwLabel: 'New Master Password',
    forgotNewPwPh: 'your new password...',
    forgotVerifyBtn: 'Verify',

    hardResetTitle: '⚠ WARNING: FULL RESET',
    hardResetBody1: 'This action <span style="color:var(--red);font-weight:600">permanently deletes all your entries, password, and recovery key.</span>',
    hardResetBody2: 'This cannot be undone. Type <span style="color:var(--red)">RESET</span> below to continue.',
    hardResetConfirmLabel: 'Confirm',
    hardResetBtn: 'Reset',

    autoLockTitle: '⏱ INACTIVITY WARNING',
    autoLockBody: 'No activity detected for a while.<br>Will lock automatically when the countdown ends.',
    autoLockStillHere: "I'm Still Here",

    extReqTitle: '⬡ BROWSER EXTENSION REQUEST',
    extReqFor: 'is requesting credentials.',
    extReqSite: 'ENTRY',
    extReqUser: 'USERNAME',
    extReqDeny: 'Deny',
    extReqAllow: 'Allow',

    healthTitle: 'HEALTH REPORT',
    healthScanBtn: '⌖ Breach Scan',
    healthScanBtnAgain: '⌖ Scan Again',
    healthScanning: 'scanning...',
    healthInfoBox: '<em>k-Anonymity:</em> Your passwords are never sent. Only the first 5 characters of the SHA-1 hash go to HaveIBeenPwned; the match check happens entirely on this device.',
    healthWeak: 'Weak', healthMedium: 'Medium', healthStrong: 'Strong',
    healthDup: 'Reused', health2FA: '2FA Active', healthTotal: 'Total',
    healthWeakSection: 'Weak Passwords', healthDupSection: 'Reused Passwords',
    healthDupTag: 'reused', healthNoIssues: '✓ no issues found',
    hibpAllClean: 'All passwords are clean — no breaches found',
    hibpBreachedSection: 'Found In Breaches',
    hibpBreachedCount: '× breached',
    hibpChangeBtn: 'Change',
    hibpCheckFailed: 'could not check entry',
    hibpNoEntries: 'no entries to scan',
    hibpFoundToast: 'breaches found',
    hibpCleanToast: 'all passwords are clean',

    securityTitle: 'SECURITY INFO',
    securityInfoBox: 'This app runs all cryptographic operations in Electron\'s main process using Node.js\'s <em>crypto</em> module. Encryption logic never runs in the browser environment (renderer).',
    secKdf: 'Key Derivation', secDualKey: 'Dual Key', secDualKeySub: 'Two independent keys from one master',
    secEncryption: 'Encryption', secRamZero: 'RAM Zeroing', secRamZeroVal: 'Active', secRamZeroSub: 'Buffer.fill(0) after every operation',
    secTiming: 'Timing Attack', secTimingVal: 'Protected', secClipboard: 'Clipboard', secClipboardVal: '30s Auto-Clear',
    secEntropy: 'Entropy Analysis', secEntropyReal: 'Real-time, estimation-based', secEntropySimple: 'Regex-based', secEntropySimpleName: 'Simple',
    secQrSync: 'QR Sync', secQrReady: 'Ready', secQrSub: 'Chunks encrypted with SyncKey',

    ioTitle: 'EXPORT / IMPORT',
    ioExportJsonTitle: '↑ Export JSON', ioExportJsonSub: 'Save all entries in JSON format.', ioExportJsonBtn: 'Download JSON',
    ioExportCsvTitle: '↑ Export CSV', ioExportCsvSub: 'Save all entries as CSV.', ioExportCsvBtn: 'Download CSV',
    ioImportJsonTitle: '↓ Import JSON', ioImportJsonSub: 'Restore a previous Fuin backup.', ioImportJsonBtn: 'Choose JSON',
    ioImportCsvTitle: '↓ Import CSV', ioImportCsvSub: 'CSV with site, username, password columns.', ioImportCsvBtn: 'Choose CSV',
    ioWarnBox: '⚠ Exported files contain unencrypted plain text. Store them somewhere secure.',
    sysTitle: 'SYSTEM & UPDATES',
    sysUpdateCheckTitle: '⟳ Version Check',
    sysUpdateCheckSub: 'Check GitHub for newer versions of Fuin. Current version: v1.0.0',
    sysUpdateBtn: 'Check Now',
    sysBackupTitle: '⛁ Backup Folder',
    sysBackupSub: 'Access your automatically generated vault backups (.bak files).',
    sysBackupBtn: 'Open Folder',
    slogan: 'Quietly secure.',

    toastClipCleared: 'clipboard cleared ✓',
    toastCopiedDefault: 'copied',
    toastClipTimer: 'clipboard clears in {s}s',
    toastMinChars: 'enter at least 8 characters',
    toastWrongPassword: 'wrong password',
    toastExtCredSent: 'credentials sent to extension',
    toastSiteRequired: 'site and password are required',
    toastDeleted: 'deleted',
    toastAllDataErased: 'all data erased — you can set a new password',
    toastPasswordUpdated: 'password updated — you can sign in',
    toastRecoveryCopied: 'recovery key copied',
    toastAppReset: 'app has been reset',
    toastLoginFirst: 'please sign in first',
    toastSyncOpening: 'opening sync window...',
    toastNoDataToSync: 'no data to sync',
    toastSyncFailed: 'sync could not start: ',
    toastJsonExported: 'json exported',
    toastCsvExported: 'csv exported',
    toastEntriesAdded: 'entries added',
    toastInvalidFile: 'invalid file: ',
    toastEmptyFile: 'file is empty',
    toastCsvUnreadable: 'could not read csv: ',
    toastStrongPwGenerated: 'strong password generated',
    toastUpdated: 'updated',
    toastSaved: 'saved',
    toastPwCopied: 'password copied',
    toastTotpCopied: '2FA code copied',

    strengthVeryWeak: 'very weak', strengthWeak: 'weak', strengthMedium: 'medium',
    strengthStrong: 'strong', strengthVeryStrong: 'very strong', strengthCrackTime: 'crack time:',

    emptyNoResults: 'no results found',
    emptyNoEntries: 'no entries yet',
    emptyStartHint: 'Click + New to get started',

    forgotChangePwBtn: 'Change Password',
    forgotKeyVerified: '✓ Key verified. Enter your new password.',
    forgotKeyInvalid: '✕ Invalid recovery key.',
    forgotRecoveryFailed: '✕ Data could not be recovered. You can reset with "{word}".',
    forgotNoRecovery: '⚠ No recovery key found. Type "{word}" to erase all data.',
    hardResetConfirmHint: 'Type exactly "{word}" to confirm.',
    resetConfirmWord: 'RESET',

    autoLockIdle: 'auto-locked due to inactivity',
    autoLockSuspend: 'system entered sleep mode — auto-locked',
    autoLockScreen: 'screen locked — auto-locked',
    autoLockGeneric: 'auto-locked',

    syncTitle: '⬡ AIR-GAP SYNC',
    syncKeyActive: 'SyncKey Active',
    syncPreparing: 'PREPARING PACKAGE...',
    syncPreparingRebuild: 'REBUILDING PACKAGE...',
    syncExpired: '⚠ Sync session expired<br>(5 min timeout)<br><br>Please close this window<br>and reopen it.',
    syncStatus: 'STATUS', syncStatusPreparing: 'Preparing...',
    syncChunk: 'CHUNK', syncSpeed: 'SPEED',
    syncTransferId: 'TRANSFER ID:',
    syncSpeedLabel: 'Transfer Speed',
    syncSlow: 'Slow', syncMedium: 'Medium', syncFast: 'Fast',
    syncPause: '❙❙ Pause', syncResume: '▶ Resume', syncReset: '↺ Restart',
    syncInfoNote: 'Scan the QR codes with your phone\'s camera.',
    syncErrorLevel: '<em>Error Correction: Level M</em> · Entire transfer is encrypted',
    syncErrorPrefix: '⚠ ERROR: ',
    syncTimedOut: 'Timed Out',
    syncTransferring: 'Transfer In Progress',
    syncPaused: 'Paused',
  },
};

function t(key) {
  const lang = document.documentElement.lang === 'en' ? 'en' : 'tr';
  return TRANSLATIONS[lang][key] ?? TRANSLATIONS.tr[key] ?? key;
}

// Güvenlik: Yalnızca bilinen HTML içeren anahtarlar için innerHTML kullan
const I18N_HTML_KEYS = new Set([
  'lockHintLocalOnly', 'hardResetBody1', 'hardResetBody2',
  'autoLockBody', 'syncErrorLevel', 'healthInfoBox', 'securityInfoBox',
]);
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const key = el.getAttribute('data-i18n');
    if (I18N_HTML_KEYS.has(key)) el.innerHTML = t(key);
    else el.textContent = t(key);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
    el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
  });
  document.querySelectorAll('[data-i18n-title]').forEach(el => {
    el.title = t(el.getAttribute('data-i18n-title'));
  });
  // Dinamik başlıklar (JS'te oluşturulanlar) — mevcutsa yeniden çalıştır
  if (typeof refreshDynamicI18nLabels === 'function') refreshDynamicI18nLabels();
}

function setLanguage(lang) {
  document.documentElement.lang = lang;
  localStorage.setItem('fuin-lang', lang);
  const btn = document.getElementById('langToggle');
  if (btn) btn.textContent = lang === 'en' ? 'TR' : 'EN'; // buton, GEÇİLECEK dili gösterir
  applyI18n();
}

function toggleLanguage() {
  setLanguage(document.documentElement.lang === 'en' ? 'tr' : 'en');
}

setLanguage(localStorage.getItem('fuin-lang') || 'tr');
