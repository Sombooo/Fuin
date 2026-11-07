'use strict';

const api = window.kekkai;
let master = '', entries = [], editId = null, curView = 'all', totpIv = null;

let sessionKey = null;
const _pwScoreCache = new WeakMap();
async function memEncrypt(text) {
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, sessionKey, encoded);
  encoded.fill(0);
  return { iv: Array.from(iv), data: Array.from(new Uint8Array(cipher)) };
}
async function memDecrypt(encObj) {
  if (!encObj) return '';
  if (typeof encObj === 'string') return encObj;
  try {
    const iv = new Uint8Array(encObj.iv);
    const data = new Uint8Array(encObj.data);
    const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, sessionKey, data);
    const str = new TextDecoder().decode(dec);
    new Uint8Array(dec).fill(0);
    return str;
  } catch { return ''; }
}

let revealT = {};

// ── Platforma göre pencere kontrolleri (macOS: solda/renkli daire,
// Windows/Linux: sağda/kare buton) ──────────────────────────────────
(function adaptTitlebarToPlatform() {
  if (api.platform === 'darwin') return; // varsayılan HTML zaten macOS düzeninde
  const controls = document.querySelector('.titlebar-controls');
  const tbRight = document.querySelector('.tb-right');
  if (!controls || !tbRight) return;
  controls.classList.add('win-style');
  tbRight.appendChild(controls); // sağ tarafa taşı
})();

// ── Tema (koyu/açık mod) ─────────────────────────────────────────────
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const btn = document.getElementById('themeToggle');
  if (btn) btn.textContent = theme === 'dark' ? '◑' : '◐';
  localStorage.setItem('fuin-theme', theme);
}
function toggleTheme() {
  const cur = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(cur);
}
applyTheme(localStorage.getItem('fuin-theme') || (window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));

// ── Pano sayacı ───────────────────────────────────────────────────
let clipToastT = null;
api.onClipboardCleared(() => toast(t('toastClipCleared')));

async function copySecure(text, label, durationMs = 30000) {
  await api.copySecure(text, durationMs);
  // Toast: geri sayım göster
  let sec = Math.round(durationMs / 1000);
  const tick = () => {
    toast(`${label || t('toastCopiedDefault')} — ${t('toastClipTimer').replace('{s}', sec)}`);
    if (sec > 0) { sec--; clipToastT = setTimeout(tick, 1000); }
  };
  clearTimeout(clipToastT);
  tick();
}

// ── INIT ──────────────────────────────────────────────────────────
async function init() {
  const info = await api.cryptoInfo();
  const badge = document.getElementById('cryptoBadge');
  badge.textContent = info.argon2 ? 'Argon2id · Dual-Key' : 'PBKDF2 · Dual-Key';
  badge.style.color  = info.argon2 ? 'var(--green)' : 'var(--amber)';
}
init();

// ── TOTP (totpEngine servisi ile) ─────────────────────────────────
function b32dec(s) {
  return TotpEngine.base32Decode(s, { loose: true });
}
async function getTOTP(secret) {
  return await TotpEngine.getTOTP(secret);
}

async function sha1hex(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
}

// ── RECOVERY KEY ──────────────────────────────────────────────────
function generateRecoveryKey() {
  return window.FuinRecoveryUI.generateRecoveryKey();
}

async function saveRecoveryKey(key, masterPw) {
  const keyClean = key.replace(/-/g, '');
  // recovery.enc: { key, verified } — kurtarma anahtarını doğrulamak için
  const enc = await api.encrypt({ key, verified: true }, keyClean);
  // master.enc: { master } — şifre değiştirirken vault'u yeniden şifrelemek için
  const masterEnc = await api.encrypt({ master: masterPw }, keyClean);
  // Her iki dosya tek bir ayrıcalıklı atomik işlemle diske yazılır
  await api.saveRecoveryPair(enc, masterEnc);
}

// ADV-03: Recovery Migration Status Check & UI Update
async function checkRecoveryStatus() {
  if (!api.getRecoveryStatus) return;
  try {
    const status = await api.getRecoveryStatus();
    const banner = document.getElementById('recoveryMigrationBanner');
    const settingWarn = document.getElementById('recoverySettingWarning');
    const badge = document.getElementById('recoveryStatusBadge');

    if (status.legacyBound) {
      // If vault is unlocked and legacyBound is true, persist portable vault immediately
      if (master) {
        try { await persist(); } catch (e) { console.warn('Auto-migration persist error:', e); }
      }
      if (banner) banner.style.display = 'flex';
      if (settingWarn) settingWarn.style.display = 'block';
      if (badge) {
        badge.textContent = t('recoveryStatusLegacy');
        badge.style.color = 'var(--amber)';
      }
    } else {
      if (banner) banner.style.display = 'none';
      if (settingWarn) settingWarn.style.display = 'none';
      if (badge) {
        badge.textContent = status.exists ? t('recoveryStatusPortable') : '';
        badge.style.color = 'var(--green)';
      }
    }
  } catch (err) {
    console.error('checkRecoveryStatus error:', err);
  }
}

async function handleRegenerateRecovery() {
  if (!master) { toast(t('toastWrongPassword')); return; }
  if (!confirm(t('confirmRegenRecovery'))) return;
  try {
    const rKey = generateRecoveryKey();
    await saveRecoveryKey(rKey, master);
    document.getElementById('recoveryKeyDisplay').textContent = rKey;
    document.getElementById('recoveryOverlay').classList.add('open');
    await checkRecoveryStatus();
    toast(t('toastRecoveryRegenerated'));
  } catch (err) {
    console.error('Regenerate recovery error:', err);
    toast(t('toastError'));
  }
}

// ── LOCK / UNLOCK ─────────────────────────────────────────────────
async function unlock() {
  sessionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const pw = document.getElementById('masterInp').value;
  if (!pw || pw.length < 8) { toast(t('toastMinChars')); return; }

  const exists = await api.dataExists();
  const btn    = document.getElementById('unlockBtn');
  const loading = document.getElementById('lockLoading');
  const loadTxt = document.getElementById('lockLoadingText');

  btn.disabled = true;
  loading.classList.add('show');
  loadTxt.textContent = t('lockVerifying');

  if (exists) {
    const raw = await api.loadData();
    if (raw) {
      try { 
        let parsed = await api.decrypt(raw, pw); 
        if (parsed && parsed.type === 'fuin/vault') {
          entries = parsed.entries || [];
        } else {
          entries = Array.isArray(parsed) ? parsed : (parsed.entries || []);
        }

        let hadCorruptArtifact = false;
        const seenContent = new Set();
        entries = entries.filter(e => {
           if ((e.site === 'Yeni Hesap' || e.site === 'Bilinmeyen Site') && !e.username && !e.password) {
             hadCorruptArtifact = true;
             return false;
           }
           const key = `${e.site}||${e.username}||${e.password}`;
           if (seenContent.has(key)) return false;
           seenContent.add(key);
           return true;
        });

        const seenIds = new Set();
        entries = await Promise.all(entries.map(async e => {
           let id = e.id;
           while(seenIds.has(id) || !id) id = crypto.randomUUID();
           seenIds.add(id);
           return { ...e, id, password: await memEncrypt(e.password), totp: await memEncrypt(e.totp) };
        }));
        if (hadCorruptArtifact) {
          setTimeout(() => { if (master) persist().catch(() => {}); }, 200);
        }
      }
      catch (err) {
        btn.disabled = false; loading.classList.remove('show');
        if (err && err.message && err.message.includes('Too many attempts')) {
          toast(err.message);
        } else {
          toast(t('toastWrongPassword'));
        }
        const inp = document.getElementById('masterInp');
        inp.style.borderColor = 'var(--red)';
        setTimeout(() => inp.style.borderColor='', 800);
        return;
      }
    } else { entries = []; }
  } else { entries = []; }

  master = pw;
  document.getElementById('masterInp').value = '';
  btn.disabled = false; loading.classList.remove('show');
  document.getElementById('lockScreen').style.display = 'none';
  const appEl = document.getElementById('app');
  appEl.style.display='flex'; appEl.style.flexDirection='column';
  renderList();
  renderCategoryNav();
  loadSyncSettings();
  api.setUnlockState(true);
  silentCheckForUpdates();
  checkRecoveryStatus();
  if (exists && window.FuinWhatsNewController) {
    (async () => {
      try {
        const curVer = (window.kekkai?.getAppVersion ? await window.kekkai.getAppVersion() : '1.0.0-beta.8') || '1.0.0-beta.8';
        window.FuinWhatsNewController.checkOnUnlock(curVer);
      } catch {}
    })();
  }
  
  if (api.saveTouchIdKey && localStorage.getItem('fuin-touchid-enabled') === 'true') api.saveTouchIdKey(pw);

  if (!exists) {
    await persist();
    const rKey = generateRecoveryKey();
    await saveRecoveryKey(rKey, pw);
    document.getElementById('recoveryKeyDisplay').textContent = rKey;
    document.getElementById('recoveryOverlay').classList.add('open');
  }
}

function lock() {
  master = null;
  sessionKey = null;
  entries = [];
  if (typeof revealT === 'object' && revealT) {
    Object.keys(revealT).forEach(k => { clearTimeout(revealT[k]); delete revealT[k]; });
    revealT = {};
  }
  if (lanSyncCountdownTimer) {
    clearInterval(lanSyncCountdownTimer);
    lanSyncCountdownTimer = null;
  }
  const pwListEl = document.getElementById('pwList');
  if (pwListEl) pwListEl.innerHTML = '';
  const catNavEl = document.getElementById('categoryNav');
  if (catNavEl) catNavEl.innerHTML = '';
  const catSecEl = document.getElementById('categoryNavSection');
  if (catSecEl) catSecEl.style.display = 'none';
  ['f-site','f-user','f-pw','f-note','f-url','f-totp','genPwResult','syncPasswordInput','curPwInp','newMasterPwInp','newMasterPwConfirmInp','repromptPwInp','verifyRecoveryInp'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['addOverlay','totpOverlay','genOverlay','pairOverlay','lanSyncOverlay','newCategoryOverlay','changePwOverlay','backupOverlay','recoveryOverlay','repromptOverlay','pwHistoryOverlay','verifyRecoveryOverlay','backupHistoryOverlay'].forEach(id => {
    document.getElementById(id)?.classList.remove('open');
  });
  const overlaySyncPass = document.getElementById('overlaySyncPass');
  if (overlaySyncPass) overlaySyncPass.style.display = 'none';
  document.getElementById('lockScreen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('searchInp').value='';
  document.getElementById('unlockBtn').disabled=false;
  document.getElementById('lockLoading').classList.remove('show');
  editId=null;
  document.getElementById('masterInp').value='';
  closeTOTPTimer();
  try { if (api?.cancelClipboardClear) api.cancelClipboardClear(); } catch {}
  try { if (api?.setUnlockState) api.setUnlockState(false); } catch {}
  initTouchId();
  document.getElementById('autoLockOverlay')?.classList.remove('open');
  if (pendingExtReveal) { try { api?.extRespond?.(pendingExtReveal.requestId, { error: 'locked' }); } catch {} pendingExtReveal = null; }
  document.getElementById('extRevealOverlay')?.classList.remove('open');
  const banner = document.getElementById('recoveryMigrationBanner');
  if (banner) banner.style.display = 'none';
}

function initTouchId() {
  const setCard = document.getElementById('touchIdSettingCard');
  if (setCard) setCard.style.display = 'flex'; // Her zaman görünür olsun
  
  const tb = document.getElementById('touchIdBtn');
  if (tb) tb.style.display = 'none'; // Güvenlik: Asenkron sorgulardan önce her zaman gizle
  
  if (api.checkTouchId) {
    api.checkTouchId().then(hasTouch => {
      if (!hasTouch) return;
      const isEnabled = localStorage.getItem('fuin-touchid-enabled') === 'true';
      if (!isEnabled) return;
      const currentTb = document.getElementById('touchIdBtn');
      if (currentTb) {
        currentTb.style.display = 'flex';
        const newTb = currentTb.cloneNode(true);
        currentTb.parentNode.replaceChild(newTb, currentTb);
        
        const doTouchAuth = async () => {
          const masterPw = await api.touchIdUnlock();
          if (masterPw) {
            document.getElementById('masterInp').value = masterPw;
            unlock();
          }
        };
        newTb.addEventListener('click', doTouchAuth);
      }
    }).catch(() => {});
  }
}

// ── FAZ 2 — AUTO-LOCK (idle timeout / ekran kilidi / suspend) ─────
api.onAutoLockWarning((sec) => {
  const overlay = document.getElementById('autoLockOverlay');
  document.getElementById('autoLockCountdown').textContent = sec;
  overlay.classList.add('open');
});
api.onAutoLockWarningCancel(() => {
  document.getElementById('autoLockOverlay')?.classList.remove('open');
});
api.onForceLock((reason) => {
  document.getElementById('autoLockOverlay')?.classList.remove('open');
  if (!master) return; // zaten kilitliyse tekrar işlem yapma
  lock();
  const msgs = {
    idle:        t('autoLockIdle'),
    suspend:     t('autoLockSuspend'),
    'lock-screen':t('autoLockScreen'),
  };
  toast(msgs[reason] || t('autoLockGeneric'));
});
function dismissAutoLockWarning() {
  document.getElementById('autoLockOverlay')?.classList.remove('open');
}

let _lastActivityReport = 0;
function reportUserActivity() {
  const now = Date.now();
  if (now - _lastActivityReport > 5000) {
    _lastActivityReport = now;
    try { api.notifyActivity?.(); } catch {}
  }
}
window.addEventListener('pointerdown', reportUserActivity, { passive: true });
window.addEventListener('keydown', reportUserActivity, { passive: true });

// ── TARAYICI EKLENTİSİ KÖPRÜSÜ ──────────────────────────────────────
// main.js sadece taşıyıcı; asıl arama/ifşa işlemi burada (renderer'ın
// bellekte tuttuğu `entries` üzerinde) yapılır — şifre çözülmüş veri
// hiçbir zaman main process'te veya diskte durmaz.
function normalizeDomain(str) {
  if (!str) return '';
  let s = str.trim().toLowerCase();
  if (!/^https?:\/\//.test(s)) s = 'https://' + s;
  try { return new URL(s).hostname.replace(/^www\./, '').replace(/\.+$/, ''); }
  catch { return str.toLowerCase().replace(/^www\./, '').split('/')[0].replace(/\.+$/, ''); }
}
const MULTI_TENANT_SUFFIXES = new Set([
  'github.io',
  'pages.dev',
  'vercel.app',
  'netlify.app',
  'gitlab.io',
  'herokuapp.com',
  'firebaseapp.com',
  'fly.dev',
  'render.com',
  'onrender.com',
  'workers.dev',
  'web.app',
  'azurewebsites.net',
  'cloudfront.net',
  'railway.app',
  'up.railway.app',
  'deno.dev',
  'appspot.com',
  'surge.sh',
  'amplifyapp.com',
  'elasticbeanstalk.com',
  's3.amazonaws.com',
  'fastly.net',
  'b-cdn.net',
  'ngrok-free.app',
  'ngrok.io',
  'glitch.me',
  'myshopify.com',
  '000webhostapp.com',
  'pipedream.net',
  'pantheonsite.io',
  'wixsite.com',
  'ghost.io',
  'substack.com',
  'azureedge.net',
  'trafficmanager.net',
  'blob.core.windows.net',
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
  'com.tr', 'org.tr', 'edu.tr', 'gov.tr', 'net.tr', 'gen.tr',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'org.nz', 'net.nz',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br',
  'co.za', 'org.za',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'com.de', 'co.ca'
]);

function domainMatches(entry, domain) {
  const entryDomain = normalizeDomain(entry?.url || entry?.site);
  const targetDomain = normalizeDomain(domain);
  if (!entryDomain || !targetDomain) return false;
  
  // Basit güvenlik: Çok kısa veya noktasız (örn. "com") domainleri reddet
  if (!entryDomain.includes('.') || entryDomain.length < 4) {
    return targetDomain === entryDomain;
  }

  // IPv4 / IPv6 adreslerinde yalnızca tam eşleşmeye izin ver
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(entryDomain) || entryDomain.includes(':') || entryDomain.startsWith('[')) {
    return targetDomain === entryDomain;
  }

  // Multi-tenant public suffix kontrolü (F-01):
  // Eğer entryDomain doğrudan bir multi-tenant suffix ise (örn: "github.io"),
  // veya bilinen çok kiracılı bir platformun alt alan adı ise (örn: "myapp.github.io", "myapp.vercel.app"),
  // subdomain genişletmesi (wildcard match) YASAKLANIR, sadece tam eşleşmeye izin verilir.
  if (MULTI_TENANT_SUFFIXES.has(entryDomain)) {
    return targetDomain === entryDomain;
  }
  for (const suffix of MULTI_TENANT_SUFFIXES) {
    if (entryDomain.endsWith('.' + suffix)) {
      return targetDomain === entryDomain;
    }
  }
  
  // Sadece tam eşleşme veya sitenin bir subdomain'i olma durumuna izin ver
  // (Örn: kasa="google.com", site="accounts.google.com" -> Eşleşir)
  // (Örn: kasa="accounts.google.com", site="google.com" -> EşleşMEZ - Principle of Least Privilege)
  return targetDomain === entryDomain || targetDomain.endsWith('.' + entryDomain);
}

let pendingExtReveal = null;

api.onExtLookupRequest((req) => {
  const matches = entries
    .filter(e => !e.isDeleted && domainMatches(e, req.domain))
    .map(e => ({ id: e.id, site: e.site, username: e.username }));
  api.extRespond(req.requestId, matches);
});

api.onExtRevealRequest(async (req) => {
  if (pendingExtReveal !== null) {
    api.extRespond(req.requestId, { error: 'busy' });
    return;
  }
  const entry = entries.find(e => e.id === req.entryId && !e.isDeleted);
  if (!entry) {
    api.extRespond(req.requestId, { error: 'not-found' });
    return;
  }
  if (!domainMatches(entry, req.domain)) {
    api.extRespond(req.requestId, { error: 'domain-mismatch' });
    return;
  }

  // Kesintisiz anında otomatik doldurma (Seamless Autofill):
  // Kasa açıkken ve alan adı tam eşleştiğinde doldurur; ancak reprompt (yüksek güvenlikli) kayıtlar her zaman masaüstü onayı ister.
  const requirePrompt = Boolean(entry.reprompt) || localStorage.getItem('fuin-ext-prompt-approval') === 'true';
  if (!requirePrompt) {
    try {
      api.extRespond(req.requestId, { username: entry.username, password: await memDecrypt(entry.password) });
      toast(t('toastExtCredSent'));
    } catch {
      api.extRespond(req.requestId, { error: 'internal-error' });
    }
    return;
  }

  pendingExtReveal = { requestId: req.requestId, entry, domain: req.domain };
  document.getElementById('extRevealSite').textContent = entry.site;
  document.getElementById('extRevealUser').textContent = entry.username || '—';
  document.getElementById('extRevealDomain').textContent = req.domain || '—';
  document.getElementById('extRevealOverlay').classList.add('open');
});

api.onExtCopySecureRequest?.(async (req) => {
  if (!master) {
    api.extRespond(req.requestId, { error: 'locked' });
    return;
  }
  const entry = entries.find(e => e.id === req.entryId && !e.isDeleted);
  if (!entry) {
    api.extRespond(req.requestId, { error: 'not-found' });
    return;
  }
  if (!domainMatches(entry, req.domain)) {
    api.extRespond(req.requestId, { error: 'domain-mismatch' });
    return;
  }
  if (req.field === 'username') {
    await copySecure(entry.username || '', t('toastCopiedDefault'), 30000);
    api.extRespond(req.requestId, { ok: true });
    return;
  }
  const requirePrompt = Boolean(entry.reprompt) || localStorage.getItem('fuin-ext-prompt-approval') === 'true';
  if (requirePrompt) {
    api.extRespond(req.requestId, { error: 'approval-required' });
    return;
  }
  try {
    const pw = await memDecrypt(entry.password);
    await copySecure(pw, t('toastPwCopied'), 30000);
    api.extRespond(req.requestId, { ok: true });
  } catch {
    api.extRespond(req.requestId, { error: 'internal-error' });
  }
});

function getExtExcludedDomains() {
  try {
    const raw = localStorage.getItem('fuin-ext-excluded-domains');
    const arr = raw ? JSON.parse(raw) : [];
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function isDomainExcludedFromSave(domain) {
  const norm = normalizeDomain(domain || '');
  if (!norm) return false;
  const list = getExtExcludedDomains();
  return list.some(ex => norm === ex || norm.endsWith('.' + ex));
}

api.onExtExcludeDomainRequest?.((req) => {
  const norm = normalizeDomain(req.domain || '');
  if (norm) {
    const list = getExtExcludedDomains();
    if (!list.includes(norm)) {
      list.push(norm);
      try { localStorage.setItem('fuin-ext-excluded-domains', JSON.stringify(list)); } catch {}
    }
  }
  api.extRespond(req.requestId, { ok: true });
});

api.onExtCheckSaveCandidateRequest?.(async (req) => {
  if (!master) {
    api.extRespond(req.requestId, { error: 'locked' });
    return;
  }
  if (!req.domain || !req.password || typeof req.password !== 'string') {
    api.extRespond(req.requestId, { shouldPrompt: false });
    return;
  }
  if (isDomainExcludedFromSave(req.domain)) {
    api.extRespond(req.requestId, { shouldPrompt: false, excluded: true });
    return;
  }

  const matchingEntries = entries.filter(e => !e.isDeleted && domainMatches(e, req.domain));
  if (!matchingEntries.length) {
    api.extRespond(req.requestId, { shouldPrompt: true, action: 'save', username: req.username || '' });
    return;
  }

  const reqUserNorm = (req.username || '').trim().toLowerCase();
  if (reqUserNorm) {
    const userMatch = matchingEntries.find(e => (e.username || '').trim().toLowerCase() === reqUserNorm);
    if (userMatch) {
      const existingPw = await memDecrypt(userMatch.password);
      if (existingPw === req.password) {
        api.extRespond(req.requestId, { shouldPrompt: false });
        return;
      }
      api.extRespond(req.requestId, {
        shouldPrompt: true,
        action: 'update',
        entryId: userMatch.id,
        username: userMatch.username || req.username || ''
      });
      return;
    }
  } else {
    // 2 adımlı (split-login) formlarda 2. adımda yalnızca şifre gelebilir:
    // Bu domain için aynı şifre zaten kayıtlıysa tekrar sorma.
    for (const m of matchingEntries) {
      const existingPw = await memDecrypt(m.password);
      if (existingPw === req.password) {
        api.extRespond(req.requestId, { shouldPrompt: false });
        return;
      }
    }
    // Bu domain için tek bir kayıt varsa güncelleme olarak öner (ancak kasadaki gizli kullanıcı adını içerik betiğine sızdırma)
    if (matchingEntries.length === 1) {
      api.extRespond(req.requestId, {
        shouldPrompt: true,
        action: 'update',
        entryId: matchingEntries[0].id,
        username: ''
      });
      return;
    }
  }

  api.extRespond(req.requestId, { shouldPrompt: true, action: 'save', username: req.username || '' });
});

function formatCleanSiteName(domain) {
  if (!domain) return 'Yeni Hesap';
  let clean = domain.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].trim();
  const parts = clean.split('.');
  if (parts.length >= 2) {
    const name = parts[0];
    return name.charAt(0).toUpperCase() + name.slice(1) + '.' + parts.slice(1).join('.');
  }
  return clean.charAt(0).toUpperCase() + clean.slice(1);
}

function deduceCategory(domain) {
  if (!domain) return 'Diğer';
  const d = domain.toLowerCase();
  if (/chess|steam|twitch|epicgames|riotgames|blizzard|playstation|xbox|ea\.com|roblox|minecraft/i.test(d)) return 'Oyun';
  if (/twitter|x\.com|facebook|instagram|linkedin|tiktok|reddit|threads|pinterest|mastodon/i.test(d)) return 'Sosyal Medya';
  if (/gmail|mail|outlook|proton|yahoo|zoho|tutanota|fastmail/i.test(d)) return 'E-posta';
  if (/github|gitlab|bitbucket|stackoverflow|vercel|netlify|aws|digitalocean|cloudflare|azure/i.test(d)) return 'Geliştirici / Araçlar';
  if (/amazon|ebay|trendyol|hepsiburada|aliexpress|shopify|etsy|n11/i.test(d)) return 'Alışveriş';
  if (/bank|garanti|isbank|akbank|ziraat|yapikredi|paypal|stripe|wise|revolut|binance|coinbase/i.test(d)) return 'Finans';
  if (/slack|notion|jira|asana|trello|zoom|figma|miro|linear|office|microsoft/i.test(d)) return 'İş / Kurumsal';
  return 'Diğer';
}

function highlightSavedCard(entryId) {
  curView = 'all';
  const searchInp = document.getElementById('searchInp');
  if (searchInp) searchInp.value = '';
  document.querySelectorAll('.cat-item').forEach(el => el.classList.remove('active'));
  document.querySelector('.cat-item[data-view="all"]')?.classList.add('active');
  const viewTitle = document.getElementById('viewTitle');
  if (viewTitle) viewTitle.textContent = t('viewTitleAll');

  renderList().then(() => {
    setTimeout(() => {
      const cardEl = Array.from(document.querySelectorAll('.pw-card')).find(c => c.dataset.id === entryId);
      if (cardEl) {
        cardEl.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        cardEl.style.borderColor = 'var(--ac)';
        cardEl.style.boxShadow = '0 0 12px rgba(90, 154, 110, 0.4)';
        setTimeout(() => {
          cardEl.style.borderColor = '';
          cardEl.style.boxShadow = '';
        }, 2500);
      }
    }, 80);
  });
}

api.onExtSaveCredentialRequest?.(async (req) => {
  if (!master) {
    api.extRespond(req.requestId, { error: 'locked' });
    return;
  }
  if (
    !req.domain || typeof req.domain !== 'string' || req.domain.length > 253 ||
    !req.password || typeof req.password !== 'string' || req.password.length > 1024
  ) {
    api.extRespond(req.requestId, { error: 'invalid-credential' });
    return;
  }

  // Eski hatalı boş kayıtları temizle
  entries = entries.filter(x => !((x.site === 'Yeni Hesap' || x.site === 'Bilinmeyen Site') && !x.username && !x.password));

  const now = Date.now();
  const cleanUser = (req.username || '').trim().slice(0, 512);
  const reqUserNorm = cleanUser.toLowerCase();

  let existing = null;
  if (req.updateEntryId) {
    const byId = entries.find(x => x.id === req.updateEntryId && !x.isDeleted);
    if (byId) {
      // Güvenlik: updateEntryId verilse bile alan adı eşleşmesi (domainMatches) zorunludur
      if (!domainMatches(byId, req.domain)) {
        api.extRespond(req.requestId, { error: 'domain-mismatch' });
        return;
      }
      existing = byId;
    }
  }

  if (!existing) {
    existing = entries.find(x =>
      !x.isDeleted &&
      domainMatches(x, req.domain) &&
      (x.username || '').trim().toLowerCase() === reqUserNorm
    );
  }

  if (existing) {
    if (existing.reprompt) {
      api.extRespond(req.requestId, { error: 'reprompt-protected' });
      return;
    }
    const oldPw = await memDecrypt(existing.password);
    if (cleanUser && !existing.username) existing.username = cleanUser;
    if (!existing.url && req.domain) {
      existing.url = req.domain.startsWith('http') ? req.domain : 'https://' + req.domain;
    }
    if (oldPw !== req.password) {
      let history = Array.isArray(existing.history) ? [...existing.history] : [];
      if (existing.password) {
        history.unshift({ password: existing.password, date: now });
        if (history.length > 5) history = history.slice(0, 5);
      }
      existing.history = history;
      existing.password = await memEncrypt(req.password);
      existing.updated = now;
      existing.updatedAt = now;
      await persist();
      highlightSavedCard(existing.id);
      toast(`${t('toastUpdated')}: ${existing.site}`);
      api.extRespond(req.requestId, { ok: true, action: 'updated', id: existing.id });
      return;
    }
    await persist();
    highlightSavedCard(existing.id);
    api.extRespond(req.requestId, { ok: true, action: 'unchanged', id: existing.id });
    return;
  }

  const site = formatCleanSiteName(req.domain);
  const category = deduceCategory(req.domain);
  const newEntry = {
    id: crypto.randomUUID(),
    site,
    category,
    username: cleanUser,
    password: await memEncrypt(req.password),
    note: '',
    url: req.domain ? (req.domain.startsWith('http') ? req.domain : 'https://' + req.domain) : '',
    totp: await memEncrypt(''),
    fav: false,
    reprompt: false,
    updated: now,
    updatedAt: now,
    created: now,
    createdAt: now,
    deletedAt: null,
    isDeleted: false,
    history: []
  };
  entries.unshift(newEntry);
  await persist();
  highlightSavedCard(newEntry.id);
  toast(`${t('toastSaved')}: ${site}${newEntry.username ? ' (' + newEntry.username + ')' : ''}`);

  api.extRespond(req.requestId, { ok: true, action: 'created', id: newEntry.id });
});

async function approveExtReveal() {
  if (!pendingExtReveal) return;
  const { requestId, entry } = pendingExtReveal;
  pendingExtReveal = null;
  document.getElementById('extRevealOverlay').classList.remove('open');
  try {
    api.extRespond(requestId, { username: entry.username, password: await memDecrypt(entry.password) });
    toast(t('toastExtCredSent'));
  } catch (err) {
    api.extRespond(requestId, { error: 'internal-error' });
  }
}
function denyExtReveal() {
  if (!pendingExtReveal) return;
  const { requestId } = pendingExtReveal;
  pendingExtReveal = null;
  document.getElementById('extRevealOverlay').classList.remove('open');
  api.extRespond(requestId, { error: 'denied' });
}

document.getElementById('masterInp').addEventListener('keydown', e => e.key==='Enter' && unlock());

async function persist() {
  if (!master) return;
  const exportEntries = await Promise.all(entries.map(async entry => ({ ...entry, password: await memDecrypt(entry.password), totp: await memDecrypt(entry.totp) })));
  const payload = { type: 'fuin/vault', categories: [], entries: exportEntries };
  const enc = await api.encrypt(payload, master);
  await api.saveData(enc);
  renderCategoryNav();
}

// ── KATEGORİLER (Faz 3) ─────────────────────────────────────────────
// Kategori DEĞERLERİ (veride saklanan) her zaman Türkçe sabit kalır —
// mevcut kayıtlarla uyumluluk bozulmasın diye. Sadece EKRANDA gösterilen
// metin dile göre çevrilir.
const CATEGORY_KEY_MAP = {
  'Sosyal Medya': 'cat_social', 'E-posta': 'cat_email', 'Finans': 'cat_finance',
  'Alışveriş': 'cat_shopping', 'İş / Kurumsal': 'cat_work', 'Oyun': 'cat_gaming',
  'Geliştirici / Araçlar': 'cat_dev', 'Diğer': 'cat_other',
};
function catLabel(raw) {
  const key = CATEGORY_KEY_MAP[raw];
  return key ? t(key) : raw; // özel/bilinmeyen kategori adı ise olduğu gibi bırak
}

function renderCategoryNav() {
  const section = document.getElementById('categoryNavSection');
  const wrap    = document.getElementById('categoryNav');
  const counts  = {};
  entries.forEach(e => { const c = e.category || 'Diğer'; counts[c] = (counts[c]||0)+1; });
  
  const allCats = new Set([...Object.keys(counts)]);
  const cats = Array.from(allCats).sort((a,b)=>a.localeCompare('tr'));

  section.style.display='block';
  wrap.innerHTML = cats.map(c => `
    <div style="display:flex; align-items:center;">
      <button class="nav-item" style="flex:1;" data-action="set-view" data-val="cat:${esc(c)}">
        <span class="icon"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:middle;display:inline-block;"><polyline points="9 18 15 12 9 6"/></svg></span> ${esc(catLabel(c))} <span style="margin-left:auto;color:var(--mu);font-size:11px">${counts[c] || 0}</span>
      </button>
    </div>`).join('');
}

// ── VIEWS ─────────────────────────────────────────────────────────
function setView(v, btn) {
  curView = v;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  btn.classList.add('active');
  ['passwords','health','security','io','settings'].forEach(id => {
    const el = document.getElementById('view-'+id);
    if (el) el.style.display = 'none';
  });
  if (v==='all'||v==='fav'||v==='trash') {
    document.getElementById('view-passwords').style.display='flex';
    document.getElementById('btnAddNew').style.display = (v === 'trash') ? 'none' : 'block';
    
    if (v==='fav') document.getElementById('viewTitle').textContent = t('viewTitleFav');
    else if (v==='trash') document.getElementById('viewTitle').textContent = t('viewTitleTrash');
    else document.getElementById('viewTitle').textContent = t('viewTitleAll');
    renderList();
  } else if (v.startsWith('cat:')) {
    document.getElementById('view-passwords').style.display='flex';
    document.getElementById('btnAddNew').style.display='block';
    document.getElementById('viewTitle').textContent = catLabel(v.slice(4)).toUpperCase();
    renderList();
  } else if (v==='health') {
    document.getElementById('view-health').style.display='block'; renderHealth();
  } else if (v==='security') {
    document.getElementById('view-security').style.display='block'; renderSecurity();
  } else if (v==='io') {
    document.getElementById('view-io').style.display='block';
  } else if (v==='settings') {
    document.getElementById('view-settings').style.display='block';
    loadSyncSettings();
    updateExtStatusUI();
    refreshBackupSummaryBadge();
    getLocalAppVersion().then(ver => {
      const sub = document.getElementById('sysUpdateCheckSub');
      if (sub) sub.textContent = `${t('sysUpdateCheckSub')} ${t('sysUpdateCurrent', { v: normalizeVersion(ver) })}`;
    });
  }
}

// ── ZXCVBN ───────────────────────────────────────────────────────
function getScoreLabels() { return [t('strengthVeryWeak'),t('strengthWeak'),t('strengthMedium'),t('strengthStrong'),t('strengthVeryStrong')]; }
const scoreColors = ['var(--red)','var(--red)','var(--amber)','var(--green)','var(--green)'];

async function onPwInput() {
  const pw = document.getElementById('f-pw').value;
  const wrap = document.getElementById('zxcvbnWrap');
  if (!pw) { wrap.style.display='none'; return; }
  wrap.style.display='block';
  const result = await api.zxcvbn(pw);
  if (!result) {
    const s = simpleStrength(pw);
    for(let i=0;i<4;i++) document.getElementById('zs'+i).style.background = i<=s ? scoreColors[s] : 'var(--b)';
    document.getElementById('zxcvbnLabel').textContent = getScoreLabels()[s]||'—';
    document.getElementById('zxcvbnCrack').textContent = '';
    document.getElementById('zxcvbnWarn').textContent = '';
    return;
  }
  const { score, crackTime, warning } = result;
  for(let i=0;i<4;i++) document.getElementById('zs'+i).style.background = i<score ? scoreColors[score] : 'var(--b)';
  document.getElementById('zxcvbnLabel').textContent = getScoreLabels()[score];
  document.getElementById('zxcvbnLabel').style.color = scoreColors[score];
  document.getElementById('zxcvbnCrack').textContent = crackTime ? `${t('strengthCrackTime')} ${crackTime}` : '';
  document.getElementById('zxcvbnWarn').textContent  = warning || '';
}

function simpleStrength(pw) {
  if (typeof PasswordGenerator !== 'undefined' && PasswordGenerator.calculatePasswordStrength) {
    return PasswordGenerator.calculatePasswordStrength(pw).score;
  }
  let s=0;
  if(pw.length>=8)s++;if(pw.length>=12)s++;
  if(/[A-Z]/.test(pw))s++;if(/[0-9]/.test(pw))s++;if(/[^A-Za-z0-9]/.test(pw))s++;
  return Math.min(s<=2?1:s<=3?2:s<=4?3:4,4);
}

async function getScore(pw) {
  const r = await api.zxcvbn(pw);
  return r ? r.score : simpleStrength(pw);
}

// ── RENDER LIST ───────────────────────────────────────────────────
async function renderList() {
  const q = document.getElementById('searchInp').value.toLowerCase();
  let list = entries;
  if (curView === 'trash') {
    list = list.filter(e => e.isDeleted);
  } else {
    list = list.filter(e => !e.isDeleted);
    if (curView==='fav') list = list.filter(e=>e.fav);
    else if (curView.startsWith('cat:')) { const cat=curView.slice(4); list = list.filter(e=>(e.category||'Diğer')===cat); }
  }
  if (q) list = list.filter(e=>(e.site+e.username).toLowerCase().includes(q));

  const wrap = document.getElementById('pwList');
  if (!list.length) {
    wrap.innerHTML=`<div class="empty">
      <div class="empty-icon">◉</div>
      <div class="empty-txt">${entries.length?t('emptyNoResults'):t('emptyNoEntries')}</div>
      <div class="empty-sub">${entries.length?'':t('emptyStartHint')}</div>
    </div>`; return;
  }

  const scores = await Promise.all(list.map(async e => {
    if (e.password && typeof e.password === 'object') {
      const cached = _pwScoreCache.get(e.password);
      if (typeof cached === 'number') return cached;
      const computed = getScore(await memDecrypt(e.password));
      _pwScoreCache.set(e.password, computed);
      return computed;
    }
    return getScore(await memDecrypt(e.password));
  }));
  const dotClass = s => s>=3?'strong':s>=2?'medium':'weak';

  wrap.innerHTML = list.map((e,i) => `
    <div class="pw-card" data-id="${esc(e.id)}" style="animation-delay:${i*15}ms">
      <div class="pw-icon">${esc(e.site.slice(0,2).toUpperCase())}</div>
      <div class="pw-info">
        <div class="pw-site">${e.fav ? `<span class="fav-star" title="${esc(t('navFav'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></span>` : ''}<span class="pw-site-name">${esc(e.site)}</span>${e.reprompt ? `<span class="reprompt-badge" title="${esc(t('badgeReprompt'))}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>` : ''}${e.url && /^http:\/\//i.test(e.url.trim()) ? `<span class="insecure-http-badge" title="${esc(t('warnInsecureHttp'))}">HTTP</span>` : ''}</div>
        <div class="pw-meta">
          <span class="pw-user">${esc(e.username)||'—'}</span>
          <span class="pw-cat">${esc(catLabel(e.category||'Diğer'))}</span>
          <span class="pw-dots" id="dot-${esc(e.id)}" title="${esc(t('clickToRevealPw'))}">••••••</span>
          <div class="str-dot ${dotClass(scores[i])}"></div>
        </div>
      </div>
      <div class="pw-actions">
        ${curView === 'trash' ? `
          <button class="act-btn" data-action="restore-pw" data-val="${esc(e.id)}" title="${esc(t('btnRestore'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg></button>
          <button class="act-btn del" data-action="perm-del-pw" data-val="${esc(e.id)}" title="${esc(t('btnPermDel'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        ` : `
          ${e.totp?`<button class="act-btn" data-action="show-totp" data-val="${esc(e.id)}" title="2FA"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>`:''}
          <button class="act-btn" data-action="copy-pw" data-val="${esc(e.id)}" title="${esc(t('btnCopy'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
          <button class="act-btn" data-action="reveal-pw" data-val="${esc(e.id)}" title="${esc(t('showPwTitle'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
          <button class="act-btn" data-action="edit-pw" data-val="${esc(e.id)}" title="${esc(t('btnEdit'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
          <button class="act-btn del" data-action="del-pw" data-val="${esc(e.id)}" title="${esc(t('btnDel'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
        `}
      </div>
    </div>`).join('');
}

// ── SECURITY VIEW ─────────────────────────────────────────────────
async function renderSecurity() {
  const info = await api.cryptoInfo();
  document.getElementById('secGrid').innerHTML = `
    <div class="sec-card"><div class="sec-card-title">${t('secKdf')}</div>
      <div class="sec-card-value">${info.argon2?'Argon2id':'PBKDF2'}</div>
      <div class="sec-card-sub">${info.kdf}</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secDualKey')}</div>
      <div class="sec-card-value">VaultKey + SyncKey</div>
      <div class="sec-card-sub">${t('secDualKeySub')}</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secEncryption')}</div>
      <div class="sec-card-value">AES-256-GCM</div>
      <div class="sec-card-sub">Authenticated encryption</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secRamZero')}</div>
      <div class="sec-card-value">${t('secRamZeroVal')}</div>
      <div class="sec-card-sub">${t('secRamZeroSub')}</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secTiming')}</div>
      <div class="sec-card-value">${t('secTimingVal')}</div>
      <div class="sec-card-sub">crypto.timingSafeEqual()</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secClipboard')}</div>
      <div class="sec-card-value">${t('secClipboardVal')}</div>
      <div class="sec-card-sub">Electron clipboard API</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secEntropy')}</div>
      <div class="sec-card-value">${info.zxcvbn?'zxcvbn':t('secEntropySimpleName')}</div>
      <div class="sec-card-sub">${info.zxcvbn?t('secEntropyReal'):t('secEntropySimple')}</div></div>
    <div class="sec-card"><div class="sec-card-title">${t('secLanSync')}</div>
      <div class="sec-card-value">${t('secLanSyncVal')}</div>
      <div class="sec-card-sub">${t('secLanSyncSub')}</div></div>
  `;
}

// ── CRUD ──────────────────────────────────────────────────────────
async function openAddModal(id=null, force=false) {
  if (id && !force) {
    const target = entries.find(x => x.id === id);
    if (target && target.reprompt) {
      requireReprompt(id, () => openAddModal(id, true));
      return;
    }
  }
  editId=id;
  document.getElementById('addModalTitle').textContent = id ? t('modalEditEntry') : t('modalNewEntry');
  
  const sel = document.getElementById('f-category');
  const defaults = ['Sosyal Medya', 'E-posta', 'Finans', 'Alışveriş', 'İş / Kurumsal', 'Oyun', 'Geliştirici / Araçlar', 'Diğer'];
  const allOpts = [...defaults];
  sel.innerHTML = allOpts.map(c => {
    let i18n = CATEGORY_KEY_MAP[c] || '';
    return `<option value="${esc(c)}" ${i18n ? `data-i18n="${i18n}"` : ''}>${esc(catLabel(c))}</option>`;
  }).join('');
  
  if(id) {
    const e=entries.find(x=>x.id===id);
    document.getElementById('f-site').value=e.site;
    sel.value=e.category||'Diğer';
    document.getElementById('f-user').value=e.username;
    const pwEl = document.getElementById('f-pw');
    pwEl.type = 'password';
    pwEl.value=await memDecrypt(e.password);
    document.getElementById('f-note').value=e.note||'';
    document.getElementById('f-url').value=e.url||'';
    document.getElementById('f-2fa-toggle').checked=!!e.totp;
    document.getElementById('f-totp').value=await memDecrypt(e.totp)||'';
    document.getElementById('f-fav').checked=!!e.fav;
    document.getElementById('f-reprompt').checked=!!e.reprompt;
    const histBtn = document.getElementById('f-pw-history-row');
    const histCount = e.history && Array.isArray(e.history) ? e.history.length : 0;
    if (histBtn) {
      histBtn.style.display = 'block';
      const labelEl = document.getElementById('pwHistoryBtnLabel');
      if (labelEl) labelEl.textContent = `${t('btnPwHistory')} (${histCount})`;
    }
    document.getElementById('totp-section').style.display=e.totp?'block':'none';
    onPwInput();
  } else {
    ['f-site','f-user','f-pw','f-note','f-url','f-totp'].forEach(i=>document.getElementById(i).value='');
    sel.value='Diğer';
    document.getElementById('f-2fa-toggle').checked=false;
    document.getElementById('f-fav').checked=false;
    document.getElementById('f-reprompt').checked=false;
    const histBtn = document.getElementById('f-pw-history-row');
    if (histBtn) histBtn.style.display = 'none';
    document.getElementById('totp-section').style.display='none';
    document.getElementById('zxcvbnWrap').style.display='none';
  }
  const btnEye = document.getElementById('btnEyePw');
  if (btnEye) {
    setEyeIconSvg(btnEye, false);
    btnEye.style.color = '';
  }
  document.getElementById('addOverlay').classList.add('open');
  setTimeout(()=>document.getElementById('f-site').focus(),80);
}

function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.getElementById('addOverlay').addEventListener('mousedown', e=>{if(e.target.id==='addOverlay')closeModal('addOverlay');});

async function saveEntry() {
  const site=document.getElementById('f-site').value.trim();
  const pw=document.getElementById('f-pw').value;
  if(!site||!pw){toast(t('toastSiteRequired'));return;}
  const now = Date.now();
  const existing = editId ? entries.find(x=>x.id===editId) : null;
  let history = existing && Array.isArray(existing.history) ? [...existing.history] : [];
  if (existing) {
    const oldPw = await memDecrypt(existing.password);
    if (oldPw && oldPw !== pw) {
      history.unshift({
        password: existing.password,
        date: now
      });
      if (history.length > 5) history = history.slice(0, 5);
    }
  }
  const entry={
    id: editId||crypto.randomUUID(), site,
    category: document.getElementById('f-category').value,
    username: document.getElementById('f-user').value.trim(),
    password: await memEncrypt(pw),
    note:     document.getElementById('f-note').value.trim(),
    url:      document.getElementById('f-url').value.trim(),
    totp:     await memEncrypt(document.getElementById('f-2fa-toggle').checked ? document.getElementById('f-totp').value.trim() : ''),
    fav:      document.getElementById('f-fav').checked,
    reprompt: document.getElementById('f-reprompt').checked,
    updated:  now,
    updatedAt: now,
    created:  existing ? (existing.created || now) : now,
    createdAt: existing ? (existing.createdAt || existing.created || now) : now,
    deletedAt: null,
    isDeleted: false,
    history:  history
  };
  if(editId){const i=entries.findIndex(x=>x.id===editId);entries[i]=entry;}
  else entries.unshift(entry);
  await persist(); closeModal('addOverlay'); renderList();
  toast(editId?t('toastUpdated'):t('toastSaved'));
}

async function delEntry(id) {
  const i = entries.findIndex(x=>x.id===id);
  if(i !== -1) {
    const now = Date.now();
    entries[i].isDeleted = true;
    entries[i].deletedAt = now;
    entries[i].updated = now;
    entries[i].updatedAt = now;
    await persist(); renderList(); toast(t('toastDeleted'));
  }
}

async function restoreEntry(id) {
  const i = entries.findIndex(x=>x.id===id);
  if(i !== -1) {
    const now = Date.now();
    entries[i].isDeleted = false;
    entries[i].deletedAt = null;
    entries[i].updated = now;
    entries[i].updatedAt = now;
    await persist(); renderList(); toast(t('toastEntryRestored'));
  }
}

async function permDelEntry(id) {
  entries = entries.filter(x=>x.id!==id);
  await persist(); renderList(); toast(t('toastEntryPermDeleted'));
}

// ── ACTIONS ───────────────────────────────────────────────────────
async function copyPw(id) {
  const e = entries.find(x=>x.id===id);
  if (!e) return;
  const doCopy = async () => {
    const pw = await memDecrypt(e.password);
    await copySecure(pw, t('toastPwCopied'), 45000);
  };
  if (e.reprompt) {
    requireReprompt(id, doCopy);
  } else {
    await doCopy();
  }
}

async function revealPw(id) {
  const el=document.getElementById('dot-'+id); if(!el)return;
  const e=entries.find(x=>x.id===id);
  if (!e) return;
  const doReveal = async () => {
    if(el.classList.contains('pw-reveal')){
      el.textContent='••••••'; el.classList.remove('pw-reveal'); clearTimeout(revealT[id]);
    } else {
      el.textContent=await memDecrypt(e.password); el.classList.add('pw-reveal');
      clearTimeout(revealT[id]);
      revealT[id]=setTimeout(()=>{el.textContent='••••••';el.classList.remove('pw-reveal');},8000);
    }
  };
  if (e.reprompt && !el.classList.contains('pw-reveal')) {
    requireReprompt(id, doReveal);
  } else {
    await doReveal();
  }
}

function toggle2FA() {
  document.getElementById('totp-section').style.display =
    document.getElementById('f-2fa-toggle').checked ? 'block' : 'none';
}

async function showTOTP(id, force = false) {
  const e=entries.find(x=>x.id===id); if(!e?.totp)return;
  if (e.reprompt && !force) {
    requireReprompt(id, () => showTOTP(id, true));
    return;
  }
  document.getElementById('totpSiteName').textContent=e.site.toUpperCase();
  document.getElementById('totpOverlay').classList.add('open');
  closeTOTPTimer();
  const secret = await memDecrypt(e.totp);
  const tick=async()=>{
    if (typeof TotpEngine !== 'undefined' && TotpEngine.calculateTOTP) {
      const res = await TotpEngine.calculateTOTP(secret);
      document.getElementById('totpCode').textContent = res.formattedToken;
      document.getElementById('totpBar').style.width = res.progressPercent + '%';
    } else {
      const c=await getTOTP(secret);
      document.getElementById('totpCode').textContent=c.slice(0,3)+' '+c.slice(3);
      const sec=30-Math.floor(Date.now()/1000)%30;
      document.getElementById('totpBar').style.width=(sec/30*100)+'%';
    }
  };
  await tick(); totpIv=setInterval(tick,1000);
}
function closeTOTP(){closeModal('totpOverlay');closeTOTPTimer();}
function closeTOTPTimer(){if(totpIv){clearInterval(totpIv);totpIv=null;}}
document.getElementById('totpOverlay').addEventListener('mousedown',e=>{if(e.target.id==='totpOverlay')closeTOTP();});
async function copyTOTP(){
  const code=document.getElementById('totpCode').textContent.replace(' ','');
  await copySecure(code,t('toastTotpCopied'));
}

// ── FORGOT PASSWORD ───────────────────────────────────────────────
let recoveryVerified=false;

function openForgot() {
  recoveryVerified=false;
  window.FuinRecoveryUI.resetForgotModalUI(t);
}

function closeForgot() { recoveryVerified=false; closeModal('forgotOverlay'); }

async function handleForgot() {
  const inp=document.getElementById('recoveryInp').value.trim();
  const recoveryEnc=await api.loadRecovery();

  // Kurtarma anahtarı yok → SIFIRLA seçeneği
  if(!recoveryEnc) {
    const rWord = t('resetConfirmWord');
    if(inp===rWord) {
      await api.fullReset(); // fuin.enc + fuin.recovery + fuin.master.enc siler
      closeForgot();
      toast(t('toastAllDataErased'));
    } else {
      showForgotMsg(t('forgotNoRecovery').replace('{word}', rWord),'amber');
    }
    return;
  }

  if(!recoveryVerified) {
    try {
      const keyClean=inp.replace(/-/g,'');
      await api.decrypt(recoveryEnc, keyClean);
      recoveryVerified=true;
      document.getElementById('newPwGroup').style.display='block';
      document.getElementById('forgotBtn').textContent=t('forgotChangePwBtn');
      showForgotMsg(t('forgotKeyVerified'),'green');
    } catch {
      showForgotMsg(t('forgotKeyInvalid'),'red');
    }
    return;
  }

  const newPw=document.getElementById('newPwInp').value;
  if(!newPw||newPw.length<8){toast(t('toastMinChars'));return;}
  const keyClean=inp.replace(/-/g,'');
  try {
    // master.enc dosyadan okunur — localStorage kullanılmaz
    const masterStored = await api.loadMasterEnc();
    if(masterStored) {
      const masterData=await api.decrypt(masterStored, keyClean);
      const existingEnc=await api.loadData();
      if(existingEnc) {
        const oldEntries=await api.decrypt(existingEnc, masterData.master);
        const newEnc=await api.encrypt(oldEntries, newPw);
        await api.saveData(newEnc);
      }
    }
    await saveRecoveryKey(inp, newPw);
    recoveryVerified=false;
    closeForgot();
    toast(t('toastPasswordUpdated'));
  } catch {
    showForgotMsg(t('forgotRecoveryFailed').replace('{word}', t('resetConfirmWord')),'red');
  }
}

function showForgotMsg(text, type) {
  window.FuinRecoveryUI.showForgotMsg(text, type);
}

function copyRecoveryKey() {
  const key=document.getElementById('recoveryKeyDisplay').textContent;
  copySecure(key, t('toastRecoveryCopied')); // Güvenlik: 30 saniye sonra panoyu temizle
}

// ── MASTER PASSWORD REPROMPT ───────────────────────────────────────
let repromptPendingAction = null;
let repromptCustomVerifier = null;

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const charA = i < a.length ? a.charCodeAt(i) : 0;
    const charB = i < b.length ? b.charCodeAt(i) : 0;
    diff |= charA ^ charB;
  }
  return diff === 0;
}

function requireReprompt(id, callback) {
  const e = entries.find(x => x.id === id);
  if (!e || !e.reprompt) {
    callback();
    return;
  }
  repromptCustomVerifier = null;
  repromptPendingAction = callback;
  const overlay = document.getElementById('repromptOverlay');
  const inp = document.getElementById('repromptPwInp');
  const msg = document.getElementById('repromptMsg');
  if (inp) {
    inp.value = '';
    inp.type = 'password';
  }
  if (msg) {
    msg.textContent = '';
    msg.style.display = 'none';
  }
  const eyeBtn = document.getElementById('btnEyeReprompt');
  if (eyeBtn) eyeBtn.textContent = '●';
  if (overlay) overlay.classList.add('open');
  setTimeout(() => { if (inp) inp.focus(); }, 80);
}

async function verifyReprompt() {
  const inp = document.getElementById('repromptPwInp');
  const msg = document.getElementById('repromptMsg');
  const val = inp ? inp.value : '';
  if (typeof repromptCustomVerifier === 'function') {
    const ok = await repromptCustomVerifier(val, msg, inp);
    if (ok) {
      repromptCustomVerifier = null;
      repromptPendingAction = null;
      closeRepromptModal();
    }
    return;
  }
  if (constantTimeEqual(val, master)) {
    const action = repromptPendingAction;
    repromptPendingAction = null;
    closeRepromptModal();
    if (typeof action === 'function') {
      try {
        action();
      } catch (err) {
        console.error('Reprompt action execution error:', err);
      }
    }
  } else {
    if (msg) {
      msg.textContent = t('repromptWrongPw');
      msg.style.display = 'block';
    }
    if (inp) {
      inp.select();
      inp.focus();
    }
  }
}

function cancelReprompt() {
  repromptPendingAction = null;
  repromptCustomVerifier = null;
  closeRepromptModal();
}

function closeRepromptModal() {
  const inp = document.getElementById('repromptPwInp');
  if (inp) inp.value = '';
  closeModal('repromptOverlay');
}

// ── PASSWORD REVISION HISTORY ──────────────────────────────────────
async function openPwHistory() {
  const listEl = document.getElementById('pwHistoryList');
  if (!listEl) return;
  const entry = editId ? entries.find(x => x.id === editId) : null;
  if (!entry || !Array.isArray(entry.history) || entry.history.length === 0) {
    listEl.innerHTML = `<div style="font-family:var(--mono);font-size:12px;color:var(--mu);text-align:center;padding:16px;">${esc(t('pwHistoryEmpty'))}</div>`;
  } else {
    const itemsHtml = await Promise.all(entry.history.map(async (item, idx) => {
      const decrypted = await memDecrypt(item.password);
      const d = new Date(item.date);
      const dateFormatted = isNaN(d.getTime()) ? '' : d.toLocaleString();
      const masked = decrypted ? (decrypted.length > 4 ? decrypted.slice(0, 2) + '••••' + decrypted.slice(-2) : '••••') : '••••';
      return `
        <div class="pw-history-item">
          <div style="display:flex;flex-direction:column;gap:2px;overflow:hidden;flex:1;">
            <div class="pw-hist-date">${esc(dateFormatted)}</div>
            <div class="pw-hist-val" title="${esc(decrypted)}">${esc(masked)}</div>
          </div>
          <button type="button" class="btn-io" data-copy-hist="${idx}" style="font-size:11px;padding:4px 8px;flex-shrink:0;">
            ${esc(t('btnCopy'))}
          </button>
        </div>
      `;
    }));
    listEl.innerHTML = itemsHtml.join('');
    listEl.querySelectorAll('[data-copy-hist]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const idx = parseInt(btn.getAttribute('data-copy-hist'), 10);
        if (entry.history[idx]) {
          const raw = await memDecrypt(entry.history[idx].password);
          await copySecure(raw, t('pwHistoryCopied'), 45000);
        }
      });
    });
  }
  document.getElementById('pwHistoryOverlay')?.classList.add('open');
}

// ── EMERGENCY KIT (.html) ──────────────────────────────────────────
function generateEmergencyKitHtml(recoveryKey, dateStr) {
  const safeEsc = (s) => String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');
  const isEn = document.documentElement.lang === 'en';
  const trFn = typeof t === 'function' ? t : (k) => ({
    kitDocTitle: 'FUIN EMERGENCY KIT',
    kitDocSubtitle: 'Fuin Vault Recovery Document',
    kitRecoveryTitle: 'PRIMARY RECOVERY KEY',
    kitRecoveryDesc: '256-bit cryptographic recovery key for your vault.',
    kitMasterPwTitle: 'ANA \u015e\u0130FRE / MASTER PASSWORD',
    kitMasterPwDesc: 'Write your Master Password here by hand after printing.',
    kitInstructionsTitle: 'RECOVERY STEPS',
    kitStep1: '1. Open Fuin on your computer.',
    kitStep2: '2. Click Forgot Password on the lock screen.',
    kitStep3: '3. Enter your 32-character Recovery Key.',
    kitStep4: '4. Set your new Master Password.',
    kitRulesTitle: 'SECURITY RULES',
    kitRule1: 'PRINT: Print this page and delete the digital file.',
    kitRule2: 'STORE: Keep the printed sheet in a safe place.',
    kitRule3: 'PRIVATE: Never upload this file to cloud services.',
    kitFooterNote: 'Fuin Password Manager',
    kitPrintBtn: 'Print Kit',
    kitExportDateLabel: 'Date',
    kitHandwriteHint: '[ Handwritten Master Password ]'
  }[k] || k);
  const title = trFn('kitDocTitle');
  const subtitle = trFn('kitDocSubtitle');
  const recoveryTitle = trFn('kitRecoveryTitle');
  const recoveryDesc = trFn('kitRecoveryDesc');
  const masterPwTitle = trFn('kitMasterPwTitle');
  const masterPwDesc = trFn('kitMasterPwDesc');
  const instructionsTitle = trFn('kitInstructionsTitle');
  const step1 = trFn('kitStep1');
  const step2 = trFn('kitStep2');
  const step3 = trFn('kitStep3');
  const step4 = trFn('kitStep4');
  const securityRulesTitle = trFn('kitRulesTitle');
  const rule1 = trFn('kitRule1');
  const rule2 = trFn('kitRule2');
  const rule3 = trFn('kitRule3');
  const footerNote = trFn('kitFooterNote');
  const printBtnText = trFn('kitPrintBtn');
  const exportDateLabel = trFn('kitExportDateLabel');
  const handwriteHint = trFn('kitHandwriteHint');

  return `<!DOCTYPE html>
<html lang="${isEn ? 'en' : 'tr'}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>
  :root {
    --bg: #ffffff;
    --fg: #111827;
    --muted: #4b5563;
    --border: #e5e7eb;
    --card: #f9fafb;
    --accent: #0f172a;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #090a0f;
      --fg: #f3f4f6;
      --muted: #9ca3af;
      --border: #1f2937;
      --card: #111827;
      --accent: #38bdf8;
    }
  }
  @media print {
    :root {
      --bg: #ffffff !important;
      --fg: #000000 !important;
      --muted: #333333 !important;
      --border: #cccccc !important;
      --card: #f8f9fa !important;
      --accent: #000000 !important;
    }
    body { padding: 0 !important; }
    .no-print { display: none !important; }
    .kit-card { break-inside: avoid; }
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--fg);
    font-family: var(--sans);
    line-height: 1.5;
    padding: 40px 20px;
    display: flex;
    justify-content: center;
  }
  .container {
    max-width: 720px;
    width: 100%;
  }
  .header {
    border-bottom: 2px solid var(--accent);
    padding-bottom: 20px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
  }
  .header-left h1 {
    font-size: 24px;
    font-weight: 800;
    letter-spacing: 1px;
    color: var(--accent);
  }
  .header-left p {
    font-size: 13px;
    color: var(--muted);
    margin-top: 4px;
  }
  .meta-tag {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    background: var(--card);
    border: 1px solid var(--border);
    padding: 4px 8px;
    border-radius: 4px;
  }
  .btn-print {
    background: var(--accent);
    color: var(--bg);
    border: none;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
    border-radius: 6px;
    cursor: pointer;
    margin-bottom: 20px;
  }
  .kit-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
  }
  .kit-card h2 {
    font-size: 13px;
    font-family: var(--mono);
    font-weight: 700;
    letter-spacing: 0.5px;
    color: var(--accent);
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .kit-card p {
    font-size: 12px;
    color: var(--muted);
    margin-bottom: 12px;
    line-height: 1.6;
  }
  .key-box {
    background: var(--bg);
    border: 2px dashed var(--accent);
    padding: 14px 16px;
    font-family: var(--mono);
    font-size: 17px;
    font-weight: 700;
    letter-spacing: 2px;
    text-align: center;
    border-radius: 6px;
    word-break: break-all;
    user-select: all;
  }
  .handwrite-line {
    border-bottom: 1px solid var(--muted);
    height: 36px;
    margin-top: 10px;
    display: flex;
    align-items: flex-end;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
    padding-bottom: 4px;
  }
  ol, ul {
    padding-left: 20px;
    font-size: 13px;
    color: var(--fg);
  }
  li { margin-bottom: 8px; line-height: 1.5; }
  .footer {
    border-top: 1px solid var(--border);
    margin-top: 30px;
    padding-top: 16px;
    font-family: var(--mono);
    font-size: 11px;
    color: var(--muted);
    text-align: center;
  }
</style>
</head>
<body>
<div class="container">
  <div class="no-print" style="display:flex; justify-content:flex-end;">
    <button class="btn-print" onclick="window.print()">🖨 ${printBtnText}</button>
  </div>
  <div class="header">
    <div class="header-left">
      <h1>FUIN</h1>
      <p>${subtitle}</p>
    </div>
    <div class="meta-tag">
      ${exportDateLabel}: ${safeEsc(dateStr)}
    </div>
  </div>

  <div class="kit-card">
    <h2>🔑 ${recoveryTitle}</h2>
    <p>${recoveryDesc}</p>
    <div class="key-box">${safeEsc(recoveryKey || '________________________________________')}</div>
  </div>

  <div class="kit-card">
    <h2>✍️ ${masterPwTitle}</h2>
    <p>${masterPwDesc}</p>
    <div class="handwrite-line">${handwriteHint}</div>
  </div>

  <div class="kit-card">
    <h2>📋 ${instructionsTitle}</h2>
    <ol>
      <li>${step1}</li>
      <li>${step2}</li>
      <li>${step3}</li>
      <li>${step4}</li>
    </ol>
  </div>

  <div class="kit-card" style="border-left: 4px solid #b07020;">
    <h2>🛡 ${securityRulesTitle}</h2>
    <ul>
      <li><b>${rule1.split(':')[0]}:</b> ${rule1.split(':')[1]}</li>
      <li><b>${rule2.split(':')[0]}:</b> ${rule2.split(':')[1]}</li>
      <li><b>${rule3.split(':')[0]}:</b> ${rule3.split(':')[1]}</li>
    </ul>
  </div>

  <div class="footer">
    ${footerNote}
  </div>
</div>
</body>
</html>`;
}

async function exportEmergencyKit() {
  if (!master) {
    toast(t('toastLoginFirst'));
    return;
  }
  let rKey = document.getElementById('recoveryKeyDisplay')?.textContent?.trim() || '';
  if (!rKey) {
    const proceed = confirm(t('confirmGenKitRegen'));
    if (!proceed) return;
    rKey = generateRecoveryKey();
    await saveRecoveryKey(rKey, master);
    document.getElementById('recoveryKeyDisplay').textContent = rKey;
    await checkRecoveryStatus();
  }
  const dateStr = new Date().toLocaleString();
  const html = generateEmergencyKitHtml(rKey, dateStr);
  const success = await api.exportFile({
    content: html,
    defaultName: 'Fuin-Acil-Durum-Kiti.html',
    filters: [{ name: 'HTML Document', extensions: ['html'] }]
  });
  if (success) {
    toast(t('toastEmergencyKitSaved'));
  }
}

// ── RECOVERY KEY VERIFICATION (SELF-TEST) ─────────────────────────
function openVerifyRecoveryModal() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  const inp = document.getElementById('verifyRecoveryInp');
  const msg = document.getElementById('verifyRecoveryStatusMsg');
  if (inp) inp.value = '';
  if (msg) {
    msg.style.display = 'none';
    msg.textContent = '';
  }
  document.getElementById('verifyRecoveryOverlay')?.classList.add('open');
  setTimeout(() => inp?.focus(), 80);
}

function closeVerifyRecoveryModal() {
  const inp = document.getElementById('verifyRecoveryInp');
  if (inp) inp.value = '';
  closeModal('verifyRecoveryOverlay');
}

async function handleVerifyRecoveryKey() {
  const inp = document.getElementById('verifyRecoveryInp');
  const msg = document.getElementById('verifyRecoveryStatusMsg');
  const rawKey = (inp?.value || '').trim().toUpperCase();
  if (!msg) return;
  if (!rawKey) {
    msg.style.display = 'block';
    msg.style.background = 'rgba(200, 128, 64, 0.12)';
    msg.style.border = '1px solid var(--amber)';
    msg.style.color = 'var(--amber)';
    msg.textContent = t('verifyRecoveryInvalid');
    return;
  }
  const recoveryEnc = await api.loadRecovery();
  const masterEnc = await api.loadMasterEnc();
  if (!recoveryEnc || !masterEnc) {
    msg.style.display = 'block';
    msg.style.background = 'rgba(200, 128, 64, 0.12)';
    msg.style.border = '1px solid var(--amber)';
    msg.style.color = 'var(--amber)';
    msg.textContent = t('verifyRecoveryInvalid');
    return;
  }
  try {
    const keyClean = rawKey.replace(/-/g, '');
    const recData = await api.decrypt(recoveryEnc, keyClean);
    const masterData = await api.decrypt(masterEnc, keyClean);
    if (recData && recData.verified && masterData && typeof masterData.master === 'string') {
      msg.style.display = 'block';
      msg.style.background = 'rgba(90, 154, 110, 0.14)';
      msg.style.border = '1px solid var(--green)';
      msg.style.color = 'var(--green)';
      msg.textContent = t('verifyRecoverySuccess');
      toast(t('verifyRecoverySuccess'));
    } else {
      throw new Error('invalid-payload');
    }
  } catch {
    msg.style.display = 'block';
    msg.style.background = 'rgba(200, 80, 70, 0.12)';
    msg.style.border = '1px solid var(--red)';
    msg.style.color = 'var(--red)';
    msg.textContent = t('verifyRecoveryInvalid');
  }
}

// ── AUTOMATIC BACKUP HISTORY & SNAPSHOT RESTORE ───────────────────
function formatBackupReason(reason) {
  if (reason === 'manual') return t('backupReasonManual');
  if (reason === 'pre-restore') return t('backupReasonPreRestore');
  if (reason === 'pre-reset' || reason === 'recovery-regen') return t('backupReasonRecovery');
  return t('backupReasonAuto');
}

async function refreshBackupSummaryBadge() {
  const badge = document.getElementById('backupSummaryBadge');
  if (!badge || !api.getBackupList) return;
  try {
    const res = await api.getBackupList();
    const snaps = Array.isArray(res?.snapshots) ? res.snapshots : [];
    if (!snaps.length) {
      badge.textContent = t('backupHistoryEmpty');
      badge.style.color = 'var(--mu)';
      return;
    }
    badge.textContent = t('backupSummaryCount', { count: snaps.length });
    badge.style.color = 'var(--green)';
  } catch {
    badge.textContent = '';
  }
}

async function renderBackupHistoryList() {
  const listEl = document.getElementById('backupHistoryList');
  const healBanner = document.getElementById('backupAutoHealBanner');
  if (!listEl || !api.getBackupList) return;
  try {
    const res = await api.getBackupList();
    const snaps = Array.isArray(res?.snapshots) ? res.snapshots : [];
    if (healBanner) {
      if (res?.lastAutoHeal?.timestamp) {
        const d = new Date(res.lastAutoHeal.timestamp).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'tr-TR');
        healBanner.textContent = `${t('backupAutoHealNotice')} (${d})`;
        healBanner.style.display = 'block';
      } else {
        healBanner.style.display = 'none';
      }
    }
    if (!snaps.length) {
      listEl.innerHTML = `<div style="font-family:var(--mono);font-size:12px;color:var(--mu);text-align:center;padding:18px;">${esc(t('backupHistoryEmpty'))}</div>`;
      return;
    }
    listEl.innerHTML = snaps.map(snap => {
      const d = new Date(snap.timestamp).toLocaleString(document.documentElement.lang === 'en' ? 'en-US' : 'tr-TR');
      const kb = Math.max(1, Math.round((snap.size || 0) / 1024));
      const hashShort = snap.sha256 ? snap.sha256.slice(0, 10) : '—';
      const reasonLabel = formatBackupReason(snap.reason);
      const badgeLabel = snap.sha256 ? t('backupVerifiedBadge') : t('backupCorruptBadge');
      return `
        <div class="pw-history-item" style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div style="display:flex;flex-direction:column;gap:3px;overflow:hidden;flex:1;">
            <div style="font-size:12px;font-weight:600;color:var(--tx);display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <span>${esc(d)}</span>
              <span style="font-family:var(--mono);font-size:10px;padding:2px 6px;border-radius:4px;background:rgba(90,154,110,0.14);color:var(--ac2);">${esc(reasonLabel)}</span>
            </div>
            <div style="font-family:var(--mono);font-size:11px;color:var(--mu);">
              ${kb} KB · SHA-256: ${esc(hashShort)}… · ${esc(badgeLabel)}
            </div>
          </div>
          <button type="button" class="btn-io" data-restore-snap="${esc(snap.filename)}" style="font-size:11px;padding:6px 12px;flex-shrink:0;">
            ${esc(t('backupRestoreBtn'))}
          </button>
        </div>
      `;
    }).join('');
    listEl.querySelectorAll('[data-restore-snap]').forEach(btn => {
      btn.addEventListener('click', () => {
        const fname = btn.getAttribute('data-restore-snap');
        if (fname) restoreSnapshotByFilename(fname);
      });
    });
  } catch {
    listEl.innerHTML = `<div style="font-family:var(--mono);font-size:12px;color:var(--red);text-align:center;padding:16px;">${esc(t('toastError'))}</div>`;
  }
}

async function openBackupHistoryModal() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  await renderBackupHistoryList();
  document.getElementById('backupHistoryOverlay')?.classList.add('open');
}

function closeBackupHistoryModal() {
  closeModal('backupHistoryOverlay');
}

async function handleCreateManualBackup() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  try {
    await persist();
    if (api.createManualBackup) {
      const res = await api.createManualBackup();
      if (res?.ok) {
        toast(t('toastSnapshotCreated'));
        await refreshBackupSummaryBadge();
        if (document.getElementById('backupHistoryOverlay')?.classList.contains('open')) {
          await renderBackupHistoryList();
        }
      }
    }
  } catch (err) {
    toast(t('toastError') + ': ' + (err?.message || err));
  }
}

async function restoreSnapshotByFilename(filename) {
  if (!master) { toast(t('toastLoginFirst')); return; }
  if (!confirm(t('confirmRestoreSnapshot'))) return;
  try {
    const res = await api.restoreBackupSnapshot(filename);
    if (!res?.ok) {
      toast(t('toastError') + ': ' + (res?.error || ''));
      return;
    }
    const raw = await api.loadData();
    if (raw) {
      try {
        const parsed = await api.decrypt(raw, master);
        const list = (parsed && parsed.type === 'fuin/vault')
          ? (parsed.entries || [])
          : (Array.isArray(parsed) ? parsed : (parsed?.entries || []));
        const seenIds = new Set();
        entries = await Promise.all(list.map(async e => {
          let id = e.id;
          while (seenIds.has(id) || !id) id = crypto.randomUUID();
          seenIds.add(id);
          return { ...e, id, password: await memEncrypt(e.password), totp: await memEncrypt(e.totp) };
        }));
        closeBackupHistoryModal();
        renderList();
        renderCategoryNav();
        await refreshBackupSummaryBadge();
        toast(t('toastSnapshotRestored'));
      } catch {
        // Yedek farklı bir Ana Şifre ile şifrelenmişse kasayı kilitleyip o şifreyle açmasını sağla
        closeBackupHistoryModal();
        lock();
        toast(t('toastSnapshotRestored'));
      }
    }
  } catch (err) {
    toast(t('toastError') + ': ' + (err?.message || err));
  }
}

// ── SIFIRLAMA (giriş ekranından — tüm verileri sil) ───────────────
function openHardReset() {
  document.getElementById('hardResetOverlay').classList.add('open');
  document.getElementById('hardResetInp').value='';
  document.getElementById('hardResetMsg').style.display='none';
}
function closeHardReset() { closeModal('hardResetOverlay'); }
async function confirmHardReset() {
  const val=document.getElementById('hardResetInp').value.trim();
  const rWord = t('resetConfirmWord');
  if(val!==rWord) {
    const el=document.getElementById('hardResetMsg');
    el.style.display='block'; el.textContent=t('hardResetConfirmHint').replace('{word}', rWord);
    return;
  }
  await api.fullReset(); // fuin.enc + fuin.recovery + fuin.master.enc hepsini siler
  closeHardReset();
  toast(t('toastAppReset'));
}

// ── HEALTH ────────────────────────────────────────────────────────
async function renderHealth() {
  const decryptedPws = await Promise.all(entries.map(e=>memDecrypt(e.password)));
  const scores=await Promise.all(decryptedPws.map(pw=>getScore(pw)));
  const weak=entries.filter((_,i)=>scores[i]<=1);
  const medium=entries.filter((_,i)=>scores[i]===2);
  const strong=entries.filter((_,i)=>scores[i]>=3);
  const pwHashes=await Promise.all(decryptedPws.map(pw=>pw ? sha1hex(pw) : Promise.resolve('')));
  const pwMap={};
  entries.forEach((e, i)=>{(pwMap[pwHashes[i]]=pwMap[pwHashes[i]]||[]).push(e);});
  const dupGroups=Object.values(pwMap).filter(v=>v.length>1);
  const dups=dupGroups.flat();

  document.getElementById('healthGrid').innerHTML=`
    <div class="h-card"><div class="h-num red">${weak.length}</div><div class="h-label">${t('healthWeak')}</div></div>
    <div class="h-card"><div class="h-num amber">${medium.length}</div><div class="h-label">${t('healthMedium')}</div></div>
    <div class="h-card"><div class="h-num green">${strong.length}</div><div class="h-label">${t('healthStrong')}</div></div>
    <div class="h-card"><div class="h-num amber">${dups.length}</div><div class="h-label">${t('healthDup')}</div></div>
    <div class="h-card"><div class="h-num green">${entries.filter(e=>e.totp).length}</div><div class="h-label">${t('health2FA')}</div></div>
    <div class="h-card"><div class="h-num" style="color:var(--ac2)">${entries.length}</div><div class="h-label">${t('healthTotal')}</div></div>
  `;

  let html='';
  if(weak.length){
    html+=`<div class="h-section-title">${t('healthWeakSection')}</div>`;
    html+=weak.map(e=>`<div class="h-item"><div class="h-dot red"></div><span>${esc(e.site)}</span><span style="margin-left:auto;font-size:11px;color:var(--mu)">${esc(e.username)}</span></div>`).join('');
  }
  if(dupGroups.length){
    html+=`<div class="h-section-title">${t('healthDupSection')}</div>`;
    html+=dupGroups.map(g=>g.map(e=>`<div class="h-item"><div class="h-dot amber"></div><span>${esc(e.site)}</span><span style="margin-left:auto;font-size:11px;color:var(--mu)">${t('healthDupTag')}</span></div>`).join('')).join('');
  }
  if(!weak.length&&!dupGroups.length) html=`<div style="font-family:var(--mono);font-size:13px;color:var(--mu);padding:20px 0">${t('healthNoIssues')}</div>`;
  document.getElementById('healthDetails').innerHTML=html;
}

// ── HIBP ──────────────────────────────────────────────────────────
async function checkPwned(pw) {
  if (window.FuinHealthScanner && typeof window.FuinHealthScanner.checkPwned === 'function') {
    return window.FuinHealthScanner.checkPwned(pw, sha1hex);
  }
  const h = String(await sha1hex(pw)).toUpperCase();
  const pre = h.slice(0, 5), suf = h.slice(5);
  if (!/^[0-9A-F]{5}$/.test(pre)) return -1;
  const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
  const timer = controller ? setTimeout(() => { try { controller.abort(); } catch {} }, 8000) : null;
  try {
    const r = await fetch(`https://api.pwnedpasswords.com/range/${pre}`, {
      cache: 'no-store',
      redirect: 'error',
      headers: { 'Add-Padding': 'true' },
      signal: controller ? controller.signal : undefined
    });
    if (!r.ok) return -1;
    if (r.url && !r.url.startsWith('https://api.pwnedpasswords.com/')) return -1;
    const text = await r.text();
    if (typeof text !== 'string' || text.length > 262144) return -1;
    for (const line of text.split('\n')) {
      const [hh, c] = line.trim().split(':');
      if (hh === suf) {
        const parsed = parseInt(c, 10);
        return Number.isFinite(parsed) && parsed >= 0 ? parsed : -1;
      }
    }
    return 0;
  } catch { return -1; }
  finally { if (timer) clearTimeout(timer); }
}

async function runHIBPScan() {
  if(!entries.length){toast(t('hibpNoEntries'));return;}
  const btn=document.getElementById('scanBtn');
  btn.disabled=true; btn.textContent=t('healthScanning');
  const el=document.getElementById('hibpResults');
  el.innerHTML=`<div style="margin-bottom:14px"><div class="scan-bar-wrap"><div class="scan-bar" id="scanBar" style="width:0%"></div></div><div class="scan-status" id="scanSt">0 / ${entries.length}</div></div>`;
  const breached=[],errors=[];
  for(let i=0;i<entries.length;i++){
    if (!master || !sessionKey) return;
    const e=entries[i];
    const sb=document.getElementById('scanBar');
    const ss=document.getElementById('scanSt');
    if(sb)sb.style.width=Math.round(i/entries.length*100)+'%';
    if(ss)ss.textContent=`${i+1} / ${entries.length} — ${esc(e.site)}`;
    const decPw=await memDecrypt(e.password);
    const c=await checkPwned(decPw);
    if(c>0)breached.push({...e,count:c});
    else if(c<0)errors.push(e);
    await new Promise(r=>setTimeout(r,80));
  }
  let html='<div style="margin-bottom:14px">';
  if(!breached.length&&!errors.length){
    html+=`<div class="h-item" style="border-color:rgba(61,107,79,.3)"><div class="h-dot" style="background:var(--green)"></div><span>${t('hibpAllClean')}</span></div>`;
  } else {
    if(breached.length){
      breached.sort((a,b)=>b.count-a.count);
      html+=`<div class="h-section-title">${t('hibpBreachedSection')} (${breached.length})</div>`;
      breached.forEach(e=>{html+=`<div class="breach-row"><div class="h-dot red"></div><div style="flex:1"><div class="breach-site">${esc(e.site)}</div><div class="breach-user">${esc(e.username)}</div></div><div class="breach-count">${e.count.toLocaleString(document.documentElement.lang==='en'?'en-US':'tr-TR')}${t('hibpBreachedCount')}</div><button class="act-btn" style="opacity:1" data-action="edit-pw" data-val="${esc(e.id)}" title="${t('hibpChangeBtn')}">✎</button></div>`;});
    }
    if(errors.length) html+=`<div style="font-family:var(--mono);font-size:11px;color:var(--mu);margin-top:8px">⚠ ${errors.length} ${t('hibpCheckFailed')}</div>`;
  }
  html+='</div>';
  el.innerHTML=html;
  btn.disabled=false; btn.textContent=t('healthScanBtnAgain');
  toast(breached.length?`${breached.length} ${t('hibpFoundToast')}`:t('hibpCleanToast'));
}

// ── AIR-GAP SYNC (V2 FULL VAULT SNAPSHOT ONLY) ────────────────────
async function openSyncWindow() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  if (!entries || entries.length === 0) { toast(t('toastNoDataToSync')); return; }

  // Invariant (SEC-CRIT-01 / INV-29): Sync V2 is strictly a FULL VAULT SNAPSHOT ONLY.
  // Partial datasets or single entries must never be transmitted.
  const syncList = entries;

  const generateWithPassword = async (syncPassword) => {
    // Show sync overlay with preparing spinner immediately
    const syncOverlay = document.getElementById('syncOverlay');
    const preparingOverlay = document.getElementById('preparingOverlay');
    const preparingText = document.getElementById('preparingText');
    const spin = document.querySelector('.qr-preparing .spin');
    if (preparingText) {
      preparingText.textContent = t('syncPreparing');
      preparingText.style.color = '';
    }
    if (spin) spin.style.display = 'block';
    if (preparingOverlay) preparingOverlay.style.display = 'flex';
    if (syncOverlay) syncOverlay.classList.add('open');

    toast(t('toastSyncOpening'));
    try {
      // Ensure latest vault state is securely committed to storage and authoritative binding is synchronized
      await persist();
      const exportSyncList = await Promise.all(
        syncList.map(async e => ({ ...e, password: await memDecrypt(e.password), totp: await memDecrypt(e.totp) }))
      );

      const ok = await api.openSyncWindowV2(syncPassword, exportSyncList);
      if (ok) {
        localStorage.setItem('fuin-last-sync', Date.now().toString());
      }
    } catch(e) {
      toast(t('toastSyncFailed') + e.message);
      if (preparingText) {
        preparingText.textContent = t('syncErrorPrefix') + e.message;
        preparingText.style.color = 'var(--red)';
      }
      if (spin) spin.style.display = 'none';
    }
  };

  // If a paired device exists, directly generate Air-Gap QR using paired key without asking for any password!
  try {
    const pairedDevices = (api.getPairedDevices) ? await api.getPairedDevices() : [];
    if (Array.isArray(pairedDevices) && pairedDevices.length > 0) {
      await generateWithPassword('__PAIRED_DEVICE__');
      return;
    }
  } catch (err) {
    console.warn('[openSyncWindow] Could not check paired devices:', err);
  }

  // ── V2 PATH (Fallback for unpaired devices): Request Sync Password
  const overlaySyncPass = document.getElementById('overlaySyncPass');
  const inputSyncPass = document.getElementById('syncPasswordInput');
  inputSyncPass.type = 'password';
  inputSyncPass.value = '';
  overlaySyncPass.style.display = 'flex';
  inputSyncPass.focus();
  
  const cleanup = () => {
    overlaySyncPass.style.display = 'none';
    inputSyncPass.value = '';
    inputSyncPass.type = 'password';
  };

  document.getElementById('btnCloseSyncPass').onclick = cleanup;
  document.getElementById('btnCancelSyncPass').onclick = cleanup;
  const btnEyeSyncPass = document.getElementById('btnEyeSyncPass');
  if (btnEyeSyncPass) {
    btnEyeSyncPass.onclick = () => toggleEye('syncPasswordInput');
  }

  const pairedSection = document.getElementById('syncPassPairedSection');
  const btnSyncPassUsePaired = document.getElementById('btnSyncPassUsePaired');
  const pairedDeviceName = document.getElementById('syncPassPairedDeviceName');
  if (pairedSection) {
    let pairedList = [];
    try {
      pairedList = (api.getPairedDevices) ? await api.getPairedDevices() : [];
    } catch {}
    if (Array.isArray(pairedList) && pairedList.length > 0) {
      pairedSection.style.display = 'block';
      if (pairedDeviceName) {
        pairedDeviceName.textContent = `${pairedList[0].deviceName || t('deviceMobileDefault')} (${pairedList[0].keyPreview || ''})`;
      }
      if (btnSyncPassUsePaired) {
        btnSyncPassUsePaired.onclick = async () => {
          cleanup();
          await generateWithPassword('__PAIRED_DEVICE__');
        };
      }
    } else {
      pairedSection.style.display = 'none';
    }
  }

  inputSyncPass.onkeydown = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      document.getElementById('btnConfirmSyncPass').click();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      cleanup();
    }
  };

  document.getElementById('btnConfirmSyncPass').onclick = async () => {
    const syncPassword = inputSyncPass.value;
    if (!syncPassword || syncPassword.trim().length === 0) {
      toast(t('toastSyncPassRequired'));
      inputSyncPass.focus();
      return;
    }
    if (syncPassword.trim().length < 10) {
      toast(t('toastSyncPassMinLength'));
      inputSyncPass.focus();
      return;
    }
    cleanup();
    await generateWithPassword(syncPassword.trim());
  };
}

// ── HYBRID SYNC: LAN & AIR-GAP ROUTING (R1, R2, R4) ────────────────
let lanSyncCountdownTimer = null;

async function handleSyncClick() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  startLanSyncFlow();
}

async function startLanSyncFlow() {
  if (!master) { toast(t('toastLoginFirst')); return; }

  const overlay = document.getElementById('lanSyncOverlay');
  const statusText = document.getElementById('lanSyncStatusText');
  const timerText = document.getElementById('lanSyncTimer');
  const addrText = document.getElementById('lanSyncAddresses');

  if (statusText) statusText.textContent = t('lanSyncWaiting');
  if (timerText) timerText.textContent = `${t('lanSyncTimer')}120s`;
  if (addrText) addrText.textContent = t('syncStatusPreparing');
  if (overlay) overlay.classList.add('open');

  try {
    if (entries && entries.length > 0) {
      await persist();
    }
    const exportSyncList = Array.isArray(entries) && entries.length > 0 ? await Promise.all(
      entries.map(async e => ({
        ...e,
        password: await memDecrypt(e.password),
        totp: await memDecrypt(e.totp)
      }))
    ) : [];

    const res = await api.startLanSync(exportSyncList);
    if (addrText) {
      addrText.textContent = (res.addresses && res.addresses.length > 0)
        ? res.addresses.map(a => `${a}:${res.port}`).join('  |  ')
        : `127.0.0.1:${res.port || 8765}`;
    }

    let remaining = res.timeoutSec || 120;
    if (lanSyncCountdownTimer) clearInterval(lanSyncCountdownTimer);
    lanSyncCountdownTimer = setInterval(() => {
      remaining--;
      if (timerText) timerText.textContent = `${t('lanSyncTimer')}${remaining}s`;
      if (remaining <= 0) {
        clearInterval(lanSyncCountdownTimer);
        lanSyncCountdownTimer = null;
      }
    }, 1000);
  } catch (err) {
    if (lanSyncCountdownTimer) {
      clearInterval(lanSyncCountdownTimer);
      lanSyncCountdownTimer = null;
    }
    if (overlay) overlay.classList.remove('open');
    if (api.stopLanSync) await api.stopLanSync();
    toast(t('toastSyncFailed') + err.message);
  }
}

function updateSyncModeUI() {
  window.FuinLanSyncUI.updateSyncModeUI(t);
}

async function setSyncMode() {
  try {
    localStorage.setItem('fuin-sync-mode', 'lan');
    if (api.setSyncMode) {
      await api.setSyncMode('lan');
    }
    updateSyncModeUI();
  } catch (e) {
    console.error('setSyncMode error:', e);
  }
}

async function loadSyncSettings() {
  localStorage.setItem('fuin-sync-mode', 'lan');
  if (api.setSyncMode) {
    try { await api.setSyncMode('lan'); } catch {}
  }
  updateSyncModeUI();
  await refreshPairedDevicesList();
}

async function refreshPairedDevicesList() {
  await window.FuinLanSyncUI.renderPairedDevicesList({
    api,
    t,
    esc,
    onRevoke: (devId) => window.revokePairedDevice(devId),
  });
}

window.revokePairedDevice = async function(deviceId) {
  if (!confirm(t('confirmRevokeDevice'))) return;
  if (!api.revokePairedDevice) return;
  try {
    await api.revokePairedDevice(deviceId);
    toast(t('toastDeviceRevoked'));
    await refreshPairedDevicesList();
  } catch (err) {
    toast(t('toastError') + ': ' + (err.message || ''));
  }
};

async function openPairingModal() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  if (!api.generatePairingQR) return;

  try {
    if (entries && entries.length > 0) {
      await persist();
    }
    const exportSyncList = Array.isArray(entries) && entries.length > 0 ? await Promise.all(
      entries.map(async e => ({
        ...e,
        password: await memDecrypt(e.password),
        totp: await memDecrypt(e.totp)
      }))
    ) : [];

    const res = await api.startLanSync(exportSyncList);
    const payload = await api.generatePairingQR({ port: res.port });
    window.FuinLanSyncUI.renderPairingQRToCanvas(JSON.stringify(payload));

    const infoEl = document.getElementById('pairDeviceInfo');
    if (infoEl) {
      infoEl.textContent = `${t('pairDeviceLabel')}: ${payload.deviceId} · Port: ${payload.port}`;
    }

    document.getElementById('pairOverlay')?.classList.add('open');
  } catch (err) {
    if (api.stopLanSync) await api.stopLanSync();
    toast(t('toastSyncFailed') + err.message);
  }
}

// ── IMPORT / EXPORT ───────────────────────────────────────────────
async function exportEncryptedBackup() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  try {
    const exportEntries = await Promise.all(entries.map(async e => ({
      ...e,
      password: await memDecrypt(e.password),
      totp: await memDecrypt(e.totp)
    })));
    const payload = {
      type: 'fuin/vault',
      exportedAt: Date.now(),
      categories: [],
      entries: exportEntries
    };
    const enc = await api.encrypt(payload, master);
    const datePart = new Date().toISOString().slice(0, 10);
    const ok = await api.exportFile({
      content: JSON.stringify(enc, null, 2),
      defaultName: `fuin-kasa-${datePart}.fuin`,
      filters: [{ name: 'Fuin Encrypted Backup', extensions: ['fuin', 'enc', 'json'] }]
    });
    if (ok) toast(t('toastEncBackupExported'));
  } catch (err) {
    toast(t('toastError') + ': ' + (err?.message || err));
  }
}

async function importEncryptedBackup() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  const raw = await api.importFile({
    filters: [{ name: 'Fuin Encrypted Backup', extensions: ['fuin', 'enc', 'json'] }]
  });
  if (!raw) return;
  let encObj;
  try {
    encObj = JSON.parse(raw);
    if (!encObj || typeof encObj.data !== 'string' || typeof encObj.iv !== 'string' || typeof encObj.salt !== 'string' || typeof encObj.tag !== 'string') {
      throw new Error('invalid-format');
    }
  } catch {
    toast(t('toastInvalidFile') + ' (.fuin)');
    return;
  }

  const applyDecryptedVault = async (parsed) => {
    const list = (parsed && parsed.type === 'fuin/vault')
      ? (parsed.entries || [])
      : (Array.isArray(parsed) ? parsed : (parsed?.entries || []));
    await processImportedEntries(list, 'Fuin (.fuin)');
    toast(t('toastEncBackupRestored'));
  };

  try {
    const parsed = await api.decrypt(encObj, master);
    await applyDecryptedVault(parsed);
  } catch {
    // Mevcut ana şifre ile çözülemediyse yedeğin oluşturulduğu şifreyi sor
    repromptCustomVerifier = async (val, msgEl, inpEl) => {
      if (!val) return false;
      try {
        const parsed = await api.decrypt(encObj, val);
        await applyDecryptedVault(parsed);
        return true;
      } catch {
        if (msgEl) {
          msgEl.textContent = t('repromptWrongPw');
          msgEl.style.display = 'block';
        }
        if (inpEl) {
          inpEl.select();
          inpEl.focus();
        }
        return false;
      }
    };
    const overlay = document.getElementById('repromptOverlay');
    const inp = document.getElementById('repromptPwInp');
    const msg = document.getElementById('repromptMsg');
    if (inp) { inp.value = ''; inp.type = 'password'; }
    if (msg) {
      msg.textContent = t('promptEncBackupPassword');
      msg.style.display = 'block';
    }
    overlay?.classList.add('open');
    setTimeout(() => inp?.focus(), 80);
  }
}

async function exportJSON() {
  if(!confirm(t('confirmPlaintextExport'))) return;
  const exportEntries = await Promise.all(entries.map(async e => ({ ...e, password: await memDecrypt(e.password), totp: await memDecrypt(e.totp) })));
  const payload = { type: 'fuin/vault', categories: [], entries: exportEntries };
  const c=JSON.stringify(payload,null,2);
  await api.exportFile({content:c,defaultName:'fuin-yedek.json',filters:[{name:'JSON',extensions:['json']}]});
  toast(t('toastJsonExported'));
}
async function exportCSV() {
  if(!confirm(t('confirmPlaintextExport'))) return;
  const rows=['site,category,username,password,url,note'];
  const exportEntries = await Promise.all(entries.map(async e => ({ ...e, password: await memDecrypt(e.password), totp: await memDecrypt(e.totp) })));
  exportEntries.forEach(e=>rows.push([e.site,e.category||'Diğer',e.username,e.password,e.url||'',e.note||''].map(v=>`"${(v||'').replace(/"/g,'""')}"`).join(',')));
  await api.exportFile({content:rows.join('\n'),defaultName:'fuin-yedek.csv',filters:[{name:'CSV',extensions:['csv']}]});
  toast(t('toastCsvExported'));
}
// ── İçe Aktarım İşleyicileri (FuinImporters Servisi ile) ───────────
async function processImportedEntries(imported, label) {
  if (!Array.isArray(imported) || imported.length === 0) {
    toast(t('toastEmptyFile'));
    return;
  }
  const currentDecrypted = await Promise.all(
    entries.map(async e => ({ site: e.site, username: e.username, password: await memDecrypt(e.password) }))
  );

  let newEntries = imported.filter(x =>
    x.site && x.password &&
    !currentDecrypted.find(e => e.site === x.site && e.username === x.username && e.password === x.password)
  );

  newEntries = await Promise.all(
    newEntries.map(async e => ({ ...e, password: await memEncrypt(e.password), totp: await memEncrypt(e.totp) }))
  );

  entries = [...newEntries, ...entries];
  await persist();
  renderList();
  toast(`${label ? label + ' — ' : ''}${newEntries.length} ${t('toastEntriesAdded')}`);
}

async function importJSON() {
  const raw = await api.importFile({ filters: [{ name: 'JSON', extensions: ['json'] }] });
  if (!raw) return;
  try {
    const importers = window.FuinImporters || (typeof FuinImporters !== 'undefined' ? FuinImporters : null);
    const res = importers.importJSON(raw);
    await processImportedEntries(res.entries, res.format === 'bitwarden' ? 'Bitwarden' : 'Fuin');
  } catch (err) {
    toast(t('toastInvalidFile') + err.message);
  }
}

async function importCSV() {
  const raw = await api.importFile({ filters: [{ name: 'CSV', extensions: ['csv'] }] });
  if (!raw) return;
  try {
    const importers = window.FuinImporters || (typeof FuinImporters !== 'undefined' ? FuinImporters : null);
    const res = importers.importCSV(raw);
    const formatNames = { bitwarden: 'Bitwarden', lastpass: 'LastPass', '1password': '1Password', chrome: 'Chrome/Edge', fuin: 'Fuin' };
    await processImportedEntries(res.entries, formatNames[res.format] || 'CSV');
  } catch (err) {
    toast(t('toastCsvUnreadable') + err.message);
  }
}

// ── HELPERS ───────────────────────────────────────────────────────
function setEyeIconSvg(btn, shown) {
  if (!btn) return;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', '14');
  svg.setAttribute('height', '14');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  if (shown) {
    const p1 = document.createElementNS(ns, 'path');
    p1.setAttribute('d', 'M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24');
    const l1 = document.createElementNS(ns, 'line');
    l1.setAttribute('x1', '1'); l1.setAttribute('y1', '1');
    l1.setAttribute('x2', '23'); l1.setAttribute('y2', '23');
    svg.appendChild(p1);
    svg.appendChild(l1);
  } else {
    const p1 = document.createElementNS(ns, 'path');
    p1.setAttribute('d', 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z');
    const c1 = document.createElementNS(ns, 'circle');
    c1.setAttribute('cx', '12'); c1.setAttribute('cy', '12'); c1.setAttribute('r', '3');
    svg.appendChild(p1);
    svg.appendChild(c1);
  }
  btn.replaceChildren(svg);
}

function toggleEye(id) {
  const i = document.getElementById(id);
  if (!i) return;
  const isMasked = i.type === 'password';
  i.type = isMasked ? 'text' : 'password';
  const btn = document.getElementById('btnEyePw');
  if (btn && id === 'f-pw') {
    setEyeIconSvg(btn, isMasked);
    btn.style.color = isMasked ? 'var(--ac)' : '';
  }
}

function genPw(){
  document.getElementById('genOverlay').classList.add('open');
  generateAdvancedPw();
}

let _lastGenRes = null;

function renderGenStrengthUI(res) {
  if (!res) return;
  const pw = res.password;
  const score = res.score;

  const colors = ['var(--red)', '#e67e22', 'var(--amber)', '#5cb85c', 'var(--ac)'];
  const labels = getScoreLabels();
  const widths = ['20%', '40%', '60%', '80%', '100%'];

  const fill = document.getElementById('genStrengthFill');
  const label = document.getElementById('genStrengthLabel');
  if (fill && label) {
    if (!pw) {
      fill.style.width = '0%';
      fill.style.background = 'var(--red)';
      label.innerHTML = `<span>${esc(labels[0] || '...')}</span><span>0 bit</span>`;
      return;
    }
    const isEn = document.documentElement.lang === 'en';
    const crackText = isEn ? res.crackTime : res.crackTimeTr;
    const bitUnit = isEn ? 'bits' : 'bit';
    const tierText = labels[score] || '...';
    const metaText = `${Math.round(res.entropy || 0)} ${bitUnit} · ${t('strengthCrackTime')} ${crackText || ''}`;
    fill.style.width = widths[score] || '20%';
    fill.style.background = colors[score] || 'var(--red)';
    label.innerHTML = `<span style="color:${colors[score] || 'var(--mu)'}">${esc(tierText)}</span><span style="color:var(--mu);font-weight:500">${esc(metaText)}</span>`;
  }
}

function generateAdvancedPw() {
  const len = parseInt(document.getElementById('genLen').value) || 16;
  const useUpper = document.getElementById('genUpper').checked;
  const useLower = document.getElementById('genLower').checked;
  const useNum = document.getElementById('genNum').checked;
  const useSym = document.getElementById('genSym').checked;
  const exc = document.getElementById('genExc').checked;

  const res = PasswordGenerator.generatePassword({
    length: len,
    includeUpper: useUpper,
    includeLower: useLower,
    includeDigits: useNum,
    includeSymbols: useSym,
    excludeSimilar: exc
  });
  _lastGenRes = res;

  document.getElementById('genPwResult').value = res.password;
  renderGenStrengthUI(res);
}

function applyGeneratedPw() {
  const pw = document.getElementById('genPwResult').value;
  if (!pw) return;
  const inp=document.getElementById('f-pw');
  inp.value=pw; inp.type='text'; onPwInput();
  document.getElementById('genOverlay').classList.remove('open');
  toast(t('toastStrongPwGenerated'));
  setTimeout(()=>{inp.type='password';},2000);
}

function esc(s){return String(s == null ? '' : s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');}

let toastT;
function toast(msg){
  clearTimeout(toastT);
  document.getElementById('toastMsg').textContent=msg;
  document.getElementById('toast').classList.add('show');
  toastT=setTimeout(()=>document.getElementById('toast').classList.remove('show'),3000);
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){
    if(pendingExtReveal)denyExtReveal();
    closeModal('addOverlay');closeTOTP();closeForgot();closeHardReset();closeVerifyRecoveryModal();closeBackupHistoryModal();
    if(document.getElementById('pairOverlay')?.classList.contains('open')){
      document.getElementById('pairOverlay').classList.remove('open');
      if(api.stopLanSync) api.stopLanSync();
      refreshPairedDevicesList();
    }
    if(document.getElementById('lanSyncOverlay')?.classList.contains('open')){
      if(lanSyncCountdownTimer){ clearInterval(lanSyncCountdownTimer); lanSyncCountdownTimer = null; }
      document.getElementById('lanSyncOverlay').classList.remove('open');
      if(api.stopLanSync) api.stopLanSync();
    }
  }
  if((e.ctrlKey||e.metaKey)&&e.key==='n'){e.preventDefault();if(master)openAddModal();}
  if((e.ctrlKey||e.metaKey)&&(e.key==='l'||e.key==='L')){e.preventDefault();if(master)lock();}
});

// ── i18n.js tarafından dil değiştiğinde çağrılır — data-i18n
// özniteliğiyle kapsanmayan, JS içinde dinamik üretilen metinleri günceller
function refreshDynamicI18nLabels() {
  if (window.FuinWhatsNewController && typeof window.FuinWhatsNewController.onLanguageChanged === 'function') {
    window.FuinWhatsNewController.onLanguageChanged();
  }
  if (window.FuinRecoveryUI && typeof window.FuinRecoveryUI.onLanguageChanged === 'function') {
    window.FuinRecoveryUI.onLanguageChanged(t);
  }
  if (window.FuinLanSyncUI && typeof window.FuinLanSyncUI.onLanguageChanged === 'function') {
    window.FuinLanSyncUI.onLanguageChanged(t);
  }
  if (window.FuinSyncAnimation && typeof window.FuinSyncAnimation.onLanguageChanged === 'function') {
    window.FuinSyncAnimation.onLanguageChanged(t);
  }
  if (window.FuinUpdateManager && typeof window.FuinUpdateManager.onLanguageChanged === 'function') {
    window.FuinUpdateManager.onLanguageChanged(t);
  }
  if (!master) return; // kilit ekranındayken dinamik liste/kategori yok
  renderCategoryNav();
  if (curView === 'all' || curView === 'fav' || curView === 'trash') {
    const el = document.getElementById('viewTitle');
    if (el) el.textContent = curView === 'fav' ? t('viewTitleFav') : (curView === 'trash' ? t('viewTitleTrash') : t('viewTitleAll'));
  } else if (curView.startsWith('cat:')) {
    const el = document.getElementById('viewTitle');
    if (el) el.textContent = catLabel(curView.slice(4)).toUpperCase();
  }
  renderList();
  if (curView === 'settings') {
    refreshPairedDevicesList();
    updateExtStatusUI();
    refreshBackupSummaryBadge();
  }
  if (document.getElementById('addOverlay')?.classList.contains('open')) {
    document.getElementById('addModalTitle').textContent = editId ? t('modalEditEntry') : t('modalNewEntry');
  }
  if (document.getElementById('genOverlay')?.classList.contains('open') && _lastGenRes) {
    renderGenStrengthUI(_lastGenRes);
  }
  if (document.getElementById('backupHistoryOverlay')?.classList.contains('open')) {
    renderBackupHistoryList();
  }
  const mode = localStorage.getItem('fuin-sync-mode') || 'lan';
  updateSyncModeUI(mode);
}

// ── UPDATES ────────────────────────────────────────────────────────
function normalizeVersion(v) {
  return window.FuinUpdateManager ? window.FuinUpdateManager.normalizeVersion(v) : String(v || '').trim().replace(/^v/i, '');
}

function isNewerVersion(latest, current) {
  return window.FuinUpdateManager ? window.FuinUpdateManager.isNewerVersion(latest, current) : false;
}

async function getLocalAppVersion() {
  return window.FuinUpdateManager ? window.FuinUpdateManager.getLocalAppVersion() : '1.0.0-beta.8';
}

async function silentCheckForUpdates() {
  if (window.FuinUpdateManager) return window.FuinUpdateManager.silentCheckForUpdates();
}

async function checkForUpdates() {
  if (window.FuinUpdateManager) return window.FuinUpdateManager.checkForUpdates(t);
}
// ── EVENT DELEGATION FOR DYNAMIC BUTTONS & CARDS ───────────────────
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) {
    const dots = e.target.closest('.pw-dots');
    if (dots) {
      const card = dots.closest('.pw-card');
      const val = card?.getAttribute('data-id');
      if (val) {
        revealPw(val);
        return;
      }
    }
    const card = e.target.closest('.pw-card');
    if (card) {
      const val = card.getAttribute('data-id') || card.querySelector('button[data-action="edit-pw"]')?.getAttribute('data-val');
      if (val) openAddModal(val);
    }
    return;
  }
  const action = btn.getAttribute('data-action');
  const val = btn.getAttribute('data-val');

  if (action === 'lock') lock();
  else if (action === 'set-view') setView(val, btn);
  else if (action === 'show-totp') showTOTP(val);
  else if (action === 'copy-pw') copyPw(val);
  else if (action === 'reveal-pw') revealPw(val);
  else if (action === 'edit-pw') openAddModal(val);
  else if (action === 'del-pw') delEntry(val);
  else if (action === 'restore-pw') restoreEntry(val);
  else if (action === 'perm-del-pw') permDelEntry(val);
  else if (action === 'delete') deleteEntry(val);
});

// ── GÜVENLİK: Inline onclick handler'lar kaldırıldı — addEventListener ile bağla ──
function initAppListeners() {
  initTouchId();
  
  // Auto-Lock Timer Init
  const autoLockTimer = document.getElementById('autoLockTimer');
  if (autoLockTimer) {
    const saved = localStorage.getItem('autoLockSec');
    if (saved !== null) autoLockTimer.value = saved;
    if (api.setIdleLock) api.setIdleLock(autoLockTimer.value);
    
    autoLockTimer.addEventListener('change', () => {
      localStorage.setItem('autoLockSec', autoLockTimer.value);
      if (api.setIdleLock) api.setIdleLock(autoLockTimer.value);
    });
  }

  // Titlebar
  document.querySelector('.wbtn.close')?.addEventListener('click', () => window.kekkai?.close());
  document.querySelector('.wbtn.min')?.addEventListener('click', () => window.kekkai?.minimize());
  document.querySelector('.wbtn.max')?.addEventListener('click', () => window.kekkai?.maximize());
  document.getElementById('langToggle')?.addEventListener('click', toggleLanguage);
  document.getElementById('themeToggle')?.addEventListener('click', toggleTheme);

  // Lock screen
  document.getElementById('btnEyeMaster')?.addEventListener('click', () => toggleEye('masterInp'));
  document.getElementById('unlockBtn')?.addEventListener('click', unlock);
  document.getElementById('btnForgot')?.addEventListener('click', openForgot);
  document.getElementById('btnHardReset')?.addEventListener('click', openHardReset);

  // Sidebar nav
  document.getElementById('nav-all')?.addEventListener('click', function() { setView('all', this); });
  document.getElementById('nav-fav')?.addEventListener('click', function() { setView('fav', this); });
  document.getElementById('nav-settings')?.addEventListener('click', function() { setView('settings', this); });
  document.getElementById('nav-trash')?.addEventListener('click', function() { setView('trash', this); document.getElementById('viewTitle').textContent = t('viewTitleTrash'); });
  document.getElementById('nav-health')?.addEventListener('click', function() { setView('health', this); });
  document.getElementById('nav-security')?.addEventListener('click', function() { setView('security', this); });
  document.getElementById('nav-io')?.addEventListener('click', function() { setView('io', this); });
  document.getElementById('nav-sync')?.addEventListener('click', handleSyncClick);
  document.getElementById('nav-lock')?.addEventListener('click', lock);

  // Pairing & LAN Sync UI listeners
  document.getElementById('btnOpenPairModal')?.addEventListener('click', openPairingModal);
  document.getElementById('btnClosePairModal')?.addEventListener('click', async () => {
    document.getElementById('pairOverlay')?.classList.remove('open');
    if (api.stopLanSync) await api.stopLanSync();
    refreshPairedDevicesList();
  });
  document.getElementById('btnClosePairModalBtn')?.addEventListener('click', async () => {
    document.getElementById('pairOverlay')?.classList.remove('open');
    if (api.stopLanSync) await api.stopLanSync();
    refreshPairedDevicesList();
  });
  document.getElementById('pairOverlay')?.addEventListener('click', async (e) => {
    if (e.target.id === 'pairOverlay') {
      document.getElementById('pairOverlay').classList.remove('open');
      if (api.stopLanSync) await api.stopLanSync();
      refreshPairedDevicesList();
    }
  });
  document.getElementById('btnCancelLanSync')?.addEventListener('click', async () => {
    if (lanSyncCountdownTimer) {
      clearInterval(lanSyncCountdownTimer);
      lanSyncCountdownTimer = null;
    }
    document.getElementById('lanSyncOverlay')?.classList.remove('open');
    if (api.stopLanSync) await api.stopLanSync();
  });
  document.getElementById('btnCloseLanSync')?.addEventListener('click', async () => {
    if (lanSyncCountdownTimer) {
      clearInterval(lanSyncCountdownTimer);
      lanSyncCountdownTimer = null;
    }
    document.getElementById('lanSyncOverlay')?.classList.remove('open');
    if (api.stopLanSync) await api.stopLanSync();
  });
  document.getElementById('lanSyncOverlay')?.addEventListener('click', async (e) => {
    if (e.target.id === 'lanSyncOverlay') {
      if (lanSyncCountdownTimer) {
        clearInterval(lanSyncCountdownTimer);
        lanSyncCountdownTimer = null;
      }
      document.getElementById('lanSyncOverlay').classList.remove('open');
      if (api.stopLanSync) await api.stopLanSync();
    }
  });

  // Main content
  document.getElementById('searchInp')?.addEventListener('input', renderList);
  document.getElementById('btnAddNew')?.addEventListener('click', () => openAddModal());
  document.getElementById('scanBtn')?.addEventListener('click', runHIBPScan);

  // IO buttons
  document.getElementById('btnExportEncrypted')?.addEventListener('click', exportEncryptedBackup);
  document.getElementById('btnImportEncrypted')?.addEventListener('click', importEncryptedBackup);
  document.getElementById('btnExportJSON')?.addEventListener('click', exportJSON);
  document.getElementById('btnExportCSV')?.addEventListener('click', exportCSV);
  document.getElementById('btnImportJSON')?.addEventListener('click', importJSON);
  document.getElementById('btnImportCSV')?.addEventListener('click', importCSV);
  document.getElementById('updateBtn')?.addEventListener('click', checkForUpdates);
  document.getElementById('btnBackupFolder')?.addEventListener('click', () => window.kekkai?.openBackupFolder());
  document.getElementById('btnOpenBackupHistory')?.addEventListener('click', openBackupHistoryModal);
  document.getElementById('btnCreateBackupNow')?.addEventListener('click', handleCreateManualBackup);
  document.getElementById('btnModalCreateBackupNow')?.addEventListener('click', handleCreateManualBackup);
  document.getElementById('btnCloseBackupHistory')?.addEventListener('click', closeBackupHistoryModal);
  document.getElementById('btnDoneBackupHistory')?.addEventListener('click', closeBackupHistoryModal);
  document.getElementById('backupHistoryOverlay')?.addEventListener('mousedown', (e) => {
    if (e.target.id === 'backupHistoryOverlay') closeBackupHistoryModal();
  });
  window.FuinWhatsNewController?.init();

  const toggleAutoUpdate = document.getElementById('toggleAutoUpdateCheck');
  if (toggleAutoUpdate) {
    toggleAutoUpdate.checked = localStorage.getItem('fuin-auto-update-check') !== 'false';
    toggleAutoUpdate.addEventListener('change', (e) => {
      localStorage.setItem('fuin-auto-update-check', e.target.checked ? 'true' : 'false');
    });
  }

  const touchIdToggle = document.getElementById('touchIdSettingToggle');
  if (touchIdToggle) {
    touchIdToggle.checked = localStorage.getItem('fuin-touchid-enabled') === 'true';
    touchIdToggle.addEventListener('change', (e) => {
      localStorage.setItem('fuin-touchid-enabled', e.target.checked);
      if (e.target.checked && typeof master !== 'undefined' && master && api.saveTouchIdKey) {
        api.saveTouchIdKey(master);
      } else if (!e.target.checked && api.clearTouchIdKey) {
        api.clearTouchIdKey();
      }
    });
  }

  // Add/Edit modal
  document.getElementById('btnCloseAddModal')?.addEventListener('click', () => closeModal('addOverlay'));
  document.getElementById('f-pw')?.addEventListener('input', onPwInput);
  document.getElementById('btnEyePw')?.addEventListener('click', () => toggleEye('f-pw'));
  document.getElementById('btnCopyModalPw')?.addEventListener('click', async () => {
    const pw = document.getElementById('f-pw').value;
    if (pw) {
      await copySecure(pw, t('toastPwCopied'), 45000);
    } else {
      toast(t('toastPwFieldEmpty'));
    }
  });
  document.getElementById('btnGenPw')?.addEventListener('click', genPw);
  document.getElementById('f-2fa-toggle')?.addEventListener('change', toggle2FA);
  document.getElementById('btnCancelAdd')?.addEventListener('click', () => closeModal('addOverlay'));
  document.getElementById('btnSaveEntry')?.addEventListener('click', saveEntry);

  // Advanced Generator Modal
  document.getElementById('btnGenAdvRefresh')?.addEventListener('click', (e) => {
    const btn = e.currentTarget;
    btn.classList.remove('spin-anim');
    void btn.offsetWidth; // trigger reflow
    btn.classList.add('spin-anim');
    generateAdvancedPw();
  });
  document.getElementById('btnGenAdvCopy')?.addEventListener('click', async () => {
    const pw = document.getElementById('genPwResult').value;
    if (pw) {
      await copySecure(pw, t('toastPwCopied'), 30000);
    }
  });
  document.getElementById('genLen')?.addEventListener('input', (e) => {
    document.getElementById('genLenVal').innerText = e.target.value;
    generateAdvancedPw();
  });
  ['genUpper','genLower','genNum','genSym','genExc'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', generateAdvancedPw);
  });
  document.getElementById('btnGenAdvCancel')?.addEventListener('click', () => document.getElementById('genOverlay').classList.remove('open'));
  document.getElementById('btnGenAdvCloseTop')?.addEventListener('click', () => document.getElementById('genOverlay').classList.remove('open'));
  document.getElementById('btnGenAdvApply')?.addEventListener('click', applyGeneratedPw);

  // New Category Modal
  document.getElementById('btnCloseNewCategory')?.addEventListener('click', () => document.getElementById('newCategoryOverlay').classList.remove('open'));
  document.getElementById('btnCancelNewCategory')?.addEventListener('click', () => document.getElementById('newCategoryOverlay').classList.remove('open'));
  document.getElementById('btnSaveNewCategory')?.addEventListener('click', confirmAddCustomCategory);
  document.getElementById('newCategoryInp')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') confirmAddCustomCategory();
  });

  // TOTP modal
  document.getElementById('btnCloseTOTP')?.addEventListener('click', closeTOTP);
  document.getElementById('totpCode')?.addEventListener('click', copyTOTP);

  // Recovery modal, Self-Test & Emergency Kit
  document.getElementById('recoveryKeyDisplay')?.addEventListener('click', copyRecoveryKey);
  document.getElementById('btnCloseRecovery')?.addEventListener('click', () => closeModal('recoveryOverlay'));
  document.getElementById('btnRegenRecovery')?.addEventListener('click', handleRegenerateRecovery);
  document.getElementById('btnVerifyRecoveryKey')?.addEventListener('click', openVerifyRecoveryModal);
  document.getElementById('btnCloseVerifyRecovery')?.addEventListener('click', closeVerifyRecoveryModal);
  document.getElementById('btnCancelVerifyRecovery')?.addEventListener('click', closeVerifyRecoveryModal);
  document.getElementById('btnConfirmVerifyRecovery')?.addEventListener('click', handleVerifyRecoveryKey);
  document.getElementById('verifyRecoveryInp')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleVerifyRecoveryKey();
    else if (e.key === 'Escape') closeVerifyRecoveryModal();
  });
  document.getElementById('verifyRecoveryOverlay')?.addEventListener('mousedown', (e) => {
    if (e.target.id === 'verifyRecoveryOverlay') closeVerifyRecoveryModal();
  });
  document.getElementById('btnDownloadEmergencyKit')?.addEventListener('click', exportEmergencyKit);
  document.getElementById('btnModalEmergencyKit')?.addEventListener('click', exportEmergencyKit);

  // Master Password Reprompt modal
  document.getElementById('btnCloseReprompt')?.addEventListener('click', cancelReprompt);
  document.getElementById('btnCancelReprompt')?.addEventListener('click', cancelReprompt);
  document.getElementById('btnConfirmReprompt')?.addEventListener('click', verifyReprompt);
  document.getElementById('btnEyeReprompt')?.addEventListener('click', () => toggleEye('repromptPwInp'));
  document.getElementById('repromptPwInp')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') verifyReprompt();
    else if (e.key === 'Escape') cancelReprompt();
  });
  document.getElementById('repromptOverlay')?.addEventListener('mousedown', (e) => {
    if (e.target.id === 'repromptOverlay') cancelReprompt();
  });

  // Password History modal
  document.getElementById('btnOpenPwHistory')?.addEventListener('click', openPwHistory);
  document.getElementById('btnClosePwHistory')?.addEventListener('click', () => closeModal('pwHistoryOverlay'));
  document.getElementById('btnDonePwHistory')?.addEventListener('click', () => closeModal('pwHistoryOverlay'));
  document.getElementById('pwHistoryOverlay')?.addEventListener('mousedown', (e) => {
    if (e.target.id === 'pwHistoryOverlay') closeModal('pwHistoryOverlay');
  });
  document.getElementById('btnBannerGoSettings')?.addEventListener('click', () => {
    setView('settings');
    document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.id === 'nav-settings'));
  });

  // Forgot modal
  document.getElementById('btnCloseForgot')?.addEventListener('click', closeForgot);
  document.getElementById('btnEyeNewPw')?.addEventListener('click', () => toggleEye('newPwInp'));
  document.getElementById('btnCancelForgot')?.addEventListener('click', closeForgot);
  document.getElementById('forgotBtn')?.addEventListener('click', handleForgot);

  // Hard reset modal
  document.getElementById('btnCloseHardReset')?.addEventListener('click', closeHardReset);
  document.getElementById('hardResetInp')?.addEventListener('input', () => { document.getElementById('hardResetMsg').style.display='none'; });
  document.getElementById('btnCancelHardReset')?.addEventListener('click', closeHardReset);
  document.getElementById('btnConfirmHardReset')?.addEventListener('click', confirmHardReset);

  // Auto-lock modal
  document.getElementById('btnDismissAutoLock')?.addEventListener('click', dismissAutoLockWarning);

  // Extension reveal modal
  document.getElementById('btnDenyExtReveal')?.addEventListener('click', denyExtReveal);
  document.getElementById('btnApproveExtReveal')?.addEventListener('click', approveExtReveal);

  const togglePrompt = document.getElementById('toggleExtPromptApproval');
  if (togglePrompt) {
    togglePrompt.checked = localStorage.getItem('fuin-ext-prompt-approval') === 'true';
    togglePrompt.addEventListener('change', (e) => {
      localStorage.setItem('fuin-ext-prompt-approval', e.target.checked ? 'true' : 'false');
    });
  }

  // Extension Settings & Chrome Extension registration
  document.getElementById('btnRegisterChromeExt')?.addEventListener('click', handleRegisterChromeExt);
  document.getElementById('chromeExtIdInp')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') handleRegisterChromeExt();
  });
}

async function handleRegisterChromeExt() {
  const inp = document.getElementById('chromeExtIdInp');
  const msg = document.getElementById('extConnectMsg');
  if (!inp || !msg) return;
  const id = inp.value.trim().toLowerCase();
  if (!id || !/^[a-p]{32}$/.test(id)) {
    msg.textContent = t('extInvalidId');
    msg.style.color = 'var(--red)';
    msg.style.display = 'block';
    return;
  }
  try {
    const res = await api.registerChromeExtId(id);
    if (res?.ok) {
      msg.textContent = t('extConnectedSuccess');
      msg.style.color = 'var(--ac)';
      msg.style.display = 'block';
      inp.value = '';
      toast(t('extConnectedSuccess'));
      updateExtStatusUI();
    } else {
      msg.textContent = t('extRegisterFailed');
      msg.style.color = 'var(--red)';
      msg.style.display = 'block';
    }
  } catch (err) {
    msg.textContent = t('toastError') + ': ' + (err?.message || err);
    msg.style.color = 'var(--red)';
    msg.style.display = 'block';
  }
}

async function updateExtStatusUI() {
  try {
    const badge = document.getElementById('extStatusBadge');
    if (!badge || !api.getExtensionStatus) return;
    const status = await api.getExtensionStatus();
    if (status?.running) {
      const count = status.chromeOrigins?.length || 0;
      badge.textContent = t('extStatusActiveCount', { count });
      badge.style.color = 'var(--ac)';
    } else {
      badge.textContent = t('extStatusInactive');
      badge.style.color = 'var(--mu)';
    }
  } catch {}
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initAppListeners);
} else {
  initAppListeners();
}

// ═══════════════════════════════════════════════════════════════════
// AIR-GAP SYNC MODAL LOGIC
// ═══════════════════════════════════════════════════════════════════
let syncChunks       = [];
let syncCurrentIdx   = 0;
let syncFps          = 6;
let syncPaused       = false;
let syncAnimHandle   = null;
let syncLastFrameTime= 0;
let syncEncryptedB64 = null; 

if (api.onSyncChunksReady) {
  api.onSyncChunksReady(payload => {
    syncChunks = payload.chunks;
    syncEncryptedB64 = payload.encryptedB64; 
    document.getElementById('syncOverlay').classList.add('open');
    startSyncAnimation();
  });
}

if (api.onSyncError) {
  api.onSyncError(msg => {
    const preparingText = document.getElementById('preparingText');
    if (preparingText) {
      preparingText.textContent = t('syncErrorPrefix') + msg;
      preparingText.style.color = 'var(--red)';
    }
    const spin = document.querySelector('.qr-preparing .spin');
    if (spin) spin.style.display = 'none';
    toast(t('syncErrorPrefix') + msg);
  });
}

if (api.onSyncKeyExpired) {
  api.onSyncKeyExpired(() => {
    stopSyncAnimation();
    document.getElementById('expiredOverlay').classList.add('show');
    document.getElementById('stStatus').textContent = t('syncTimedOut');
    document.getElementById('stStatus').style.color = 'var(--red)';
  });
}

if (api.onLanSyncApplied) {
  api.onLanSyncApplied(async ({ entries: merged, stats }) => {
    if (lanSyncCountdownTimer) {
      clearInterval(lanSyncCountdownTimer);
      lanSyncCountdownTimer = null;
    }
    document.getElementById('lanSyncOverlay')?.classList.remove('open');
    document.getElementById('pairOverlay')?.classList.remove('open');

    try {
      const seenCreds = new Set();
      const dedupedMerged = [];
      for (const e of (Array.isArray(merged) ? merged : [])) {
        const site = (e.site || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/+$/, '');
        const user = (e.username || '').trim().toLowerCase();
        const key = (site && user && !e.isDeleted && !e.deletedAt) ? `${site}||${user}` : (e.id || '');
        if (key && seenCreds.has(key)) continue;
        if (key) seenCreds.add(key);
        dedupedMerged.push(e);
      }

      entries = await Promise.all(
        dedupedMerged.map(async e => ({
          ...e,
          password: await memEncrypt(e.password),
          totp: await memEncrypt(e.totp)
        }))
      );
      await persist();
      renderList();
      await refreshPairedDevicesList();
      toast(t('toastLanSyncCompleted'));
    } catch (e) {
      toast(t('toastLanSyncProcessError') + e.message);
    }
  });
}

if (api.onLanSyncClosed) {
  api.onLanSyncClosed(({ reason }) => {
    if (lanSyncCountdownTimer) {
      clearInterval(lanSyncCountdownTimer);
      lanSyncCountdownTimer = null;
    }
    document.getElementById('lanSyncOverlay')?.classList.remove('open');
    document.getElementById('pairOverlay')?.classList.remove('open');
    if (reason === 'timeout') {
      toast(t('toastLanSyncTimeout'));
    }
  });
}

if (api.onLanDevicePaired) {
  api.onLanDevicePaired(() => {
    document.getElementById('pairOverlay')?.classList.remove('open');
    refreshPairedDevicesList();
    toast(t('toastDevicePaired'));
  });
}

function renderSyncChunkToCanvas(chunk) {
  return window.FuinSyncAnimation.renderSyncChunkToCanvas(chunk);
}

function animateSync(timestamp) {
  if (syncPaused || !syncChunks.length) { syncAnimHandle = requestAnimationFrame(animateSync); return; }
  const interval = 1000 / syncFps;
  if (timestamp - syncLastFrameTime >= interval) {
    syncLastFrameTime = timestamp;
    renderSyncFrame();
  }
  syncAnimHandle = requestAnimationFrame(animateSync);
}

function renderSyncFrame() {
  window.FuinSyncAnimation.renderSyncFrame({ chunk: syncChunks[syncCurrentIdx], syncFps, t });
  syncCurrentIdx = (syncCurrentIdx + 1) % syncChunks.length;
}

function startSyncAnimation() {
  document.getElementById('preparingOverlay').style.display = 'none';
  syncCurrentIdx = 0; syncLastFrameTime = 0;
  if (syncAnimHandle) cancelAnimationFrame(syncAnimHandle);
  syncAnimHandle = requestAnimationFrame(animateSync);
}

function stopSyncAnimation() {
  if (syncAnimHandle) { cancelAnimationFrame(syncAnimHandle); syncAnimHandle = null; }
}

function toggleSyncPause() {
  syncPaused = !syncPaused;
  window.FuinSyncAnimation.updatePauseUI({ syncPaused, t });
}

function setSyncFps(newFps, btn) {
  syncFps = newFps;
  window.FuinSyncAnimation.updateFpsUI(newFps, btn);
}

function resetSyncTransfer() {
  if (syncPaused) toggleSyncPause();
  syncCurrentIdx = 0;
  syncLastFrameTime = 0;
}

async function closeSyncModal() {
  stopSyncAnimation();
  await api.clearSyncKey();
  window.FuinSyncAnimation.resetSyncModalDOM(t);
}

async function initSyncUIListeners() {
  document.getElementById('btnCloseSync')?.addEventListener('click', closeSyncModal);
  document.getElementById('btnFps3')?.addEventListener('click', function() { setSyncFps(3, this); });
  document.getElementById('btnFps6')?.addEventListener('click', function() { setSyncFps(6, this); });
  document.getElementById('btnFps10')?.addEventListener('click', function() { setSyncFps(10, this); });
  document.getElementById('pauseBtn')?.addEventListener('click', toggleSyncPause);
  document.getElementById('btnResetTransfer')?.addEventListener('click', resetSyncTransfer);
  
  if (api?.cryptoInfo) {
    try {
      const info = await api.cryptoInfo();
      const badge = document.getElementById('syncBadge');
      if (badge && info) {
        badge.textContent = info.argon2 ? 'Argon2id · SyncKey' : 'PBKDF2 · SyncKey';
        badge.style.color  = info.argon2 ? 'var(--green)' : 'var(--amber)';
      }
    } catch {}
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initSyncUIListeners);
} else {
  initSyncUIListeners();
}
