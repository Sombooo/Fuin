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

async function copySecure(text, label) {
  await api.copySecure(text);
  // Toast: geri sayım göster
  let sec = 30;
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
    toast(t('toastError') || 'Hata oluştu');
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

        const seenContent = new Set();
        entries = entries.filter(e => {
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
  ['f-site','f-user','f-pw','f-note','f-url','f-totp','genPwResult','syncPasswordInput','curPwInp','newMasterPwInp','newMasterPwConfirmInp','repromptPwInp'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  ['addOverlay','totpOverlay','genOverlay','pairOverlay','lanSyncOverlay','newCategoryOverlay','changePwOverlay','backupOverlay','recoveryOverlay','repromptOverlay','pwHistoryOverlay'].forEach(id => {
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

api.onExtRevealRequest((req) => {
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
  pendingExtReveal = { requestId: req.requestId, entry, domain: req.domain };
  document.getElementById('extRevealSite').textContent = entry.site;
  document.getElementById('extRevealUser').textContent = entry.username || '—';
  document.getElementById('extRevealDomain').textContent = req.domain || '—';
  document.getElementById('extRevealOverlay').classList.add('open');
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
    else if (v==='trash') document.getElementById('viewTitle').textContent = 'ÇÖP KUTUSU';
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
    getLocalAppVersion().then(ver => {
      const sub = document.getElementById('sysUpdateCheckSub');
      if (sub) sub.textContent = `${t('sysUpdateCheckSub') || "Fuin'in yeni bir sürümü olup olmadığını GitHub üzerinden kontrol edin."} (Mevcut: v${normalizeVersion(ver)})`;
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
    <div class="pw-card" style="animation-delay:${i*15}ms">
      <div class="pw-icon">${esc(e.site.slice(0,2).toUpperCase())}</div>
      <div class="pw-info">
        <div class="pw-site">${e.fav ? `<span class="fav-star" title="${t('navFav') || 'Favori'}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></span>` : ''}<span class="pw-site-name">${esc(e.site)}</span>${e.reprompt ? `<span class="reprompt-badge" title="${esc(t('badgeReprompt'))}"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>` : ''}${e.url && /^http:\/\//i.test(e.url.trim()) ? `<span class="insecure-http-badge" title="${esc(t('warnInsecureHttp'))}">HTTP</span>` : ''}</div>
        <div class="pw-meta">
          <span class="pw-user">${esc(e.username)||'—'}</span>
          <span class="pw-cat">${esc(catLabel(e.category||'Diğer'))}</span>
          <span class="pw-dots" id="dot-${esc(e.id)}">••••••</span>
          <div class="str-dot ${dotClass(scores[i])}"></div>
        </div>
      </div>
      <div class="pw-actions">
        ${curView === 'trash' ? `
          <button class="act-btn" data-action="restore-pw" data-val="${esc(e.id)}" title="${t('btnRestore') || 'Geri Yükle'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/></svg></button>
          <button class="act-btn del" data-action="perm-del-pw" data-val="${esc(e.id)}" title="${t('btnPermDel') || 'Kalıcı Olarak Sil'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
        ` : `
          ${e.totp?`<button class="act-btn" data-action="show-totp" data-val="${esc(e.id)}" title="2FA"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></button>`:''}
          <button class="act-btn" data-action="copy-pw" data-val="${esc(e.id)}" title="${t('btnCopy') || 'Kopyala'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
          <button class="act-btn" data-action="reveal-pw" data-val="${esc(e.id)}" title="${t('showPwTitle') || 'Göster'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
          <button class="act-btn" data-action="edit-pw" data-val="${esc(e.id)}" title="${t('btnEdit') || 'Düzenle'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
          <button class="act-btn del" data-action="del-pw" data-val="${esc(e.id)}" title="${t('btnDel') || 'Sil'}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg></button>
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
    <div class="sec-card"><div class="sec-card-title">${t('secQrSync')}</div>
      <div class="sec-card-value">${t('secQrReady')}</div>
      <div class="sec-card-sub">${t('secQrSub')}</div></div>
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
    document.getElementById('f-pw').value=await memDecrypt(e.password);
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
    await persist(); renderList(); toast(t('toastDeleted') || 'Çöp kutusuna taşındı');
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
    await persist(); renderList(); toast('Kayıt geri yüklendi');
  }
}

async function permDelEntry(id) {
  entries = entries.filter(x=>x.id!==id);
  await persist(); renderList(); toast('Kalıcı olarak silindi');
}

// ── ACTIONS ───────────────────────────────────────────────────────
async function copyPw(id) {
  const e = entries.find(x=>x.id===id);
  if (!e) return;
  const doCopy = async () => {
    const pw = await memDecrypt(e.password);
    await copySecure(pw, t('toastPwCopied'));
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
      revealT[id]=setTimeout(()=>{el.textContent='••••••';el.classList.remove('pw-reveal');},3000);
      const hideOnBlur = () => { el.textContent='••••••'; el.classList.remove('pw-reveal'); clearTimeout(revealT[id]); window.removeEventListener('blur', hideOnBlur); };
      window.addEventListener('blur', hideOnBlur);
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

async function showTOTP(id) {
  const e=entries.find(x=>x.id===id); if(!e?.totp)return;
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

function verifyReprompt() {
  const inp = document.getElementById('repromptPwInp');
  const msg = document.getElementById('repromptMsg');
  const val = inp ? inp.value : '';
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
            ${esc(t('btnCopy') || 'Kopyala')}
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
          await copySecure(raw, t('pwHistoryCopied'));
        }
      });
    });
  }
  document.getElementById('pwHistoryOverlay')?.classList.add('open');
}

// ── EMERGENCY KIT (.html) ──────────────────────────────────────────
function generateEmergencyKitHtml(recoveryKey, dateStr) {
  const isEn = document.documentElement.lang === 'en';
  const title = isEn ? 'FUIN EMERGENCY KIT' : 'FUIN ACİL DURUM KİTİ';
  const subtitle = isEn 
    ? 'Confidential Disaster Recovery Document for your Fuin Password Vault'
    : 'Fuin Şifre Kasanız için Gizli ve Çevrimdışı Kurtarma Belgesi';
  const recoveryTitle = isEn ? 'PRIMARY RECOVERY KEY' : 'BİRİNCİL KURTARMA ANAHTARI';
  const recoveryDesc = isEn
    ? 'This 256-bit cryptographic key can unlock and recover your vault if you ever lose or forget your Master Password. Keep this document strictly confidential.'
    : 'Bu 256-bit kriptografik anahtar, Ana Şifrenizi unutmanız veya erişiminizi kaybetmeniz durumunda kasanızı kurtarmanızı sağlar. Bu belgeyi kesinlikle gizli tutun.';
  const masterPwTitle = isEn ? 'MASTER PASSWORD (HANDWRITTEN)' : 'ANA ŞİFRE (EL YAZISIYLA)';
  const masterPwDesc = isEn
    ? 'Write your Master Password here by hand for air-gapped physical cold backup. Never save this file with your master password typed in.'
    : 'Fiziksel soğuk yedekleme amacıyla buraya Ana Şifrenizi el yazınızla not edin. Bu dosyayı asla dijital olarak şifreniz yazılı halde kaydetmeyin.';
  const instructionsTitle = isEn ? 'DISASTER RECOVERY INSTRUCTIONS' : 'KASAYI KURTARMA ADIMLARI';
  const step1 = isEn 
    ? '1. Open Fuin on your desktop or mobile device.'
    : '1. Fuin uygulamasını bilgisayarınızda veya telefonunuzda açın.';
  const step2 = isEn
    ? '2. On the unlock screen, click "Forgot Password" ("Şifremi Unuttum").'
    : '2. Kilit ekranında "Şifremi Unuttum" bağlantısına tıklayın.';
  const step3 = isEn
    ? '3. Enter the 32-character Primary Recovery Key listed above exactly as shown.'
    : '3. Yukarıda listelenen 32 karakterlik Birincil Kurtarma Anahtarını eksiksiz girin.';
  const step4 = isEn
    ? '4. Set your new Master Password. Your vault entries will be atomically re-encrypted.'
    : '4. Yeni Ana Şifrenizi belirleyin. Kasanız yeni şifrenizle baştan sona otomatik olarak yeniden şifrelenir.';
  const securityRulesTitle = isEn ? 'SECURITY BEST PRACTICES' : 'GÜVENLİK KURALLARI';
  const rule1 = isEn
    ? 'PRINT IMMEDIATELY: Print this page physically on paper and delete this unencrypted HTML file from your downloads.'
    : 'HEMEN YAZDIRIN: Bu sayfayı fiziksel kağıda yazdırın ve indirilen bu HTML dosyasını bilgisayarınızdan kalıcı olarak silin.';
  const rule2 = isEn
    ? 'PHYSICAL STORAGE: Store the printed sheet in a fireproof safe, bank deposit box, or sealed envelope.'
    : 'FİZİKSEL SAKLAMA: Çıktıyı yangına dayanıklı bir kasada, banka kasasında veya kilitli bir çekmecede saklayın.';
  const rule3 = isEn
    ? 'NO DIGITAL SHARING: Never upload this file to Google Drive, iCloud, Dropbox, or send it via email or messaging apps.'
    : 'DİJİTAL PAYLAŞIM YASAKTIR: Bu belgeyi asla bulut depolamaya yüklemeyin, e-posta veya mesajlaşma uygulamalarıyla göndermeyin.';
  const footerNote = isEn
    ? 'Fuin Password Vault • Zero-Knowledge Local Architecture • High-Assurance End-to-End Cryptography'
    : 'Fuin Şifre Yöneticisi • Sıfır Bilgi Yerel Mimari • Uçtan Uca Yüksek Güvenceli Kriptografi';

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
    <button class="btn-print" onclick="window.print()">🖨 ${isEn ? 'Print Emergency Kit' : 'Bu Kiti Yazdır'}</button>
  </div>
  <div class="header">
    <div class="header-left">
      <h1>FUIN</h1>
      <p>${subtitle}</p>
    </div>
    <div class="meta-tag">
      ${isEn ? 'Exported' : 'Tarih'}: ${dateStr}
    </div>
  </div>

  <div class="kit-card">
    <h2>🔑 ${recoveryTitle}</h2>
    <p>${recoveryDesc}</p>
    <div class="key-box">${recoveryKey || '________________________________________'}</div>
  </div>

  <div class="kit-card">
    <h2>✍️ ${masterPwTitle}</h2>
    <p>${masterPwDesc}</p>
    <div class="handwrite-line">${isEn ? '[ Note Master Password here by hand after printing ]' : '[ Yazdırdıktan sonra buraya elle Ana Şifrenizi yazınız ]'}</div>
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
    const proceed = confirm(t('confirmGenKitRegen') || 'Acil durum kitine anahtarınızı eklemek için yeni bir kurtarma anahtarı üretilecek. Onaylıyor musunuz?');
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
  const h=await sha1hex(pw);
  const pre=h.slice(0,5),suf=h.slice(5);
  try {
    const r = await fetch(`https://api.pwnedpasswords.com/range/${pre}`, {
      cache: 'no-store',
      headers: { 'Add-Padding': 'true' }
    });
    if(!r.ok)return -1;
    for(const line of (await r.text()).split('\n')){
      const [hh,c]=line.trim().split(':');
      if(hh===suf)return parseInt(c,10);
    }
    return 0;
  } catch { return -1; }
}

async function runHIBPScan() {
  if(!entries.length){toast(t('hibpNoEntries'));return;}
  const btn=document.getElementById('scanBtn');
  btn.disabled=true; btn.textContent=t('healthScanning');
  const el=document.getElementById('hibpResults');
  el.innerHTML=`<div style="margin-bottom:14px"><div class="scan-bar-wrap"><div class="scan-bar" id="scanBar" style="width:0%"></div></div><div class="scan-status" id="scanSt">0 / ${entries.length}</div></div>`;
  const breached=[],errors=[];
  for(let i=0;i<entries.length;i++){
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
      preparingText.textContent = t('syncPreparing') || 'PAKET HAZIRLANIYOR...';
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
        pairedDeviceName.textContent = `${pairedList[0].deviceName || 'Eşleşmiş Cihaz'} (${pairedList[0].keyPreview || ''})`;
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
      toast(t('toastSyncPassRequired') || 'Sync şifresi gereklidir.');
      inputSyncPass.focus();
      return;
    }
    if (syncPassword.trim().length < 10) {
      toast(t('toastSyncPassMinLength') || 'Sync şifresi en az 10 karakter olmalıdır.');
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

  if (statusText) statusText.textContent = t('lanSyncWaiting') || 'Yerel ağ dinleyicisi başlatıldı. Telefonunuzdan Eşitle\'ye basın...';
  if (timerText) timerText.textContent = `${t('lanSyncTimer') || 'Kalan süre: '}120s`;
  if (addrText) addrText.textContent = t('syncStatusPreparing') || 'Hazırlanıyor...';
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
      if (timerText) timerText.textContent = `${t('lanSyncTimer') || 'Kalan süre: '}${remaining}s`;
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
  if (!confirm(t('confirmRevokeDevice') || 'Bu cihazın eşleşmesini kaldırmak istediğinize emin misiniz?')) return;
  if (!api.revokePairedDevice) return;
  try {
    await api.revokePairedDevice(deviceId);
    toast(t('toastDeviceRevoked') || 'Cihaz eşleşmesi iptal edildi.');
    await refreshPairedDevicesList();
  } catch (err) {
    toast((t('toastError') || 'Hata oluştu: ') + (err.message || ''));
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
      infoEl.textContent = `${t('pairDeviceLabel') || 'Cihaz'}: ${payload.deviceId} · Port: ${payload.port}`;
    }

    document.getElementById('pairOverlay')?.classList.add('open');
  } catch (err) {
    if (api.stopLanSync) await api.stopLanSync();
    toast(t('toastSyncFailed') + err.message);
  }
}

// ── IMPORT / EXPORT ───────────────────────────────────────────────
async function exportJSON() {
  if(!confirm('DİKKAT: Bu işlem tüm şifrelerinizi şifrelenmemiş (plaintext) olarak dışa aktaracaktır.\n\nDevam etmek istiyor musunuz?')) return;
  const exportEntries = await Promise.all(entries.map(async e => ({ ...e, password: await memDecrypt(e.password), totp: await memDecrypt(e.totp) })));
  const payload = { type: 'fuin/vault', categories: [], entries: exportEntries };
  const c=JSON.stringify(payload,null,2);
  await api.exportFile({content:c,defaultName:'fuin-yedek.json',filters:[{name:'JSON',extensions:['json']}]});
  toast(t('toastJsonExported'));
}
async function exportCSV() {
  if(!confirm('DİKKAT: Bu işlem tüm şifrelerinizi şifrelenmemiş (plaintext) olarak dışa aktaracaktır.\n\nDevam etmek istiyor musunuz?')) return;
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
function toggleEye(id){const i=document.getElementById(id);i.type=i.type==='password'?'text':'password';}

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
    const metaText = `${Math.round(res.entropy || 0)} ${bitUnit} · ${t('strengthCrackTime') || 'kırılma:'} ${crackText || ''}`;
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

function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/'/g,'&#39;').replace(/"/g,'&quot;');}

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
    closeModal('addOverlay');closeTOTP();closeForgot();closeHardReset();
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
  if (!master) return; // kilit ekranındayken dinamik liste/kategori yok
  renderCategoryNav();
  if (curView === 'all' || curView === 'fav') {
    const el = document.getElementById('viewTitle');
    if (el) el.textContent = curView === 'fav' ? t('viewTitleFav') : t('viewTitleAll');
  } else if (curView.startsWith('cat:')) {
    const el = document.getElementById('viewTitle');
    if (el) el.textContent = catLabel(curView.slice(4)).toUpperCase();
  }
  renderList();
  if (curView === 'settings') {
    refreshPairedDevicesList();
  }
  if (document.getElementById('addOverlay')?.classList.contains('open')) {
    document.getElementById('addModalTitle').textContent = editId ? t('modalEditEntry') : t('modalNewEntry');
  }
  if (document.getElementById('genOverlay')?.classList.contains('open') && _lastGenRes) {
    renderGenStrengthUI(_lastGenRes);
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
  return window.FuinUpdateManager ? window.FuinUpdateManager.getLocalAppVersion() : '1.0.0-beta.4';
}

async function silentCheckForUpdates() {
  if (window.FuinUpdateManager) return window.FuinUpdateManager.silentCheckForUpdates();
}

async function checkForUpdates() {
  if (window.FuinUpdateManager) return window.FuinUpdateManager.checkForUpdates(t);
}
// ── EVENT DELEGATION FOR DYNAMIC BUTTONS ────────────────────────────
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
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
  document.getElementById('nav-trash')?.addEventListener('click', function() { setView('trash', this); document.getElementById('viewTitle').textContent = 'ÇÖP KUTUSU'; });
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
  document.getElementById('btnExportJSON')?.addEventListener('click', exportJSON);
  document.getElementById('btnExportCSV')?.addEventListener('click', exportCSV);
  document.getElementById('btnImportJSON')?.addEventListener('click', importJSON);
  document.getElementById('btnImportCSV')?.addEventListener('click', importCSV);
  document.getElementById('updateBtn')?.addEventListener('click', checkForUpdates);
  document.getElementById('btnBackupFolder')?.addEventListener('click', () => window.kekkai?.openBackupFolder());

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
  document.getElementById('btnGenAdvCopy')?.addEventListener('click', () => {
    const pw = document.getElementById('genPwResult').value;
    if (pw) {
      window.kekkai?.copyToClipboard(pw);
      toast(t('toastPwCopied') || 'Kopyalandı');
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

  // Recovery modal & Emergency Kit
  document.getElementById('recoveryKeyDisplay')?.addEventListener('click', copyRecoveryKey);
  document.getElementById('btnCloseRecovery')?.addEventListener('click', () => closeModal('recoveryOverlay'));
  document.getElementById('btnRegenRecovery')?.addEventListener('click', handleRegenerateRecovery);
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
      toast(t('toastLanSyncCompleted') || 'Yerel ağ senkronizasyonu tamamlandı.');
    } catch (e) {
      toast((t('toastLanSyncProcessError') || 'Senkronize veriler işlenirken hata: ') + e.message);
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
      toast(t('toastLanSyncTimeout') || 'Yerel ağ eşitlemesi zaman aşımına uğradı (120s).');
    }
  });
}

if (api.onLanDevicePaired) {
  api.onLanDevicePaired(() => {
    document.getElementById('pairOverlay')?.classList.remove('open');
    refreshPairedDevicesList();
    toast(t('toastDevicePaired') || 'Cihaz başarıyla eşlendi.');
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
