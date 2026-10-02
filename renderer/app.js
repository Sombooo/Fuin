'use strict';

const api = window.kekkai;
let master = '', entries = [], editId = null, curView = 'all', totpIv = null;

let sessionKey = null;
async function memEncrypt(text) {
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, sessionKey, encoded);
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

const revealT = {};
if (api.onForceLock) api.onForceLock(() => lock());

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

// ── TOTP (renderer — sadece zamanlama, crypto main'de) ────────────
function b32dec(s) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  s = s.toUpperCase().replace(/[\s=]/g,'');
  let bits=0,val=0; const out=[];
  for(const c of s){const i=chars.indexOf(c);if(i<0)continue;val=(val<<5)|i;bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8;}}
  return new Uint8Array(out);
}
async function getTOTP(secret) {
  try {
    const key = b32dec(secret);
    const t   = Math.floor(Date.now()/1000/30);
    const tb  = new DataView(new ArrayBuffer(8)); tb.setUint32(4,t);
    const ck  = await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-1'},false,['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC',ck,tb.buffer));
    const off = sig[sig.length-1]&0xf;
    const code= ((sig[off]&0x7f)<<24|(sig[off+1]&0xff)<<16|(sig[off+2]&0xff)<<8|(sig[off+3]&0xff))%1000000;
    return String(code).padStart(6,'0');
  } catch { return '------'; }
}

async function sha1hex(str) {
  const buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase();
}

// ── RECOVERY KEY ──────────────────────────────────────────────────
function generateRecoveryKey() {
  const arr = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(arr).map(b=>b.toString(16).padStart(2,'0')).join('').toUpperCase().match(/.{1,8}/g).join('-');
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
  sessionKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
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
        toast(t('toastWrongPassword'));
        const inp = document.getElementById('masterInp');
        inp.style.borderColor = 'var(--red)';
        setTimeout(() => inp.style.borderColor='', 800);
        return;
      }
    } else { entries = []; }
  } else { entries = []; }

  master = pw;
  btn.disabled = false; loading.classList.remove('show');
  document.getElementById('lockScreen').style.display = 'none';
  const appEl = document.getElementById('app');
  appEl.style.display='flex'; appEl.style.flexDirection='column';
  renderList();
  renderCategoryNav();
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
  document.getElementById('lockScreen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('searchInp').value='';
  document.getElementById('unlockBtn').disabled=false;
  document.getElementById('lockLoading').classList.remove('show');
  editId=null;
  document.getElementById('masterInp').value='';
  closeTOTPTimer();
  api.cancelClipboardClear();
  api.setUnlockState(false);
  initTouchId();
  document.getElementById('autoLockOverlay')?.classList.remove('open');
  if (pendingExtReveal) { api.extRespond(pendingExtReveal.requestId, { error: 'locked' }); pendingExtReveal = null; }
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
    .filter(e => domainMatches(e, req.domain))
    .map(e => ({ id: e.id, site: e.site, username: e.username }));
  api.extRespond(req.requestId, matches);
});

api.onExtRevealRequest((req) => {
  if (pendingExtReveal !== null) {
    api.extRespond(req.requestId, { error: 'busy' });
    return;
  }
  const entry = entries.find(e => e.id === req.entryId);
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
  const exportEntries = await Promise.all(entries.map(async e => ({ ...e, password: await memDecrypt(e.password), totp: await memDecrypt(e.totp) })));
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
        <span class="icon">▸</span> ${esc(catLabel(c))} <span style="margin-left:auto;color:var(--mu);font-size:11px">${counts[c] || 0}</span>
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

  const scores = await Promise.all(list.map(async e=>getScore(await memDecrypt(e.password))));
  const dotClass = s => s>=3?'strong':s>=2?'medium':'weak';

  wrap.innerHTML = list.map((e,i) => `
    <div class="pw-card" style="animation-delay:${i*15}ms">
      <div class="pw-icon">${esc(e.site.slice(0,2).toUpperCase())}</div>
      <div class="pw-info">
        <div class="pw-site">${esc(e.site)}${e.fav?' ◆':''}</div>
        <div class="pw-meta">
          <span class="pw-user">${esc(e.username)||'—'}</span>
          <span class="pw-cat">${esc(catLabel(e.category||'Diğer'))}</span>
          <span class="pw-dots" id="dot-${e.id}">••••••</span>
          <div class="str-dot ${dotClass(scores[i])}"></div>
        </div>
      </div>
      <div class="pw-actions">
        ${curView === 'trash' ? `
          <button class="act-btn" data-action="restore-pw" data-val="${e.id}" title="Geri Yükle">↺</button>
          <button class="act-btn del" data-action="perm-del-pw" data-val="${e.id}" title="Kalıcı Olarak Sil">✕</button>
        ` : `
          ${e.totp?`<button class="act-btn" data-action="show-totp" data-val="${e.id}" title="2FA">▲</button>`:''}
          <button class="act-btn" data-action="copy-pw" data-val="${e.id}" title="Kopyala">⎘</button>
          <button class="act-btn" data-action="reveal-pw" data-val="${e.id}" title="Göster">●</button>
          <button class="act-btn" data-action="edit-pw" data-val="${e.id}" title="Düzenle">✎</button>
          <button class="act-btn del" data-action="del-pw" data-val="${e.id}" title="Sil">✕</button>
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
async function openAddModal(id=null) {
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
    document.getElementById('totp-section').style.display=e.totp?'block':'none';
    onPwInput();
  } else {
    ['f-site','f-user','f-pw','f-note','f-url','f-totp'].forEach(i=>document.getElementById(i).value='');
    sel.value='Diğer';
    document.getElementById('f-2fa-toggle').checked=false;
    document.getElementById('f-fav').checked=false;
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
  const entry={
    id: editId||crypto.randomUUID(), site,
    category: document.getElementById('f-category').value,
    username: document.getElementById('f-user').value.trim(),
    password: await memEncrypt(pw),
    note:     document.getElementById('f-note').value.trim(),
    url:      document.getElementById('f-url').value.trim(),
    totp:     await memEncrypt(document.getElementById('f-2fa-toggle').checked ? document.getElementById('f-totp').value.trim() : ''),
    fav:      document.getElementById('f-fav').checked,
    updated:  Date.now(),
  };
  if(editId){const i=entries.findIndex(x=>x.id===editId);entries[i]=entry;}
  else entries.unshift({...entry,created:Date.now()});
  await persist(); closeModal('addOverlay'); renderList();
  toast(editId?t('toastUpdated'):t('toastSaved'));
}

async function delEntry(id) {
  const i = entries.findIndex(x=>x.id===id);
  if(i !== -1) {
    entries[i].isDeleted = true;
    entries[i].updated = Date.now();
    await persist(); renderList(); toast(t('toastDeleted') || 'Çöp kutusuna taşındı');
  }
}

async function restoreEntry(id) {
  const i = entries.findIndex(x=>x.id===id);
  if(i !== -1) {
    entries[i].isDeleted = false;
    entries[i].updated = Date.now();
    await persist(); renderList(); toast('Kayıt geri yüklendi');
  }
}

async function permDelEntry(id) {
  entries = entries.filter(x=>x.id!==id);
  await persist(); renderList(); toast('Kalıcı olarak silindi');
}

// ── ACTIONS ───────────────────────────────────────────────────────
async function copyPw(id) {
  const pwEnc = entries.find(x=>x.id===id)?.password;
  if (!pwEnc) return;
  const pw = await memDecrypt(pwEnc);
  await copySecure(pw, t('toastPwCopied'));
}

async function revealPw(id) {
  const el=document.getElementById('dot-'+id); if(!el)return;
  const e=entries.find(x=>x.id===id);
  if(el.classList.contains('pw-reveal')){
    el.textContent='••••••'; el.classList.remove('pw-reveal'); clearTimeout(revealT[id]);
  } else {
    el.textContent=await memDecrypt(e.password); el.classList.add('pw-reveal');
    clearTimeout(revealT[id]);
    revealT[id]=setTimeout(()=>{el.textContent='••••••';el.classList.remove('pw-reveal');},3000);
    // Güvenlik: Pencere odağı kaybedildiğinde parolayı hemen gizle
    const hideOnBlur = () => { el.textContent='••••••'; el.classList.remove('pw-reveal'); clearTimeout(revealT[id]); window.removeEventListener('blur', hideOnBlur); };
    window.addEventListener('blur', hideOnBlur);
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
  const tick=async()=>{
    const c=await getTOTP(await memDecrypt(e.totp));
    document.getElementById('totpCode').textContent=c.slice(0,3)+' '+c.slice(3);
    const sec=30-Math.floor(Date.now()/1000)%30;
    document.getElementById('totpBar').style.width=(sec/30*100)+'%';
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
  const msgEl=document.getElementById('forgotMsg');
  msgEl.style.display='none'; msgEl.textContent='';
  document.getElementById('newPwGroup').style.display='none';
  document.getElementById('forgotBtn').textContent=t('forgotVerifyBtn');
  document.getElementById('recoveryInp').value='';
  document.getElementById('newPwInp').value='';
  document.getElementById('forgotOverlay').classList.add('open');
}

function closeForgot() { recoveryVerified=false; closeModal('forgotOverlay'); }

async function handleForgot() {
  const inp=document.getElementById('recoveryInp').value.trim();
  const msgEl=document.getElementById('forgotMsg');
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
  const el=document.getElementById('forgotMsg');
  const colors={ green:'rgba(61,107,79,.08)', red:'rgba(160,52,42,.08)', amber:'rgba(176,112,32,.08)' };
  const borders={ green:'rgba(61,107,79,.2)', red:'rgba(160,52,42,.2)', amber:'rgba(176,112,32,.2)' };
  el.style.display='block';
  el.style.color=`var(--${type})`;
  el.style.background=colors[type];
  el.style.border=`1px solid ${borders[type]}`;
  el.textContent=text;
}

function copyRecoveryKey() {
  const key=document.getElementById('recoveryKeyDisplay').textContent;
  copySecure(key, t('toastRecoveryCopied')); // Güvenlik: 30 saniye sonra panoyu temizle
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
  const h=await sha1hex(pw);
  const pre=h.slice(0,5),suf=h.slice(5);
  try {
    const r=await fetch(`https://api.pwnedpasswords.com/range/${pre}`,{headers:{'Add-Padding':'true'}});
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

  // ── V2 PATH ─────────────────────────────────────────────────────────────────
  // Request Sync Password separately from Vault Password (INV-01).
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
    if (syncPassword.trim().length < 6) {
      toast(t('toastSyncPassMinLength') || 'Sync şifresi en az 6 karakter olmalıdır.');
      inputSyncPass.focus();
      return;
    }
    cleanup();

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
// ── CSV satır parser — tırnak içindeki virgülleri doğru işler ────
function parseCSVLine(line) {
  const result = [];
  let cur = '', inQuote = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (c === '"') {
      if (inQuote && line[i+1] === '"') { cur += '"'; i++; }
      else inQuote = !inQuote;
    } else if (c === ',' && !inQuote) {
      result.push(cur.trim()); cur = '';
    } else cur += c;
  }
  result.push(cur.trim());
  return result;
}

// ── Format dedektörü ──────────────────────────────────────────────
function detectCSVFormat(header) {
  const h = header.toLowerCase();
  // Bitwarden: name,login_uri,login_username,login_password
  if (h.includes('login_username') || h.includes('login_password')) return 'bitwarden';
  // LastPass: url,username,password,extra,name,grouping,fav
  if (h.includes('grouping') || h.includes('extra')) return 'lastpass';
  // 1Password: Title,Username,Password,URL,Notes,OTPAuth
  if (h.includes('otpauth') || (h.includes('title') && h.includes('username'))) return '1password';
  // Chrome/Edge/Brave: name,url,username,password
  if (h.includes('name') && h.includes('url') && h.includes('username') && h.includes('password')) return 'chrome';
  // Fuin/Kekkai: site,username,password,url,note
  return 'fuin';
}

// ── CSV satırını Fuin entry'sine dönüştür ────────────────────────
function csvRowToEntry(cols, colMap) {
  const get = (key) => (cols[colMap[key]] || '').trim();
  const site = get('site') || get('url') || '';
  const password = get('password');
  if (!site || !password) return null;
  return {
    id:       crypto.randomUUID(),
    site,
    category: get('category') || 'Diğer',
    username: get('username') || '',
    password,
    url:      get('url') || '',
    note:     get('note') || '',
    totp:     get('totp') || '',
    fav:      false,
    created:  Date.now(),
    updated:  Date.now(),
  };
}

// ── Format → kolon haritası ───────────────────────────────────────
function buildColMap(headers, format) {
  const h = headers.map(x => x.toLowerCase().trim());
  const idx = (k) => h.indexOf(k);
  if (format === 'bitwarden') return {
    site:     idx('name'),
    url:      idx('login_uri'),
    username: idx('login_username'),
    password: idx('login_password'),
    note:     idx('notes') > -1 ? idx('notes') : idx('extra'),
    totp:     idx('login_totp'),
  };
  if (format === 'lastpass') return {
    site:     idx('name') > -1 ? idx('name') : idx('url'),
    url:      idx('url'),
    username: idx('username'),
    password: idx('password'),
    note:     idx('extra'),
    totp:     -1,
  };
  if (format === '1password') return {
    site:     idx('title'),
    url:      idx('url'),
    username: idx('username'),
    password: idx('password'),
    note:     idx('notes') > -1 ? idx('notes') : idx('note'),
    totp:     idx('otpauth'),
  };
  if (format === 'chrome') return {
    site:     idx('name'),
    url:      idx('url'),
    username: idx('username'),
    password: idx('password'),
    note:     -1,
    totp:     -1,
  };
  // fuin varsayılan
  return {
    site:     idx('site'),
    url:      idx('url'),
    username: idx('username'),
    password: idx('password'),
    note:     idx('note'),
    category: idx('category'),
    totp:     idx('totp') > -1 ? idx('totp') : -1,
  };
}

async function importJSON() {
  const raw = await api.importFile({filters:[{name:'JSON',extensions:['json']}]});
  if (!raw) return;
  try {
    let imp = JSON.parse(raw);

    if (imp && imp.type === 'fuin/vault') {
      imp = imp.entries || [];
    } else if (imp.items) {
      // Bitwarden JSON
      imp = imp.items;
    }

    const normalized = imp.map(e => {
      // Bitwarden JSON item formatı
      if (e.login) return {
        id:       crypto.randomUUID(),
        site:     e.name || '',
        username: e.login.username || '',
        password: e.login.password || '',
        url:      (e.login.uris?.[0]?.uri) || '',
        note:     e.notes || '',
        totp:     e.login.totp || '',
        fav:      !!e.favorite,
        created:  Date.now(), updated: Date.now(),
      };
      // Fuin native formatı
      return { ...e, id: crypto.randomUUID() }; // Güvenlik: import edilen ID'lere güvenme
    });

    const currentDecrypted = await Promise.all(entries.map(async e => ({ site: e.site, username: e.username, password: await memDecrypt(e.password) })));
    
    let newEntries = normalized.filter(x =>
      x.site && x.password &&
      !currentDecrypted.find(e => e.site === x.site && e.username === x.username && e.password === x.password)
    );
    
    newEntries = await Promise.all(newEntries.map(async e => ({ ...e, password: await memEncrypt(e.password), totp: await memEncrypt(e.totp) })));
    entries = [...entries, ...newEntries];
    await persist(); renderList();
    toast(`${newEntries.length} ${t('toastEntriesAdded')}`);
  } catch (err) { toast(t('toastInvalidFile') + err.message); }
}

async function importCSV() {
  const raw = await api.importFile({filters:[{name:'CSV',extensions:['csv']}]});
  if (!raw) return;
  try {
    const lines = raw.split('\n').filter(Boolean);
    if (lines.length < 2) { toast(t('toastEmptyFile')); return; }

    const headers = parseCSVLine(lines[0]);
    const format  = detectCSVFormat(lines[0]);
    const colMap  = buildColMap(headers, format);

    const formatNames = {
      bitwarden: 'Bitwarden', lastpass: 'LastPass',
      '1password': '1Password', chrome: 'Chrome/Edge',
      fuin: 'Fuin',
    };

    let added = 0;
    const currentDecrypted = await Promise.all(entries.map(async e => ({ site: e.site, username: e.username, password: await memDecrypt(e.password) })));
    for (const line of lines.slice(1)) {
      if (!line.trim()) continue;
      const cols  = parseCSVLine(line);
      const entry = csvRowToEntry(cols, colMap);
      if (!entry) continue;
      if (currentDecrypted.find(e => e.site === entry.site && e.username === entry.username && e.password === entry.password)) continue;
      entry.password = await memEncrypt(entry.password);
      entry.totp = await memEncrypt(entry.totp);
      entries.unshift(entry);
      added++;
    }

    await persist(); renderList();
    toast(`${formatNames[format]} — ${added} ${t('toastEntriesAdded')}`);
  } catch (err) { toast(t('toastCsvUnreadable') + err.message); }
}

// ── HELPERS ───────────────────────────────────────────────────────
function toggleEye(id){const i=document.getElementById(id);i.type=i.type==='password'?'text':'password';}

function genPw(){
  document.getElementById('genOverlay').classList.add('open');
  generateAdvancedPw();
}

function generateAdvancedPw() {
  const len = parseInt(document.getElementById('genLen').value) || 16;
  const useUpper = document.getElementById('genUpper').checked;
  const useLower = document.getElementById('genLower').checked;
  const useNum = document.getElementById('genNum').checked;
  const useSym = document.getElementById('genSym').checked;
  const exc = document.getElementById('genExc').checked;

  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const nums = '0123456789';
  const syms = '!@#$%^&*()_+~`|}{[]:;?><,./-=';
  const similar = 'il1Lo0O';

  let charset = '';
  if (useUpper) charset += upper;
  if (useLower) charset += lower;
  if (useNum) charset += nums;
  if (useSym) charset += syms;

  if (exc) {
    charset = charset.split('').filter(c => !similar.includes(c)).join('');
  }

  if (!charset) {
    document.getElementById('genPwResult').value = '';
    return;
  }

  let pw = '';
  const maxValid = 4294967295 - (4294967295 % charset.length);
  const rnd = new Uint32Array(1);
  for (let i = 0; i < len; i++) {
    let r;
    do {
      crypto.getRandomValues(rnd);
      r = rnd[0];
    } while (r >= maxValid);
    pw += charset[r % charset.length];
  }
  document.getElementById('genPwResult').value = pw;

  // Calculate generic strength based on len and charset
  let score = 0;
  if (len >= 12) score++;
  if (len >= 16) score++;
  if (useUpper) score++;
  if (useNum) score++;
  if (useSym) score++;
  if (score > 4) score = 4;
  if (len < 8) score = 0;

  const colors = ['var(--red)', 'var(--amber)', 'var(--yellow)', 'var(--ac)', 'var(--ac)'];
  const labels = [t('healthWeak') || 'Zayıf', t('healthMedium') || 'Orta', t('healthMedium') || 'Orta', t('healthStrong') || 'Güçlü', t('healthStrong') || 'Güçlü'];
  const widths = ['20%', '40%', '60%', '80%', '100%'];

  const fill = document.getElementById('genStrengthFill');
  const label = document.getElementById('genStrengthLabel');
  if (fill && label) {
    fill.style.width = widths[score] || '0%';
    fill.style.background = colors[score] || 'var(--red)';
    label.innerText = labels[score] || '...';
  }
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
  if(e.key==='Escape'){if(pendingExtReveal)denyExtReveal();closeModal('addOverlay');closeTOTP();closeForgot();closeHardReset();}
  if((e.ctrlKey||e.metaKey)&&e.key==='n'){e.preventDefault();if(master)openAddModal();}
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
  if (document.getElementById('addOverlay')?.classList.contains('open')) {
    document.getElementById('addModalTitle').textContent = editId ? t('modalEditEntry') : t('modalNewEntry');
  }
}

// ── UPDATES ────────────────────────────────────────────────────────
function normalizeVersion(v) {
  return String(v || '').trim().replace(/^v/i, '');
}

function isNewerVersion(latest, current) {
  const l = normalizeVersion(latest);
  const c = normalizeVersion(current);
  if (!l || !c || l === c) return false;

  const [lCore, lPre] = l.split('-');
  const [cCore, cPre] = c.split('-');

  const lParts = lCore.split('.').map(x => parseInt(x, 10) || 0);
  const cParts = cCore.split('.').map(x => parseInt(x, 10) || 0);

  for (let i = 0; i < 3; i++) {
    const lp = lParts[i] || 0;
    const cp = cParts[i] || 0;
    if (lp > cp) return true;
    if (lp < cp) return false;
  }

  // Same core version. A release without prerelease is newer than one with (e.g. 1.0.0 > 1.0.0-beta.1)
  if (!lPre && cPre) return true;
  if (lPre && !cPre) return false;

  // Both have prereleases: compare pre parts (e.g. beta.2 > beta.1)
  if (lPre && cPre) {
    const lPreParts = lPre.split('.');
    const cPreParts = cPre.split('.');
    for (let i = 0; i < Math.max(lPreParts.length, cPreParts.length); i++) {
      const lp = lPreParts[i];
      const cp = cPreParts[i];
      if (lp === undefined) return false;
      if (cp === undefined) return true;
      const ln = parseInt(lp, 10);
      const cn = parseInt(cp, 10);
      if (!isNaN(ln) && !isNaN(cn)) {
        if (ln > cn) return true;
        if (ln < cn) return false;
      } else if (lp > cp) return true;
      else if (lp < cp) return false;
    }
  }

  return false;
}

async function getLocalAppVersion() {
  try {
    const v = await window.kekkai?.getAppVersion?.();
    if (v) return v;
  } catch {}
  return '1.0.0-beta.2';
}

async function silentCheckForUpdates() {
  try {
    const res = await fetch('https://api.github.com/repos/Sombooo/Fuin/releases', { cache: 'no-store' });
    if (!res.ok) return;
    const releases = await res.json();
    if (!Array.isArray(releases) || releases.length === 0) return;
    const latestRelease = releases.find(r => !r.draft) || releases[0];
    const latestVersion = latestRelease?.tag_name;
    const currentVersion = await getLocalAppVersion();
    if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
      const badge = document.getElementById('navUpdateBadge');
      if (badge) badge.style.display = 'block';
    }
  } catch (e) {
    // Sessiz hata (internet yok veya firewall engelledi)
  }
}

async function checkForUpdates() {
  const btn = document.getElementById('updateBtn');
  const msg = document.getElementById('updateMsg');
  const subEl = document.getElementById('sysUpdateCheckSub');
  if (!btn || !msg) return;
  btn.disabled = true;
  btn.textContent = '...';
  msg.textContent = '';
  
  try {
    const currentVersion = await getLocalAppVersion();
    if (subEl) {
      subEl.textContent = `${t('sysUpdateCheckSub') || "Fuin'in yeni bir sürümü olup olmadığını GitHub üzerinden kontrol edin."} (Mevcut: v${normalizeVersion(currentVersion)})`;
    }

    const res = await fetch('https://api.github.com/repos/Sombooo/Fuin/releases', { cache: 'no-store' });
    if (!res.ok) throw new Error('API error (' + res.status + ')');
    const releases = await res.json();
    if (!Array.isArray(releases) || releases.length === 0) {
      msg.textContent = 'Henüz yayınlanmış bir sürüm bulunamadı.';
      return;
    }

    const latestRelease = releases.find(r => !r.draft) || releases[0];
    const latestVersion = latestRelease?.tag_name;
    
    if (latestVersion && isNewerVersion(latestVersion, currentVersion)) {
      msg.textContent = '';
      const vSpan = document.createElement('span');
      vSpan.style.color = 'var(--green)';
      vSpan.textContent = `Yeni sürüm mevcut: ${latestVersion}`;
      msg.appendChild(vSpan);
      // Güvenlik: URL'yi doğrula — sadece github.com domaininden kabul et
      if (latestRelease.html_url && latestRelease.html_url.startsWith('https://github.com/')) {
        const link = document.createElement('a');
        link.href = '#';
        link.textContent = 'İndir';
        link.style.cssText = 'color:var(--text);text-decoration:underline;margin-left:8px;cursor:pointer';
        link.addEventListener('click', (ev) => { ev.preventDefault(); window.kekkai?.openUrl(latestRelease.html_url); });
        msg.appendChild(link);
      }
    } else {
      msg.textContent = `En güncel sürümü kullanıyorsunuz (v${normalizeVersion(currentVersion)}).`;
    }
  } catch (err) {
    msg.textContent = 'Kontrol edilemedi. İnternet bağlantısını kontrol edin veya depo adresini ayarlayın.';
  } finally {
    btn.disabled = false;
    btn.textContent = t('sysUpdateBtn');
  }
}
// ── EVENT DELEGATION FOR DYNAMIC BUTTONS ────────────────────────────
document.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const action = btn.getAttribute('data-action');
  const val = btn.getAttribute('data-val');

  if (action === 'set-view') setView(val, btn);
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
document.addEventListener('DOMContentLoaded', () => {
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
  document.getElementById('nav-sync')?.addEventListener('click', openSyncWindow);
  document.getElementById('nav-lock')?.addEventListener('click', lock);

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

  // Recovery modal
  document.getElementById('recoveryKeyDisplay')?.addEventListener('click', copyRecoveryKey);
  document.getElementById('btnCloseRecovery')?.addEventListener('click', () => closeModal('recoveryOverlay'));
  document.getElementById('btnRegenRecovery')?.addEventListener('click', handleRegenerateRecovery);
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
});

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

function renderSyncChunkToCanvas(chunk) {
  const qrText = chunk.qrString;

  const canvas = document.getElementById('qrCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const div = document.createElement('div');
  div.style.display = 'none';
  document.body.appendChild(div);

  try {
    new QRCode(div, {
      text:           qrText,
      width:          260,
      height:         260,
      colorDark:      '#2a2520',
      colorLight:     '#ffffff',
      correctLevel:   QRCode.CorrectLevel.M,
    });
    const qrCanvasEl = div.querySelector('canvas');
    if (qrCanvasEl) {
      ctx.clearRect(0, 0, 260, 260);
      ctx.drawImage(qrCanvasEl, 0, 0, 260, 260);
    }
  } catch(e) {
    ctx.fillStyle = '#f5f0e8';
    ctx.fillRect(0,0,260,260);
    ctx.fillStyle = '#a0342a';
    ctx.font = '12px monospace';
    ctx.fillText('Chunk çok büyük', 20, 130);
  } finally {
    document.body.removeChild(div);
  }
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
  const chunk = syncChunks[syncCurrentIdx];
  renderSyncChunkToCanvas(chunk);
  document.getElementById('stChunk').textContent  = `${chunk.index} / ${chunk.total}`;
  document.getElementById('stStatus').textContent = t('syncTransferring');
  document.getElementById('stStatus').style.color = 'var(--green)';
  document.getElementById('stFps').textContent    = `${syncFps} FPS`;
  const sessionDisplay = chunk.sessionId || '';
  document.getElementById('transferIdVal').textContent = sessionDisplay;
  document.getElementById('chunkBar').style.width = (chunk.index / chunk.total * 100) + '%';
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
  const btn = document.getElementById('pauseBtn');
  if (syncPaused) {
    btn.textContent = t('syncResume');
    btn.classList.remove('pause');
    document.getElementById('stStatus').textContent = t('syncPaused');
    document.getElementById('stStatus').style.color = 'var(--amber)';
  } else {
    btn.textContent = t('syncPause');
    btn.classList.add('pause');
  }
}

function setSyncFps(newFps, btn) {
  syncFps = newFps;
  document.getElementById('btnFps3').classList.remove('active');
  document.getElementById('btnFps6').classList.remove('active');
  document.getElementById('btnFps10').classList.remove('active');
  btn.classList.add('active');
  document.getElementById('stFps').textContent = `${syncFps} FPS`;
}

function resetSyncTransfer() {
  if (syncPaused) toggleSyncPause();
  syncCurrentIdx = 0;
  syncLastFrameTime = 0;
}

async function closeSyncModal() {
  stopSyncAnimation();
  await api.clearSyncKey();
  document.getElementById('syncOverlay').classList.remove('open');
  document.getElementById('expiredOverlay').classList.remove('show');
  const prep = document.getElementById('preparingOverlay');
  if (prep) prep.style.display = 'flex';
  const spin = document.querySelector('.qr-preparing .spin');
  if (spin) spin.style.display = 'block';
  const prepText = document.getElementById('preparingText');
  if (prepText) {
    prepText.textContent = t('syncPreparing') || 'PAKET HAZIRLANIYOR...';
    prepText.style.color = '';
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  document.getElementById('btnCloseSync')?.addEventListener('click', closeSyncModal);
  document.getElementById('btnFps3')?.addEventListener('click', function() { setSyncFps(3, this); });
  document.getElementById('btnFps6')?.addEventListener('click', function() { setSyncFps(6, this); });
  document.getElementById('btnFps10')?.addEventListener('click', function() { setSyncFps(10, this); });
  document.getElementById('pauseBtn')?.addEventListener('click', toggleSyncPause);
  document.getElementById('btnResetTransfer')?.addEventListener('click', resetSyncTransfer);
  
  if (api.cryptoInfo) {
    const info = await api.cryptoInfo();
    const badge = document.getElementById('syncBadge');
    if (badge) {
      badge.textContent = info.argon2 ? 'Argon2id · SyncKey' : 'PBKDF2 · SyncKey';
      badge.style.color  = info.argon2 ? 'var(--green)' : 'var(--amber)';
    }
  }
});
