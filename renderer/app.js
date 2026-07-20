'use strict';

const api = window.kekkai;
let master = '', entries = [], editId = null, curView = 'all', totpIv = null;
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
  // Her ikisi de main process üzerinden dosyaya yazılır — localStorage kullanılmaz
  await api.saveRecovery(enc);
  await api.saveMasterEnc(masterEnc);
}

// ── LOCK / UNLOCK ─────────────────────────────────────────────────
async function unlock() {
  const pw = document.getElementById('masterInp').value;
  if (!pw || pw.length < 4) { toast(t('toastMinChars')); return; }

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
      try { entries = await api.decrypt(raw, pw); }
      catch {
        btn.disabled = false; loading.classList.remove('show');
        toast(t('toastWrongPassword'));
        const inp = document.getElementById('masterInp');
        inp.style.borderColor = 'var(--red)';
        setTimeout(() => inp.style.borderColor='', 800);
        return;
      }
    } else entries = [];
  } else entries = [];

  master = pw;
  btn.disabled = false; loading.classList.remove('show');
  document.getElementById('lockScreen').style.display = 'none';
  const appEl = document.getElementById('app');
  appEl.style.display='flex'; appEl.style.flexDirection='column';
  renderList();
  renderCategoryNav();
  api.setUnlockState(true);

  if (!exists) {
    await persist();
    const rKey = generateRecoveryKey();
    await saveRecoveryKey(rKey, pw);
    document.getElementById('recoveryKeyDisplay').textContent = rKey;
    document.getElementById('recoveryOverlay').classList.add('open');
  }
}

function lock() {
  master=''; entries=[]; editId=null;
  document.getElementById('masterInp').value='';
  document.getElementById('lockScreen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('searchInp').value='';
  document.getElementById('unlockBtn').disabled=false;
  document.getElementById('lockLoading').classList.remove('show');
  closeTOTPTimer();
  api.cancelClipboardClear();
  api.setUnlockState(false);
  document.getElementById('autoLockOverlay')?.classList.remove('open');
  if (pendingExtReveal) { api.extRespond(pendingExtReveal.requestId, { error: 'locked' }); pendingExtReveal = null; }
  document.getElementById('extRevealOverlay')?.classList.remove('open');
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
  try { return new URL(s).hostname.replace(/^www\./, ''); }
  catch { return str.toLowerCase().replace(/^www\./, '').split('/')[0]; }
}
function domainMatches(entry, domain) {
  const entryDomain = normalizeDomain(entry.url || entry.site);
  if (!entryDomain || !domain) return false;
  return domain === entryDomain
    || domain.endsWith('.' + entryDomain)
    || entryDomain.endsWith('.' + domain);
}

let pendingExtReveal = null;

api.onExtLookupRequest((req) => {
  const matches = entries
    .filter(e => domainMatches(e, req.domain))
    .map(e => ({ id: e.id, site: e.site, username: e.username }));
  api.extRespond(req.requestId, matches);
});

api.onExtRevealRequest((req) => {
  const entry = entries.find(e => e.id === req.entryId);
  if (!entry) { api.extRespond(req.requestId, { error: 'not-found' }); return; }
  pendingExtReveal = { requestId: req.requestId, entry };
  document.getElementById('extRevealSite').textContent = entry.site;
  document.getElementById('extRevealUser').textContent = entry.username || '—';
  document.getElementById('extRevealDomain').textContent = req.domain || '—';
  document.getElementById('extRevealOverlay').classList.add('open');
});

function approveExtReveal() {
  if (!pendingExtReveal) return;
  const { requestId, entry } = pendingExtReveal;
  api.extRespond(requestId, { username: entry.username, password: entry.password, totp: entry.totp || null });
  pendingExtReveal = null;
  document.getElementById('extRevealOverlay').classList.remove('open');
  toast(t('toastExtCredSent'));
}
function denyExtReveal() {
  if (!pendingExtReveal) return;
  api.extRespond(pendingExtReveal.requestId, { error: 'denied' });
  pendingExtReveal = null;
  document.getElementById('extRevealOverlay').classList.remove('open');
}

document.getElementById('masterInp').addEventListener('keydown', e => e.key==='Enter' && unlock());

async function persist() {
  const enc = await api.encrypt(entries, master);
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
  const cats = Object.keys(counts).sort((a,b)=>a.localeCompare('tr'));

  if (!cats.length) { section.style.display='none'; wrap.innerHTML=''; return; }
  section.style.display='block';
  wrap.innerHTML = cats.map(c => `
    <button class="nav-item" onclick="setView('cat:${esc(c)}',this)">
      <span class="icon">▸</span> ${esc(catLabel(c))} <span style="margin-left:auto;color:var(--mu);font-size:11px">${counts[c]}</span>
    </button>`).join('');
}

// ── VIEWS ─────────────────────────────────────────────────────────
function setView(v, btn) {
  curView = v;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  btn.classList.add('active');
  ['passwords','health','security','io'].forEach(id => {
    const el = document.getElementById('view-'+id);
    if (el) el.style.display = 'none';
  });
  if (v==='all'||v==='fav') {
    document.getElementById('view-passwords').style.display='flex';
    document.getElementById('viewTitle').textContent = v==='fav' ? t('viewTitleFav') : t('viewTitleAll');
    renderList();
  } else if (v.startsWith('cat:')) {
    document.getElementById('view-passwords').style.display='flex';
    document.getElementById('viewTitle').textContent = catLabel(v.slice(4)).toUpperCase();
    renderList();
  } else if (v==='health') {
    document.getElementById('view-health').style.display='block'; renderHealth();
  } else if (v==='security') {
    document.getElementById('view-security').style.display='block'; renderSecurity();
  } else if (v==='io') {
    document.getElementById('view-io').style.display='block';
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
  if (curView==='fav') list = list.filter(e=>e.fav);
  else if (curView.startsWith('cat:')) { const cat=curView.slice(4); list = list.filter(e=>(e.category||'Diğer')===cat); }
  if (q) list = list.filter(e=>(e.site+e.username).toLowerCase().includes(q));

  const wrap = document.getElementById('pwList');
  if (!list.length) {
    wrap.innerHTML=`<div class="empty">
      <div class="empty-icon">◉</div>
      <div class="empty-txt">${entries.length?t('emptyNoResults'):t('emptyNoEntries')}</div>
      <div class="empty-sub">${entries.length?'':t('emptyStartHint')}</div>
    </div>`; return;
  }

  const scores = await Promise.all(list.map(e=>getScore(e.password)));
  const dotClass = s => s>=3?'strong':s>=2?'medium':'weak';

  wrap.innerHTML = list.map((e,i) => `
    <div class="pw-card" style="animation-delay:${i*15}ms">
      <div class="pw-icon">${e.site.slice(0,2).toUpperCase()}</div>
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
        ${e.totp?`<button class="act-btn" onclick="showTOTP('${e.id}')" title="2FA">▲</button>`:''}
        <button class="act-btn" onclick="copyPw('${e.id}')" title="Kopyala">⎘</button>
        <button class="act-btn" onclick="revealPw('${e.id}')" title="Göster">●</button>
        <button class="act-btn" onclick="openAddModal('${e.id}')" title="Düzenle">✎</button>
        <button class="act-btn del" onclick="delEntry('${e.id}')" title="Sil">✕</button>
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
function openAddModal(id=null) {
  editId=id;
  document.getElementById('addModalTitle').textContent = id ? t('modalEditEntry') : t('modalNewEntry');
  if(id) {
    const e=entries.find(x=>x.id===id);
    document.getElementById('f-site').value=e.site;
    document.getElementById('f-category').value=e.category||'Diğer';
    document.getElementById('f-user').value=e.username;
    document.getElementById('f-pw').value=e.password;
    document.getElementById('f-note').value=e.note||'';
    document.getElementById('f-url').value=e.url||'';
    document.getElementById('f-2fa-toggle').checked=!!e.totp;
    document.getElementById('f-totp').value=e.totp||'';
    document.getElementById('f-fav').checked=!!e.fav;
    document.getElementById('totp-section').style.display=e.totp?'block':'none';
    onPwInput();
  } else {
    ['f-site','f-user','f-pw','f-note','f-url','f-totp'].forEach(i=>document.getElementById(i).value='');
    document.getElementById('f-category').value='Diğer';
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
    password: pw,
    note:     document.getElementById('f-note').value.trim(),
    url:      document.getElementById('f-url').value.trim(),
    totp:     document.getElementById('f-2fa-toggle').checked ? document.getElementById('f-totp').value.trim() : '',
    fav:      document.getElementById('f-fav').checked,
    updated:  Date.now(),
  };
  if(editId){const i=entries.findIndex(x=>x.id===editId);entries[i]=entry;}
  else entries.unshift({...entry,created:Date.now()});
  await persist(); closeModal('addOverlay'); renderList();
  toast(editId?t('toastUpdated'):t('toastSaved'));
}

async function delEntry(id) {
  entries=entries.filter(x=>x.id!==id);
  await persist(); renderList(); toast(t('toastDeleted'));
}

// ── ACTIONS ───────────────────────────────────────────────────────
async function copyPw(id) {
  const pw = entries.find(x=>x.id===id)?.password;
  if (!pw) return;
  await copySecure(pw, t('toastPwCopied'));
}

function revealPw(id) {
  const el=document.getElementById('dot-'+id); if(!el)return;
  const e=entries.find(x=>x.id===id);
  if(el.classList.contains('pw-reveal')){
    el.textContent='••••••'; el.classList.remove('pw-reveal'); clearTimeout(revealT[id]);
  } else {
    el.textContent=e.password; el.classList.add('pw-reveal');
    clearTimeout(revealT[id]);
    revealT[id]=setTimeout(()=>{el.textContent='••••••';el.classList.remove('pw-reveal');},5000);
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
    const c=await getTOTP(e.totp);
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
  if(!newPw||newPw.length<4){toast(t('toastMinChars'));return;}
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
  navigator.clipboard.writeText(key).then(()=>toast(t('toastRecoveryCopied')));
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
  const scores=await Promise.all(entries.map(e=>getScore(e.password)));
  const weak=entries.filter((_,i)=>scores[i]<=1);
  const medium=entries.filter((_,i)=>scores[i]===2);
  const strong=entries.filter((_,i)=>scores[i]>=3);
  const pwMap={};
  entries.forEach(e=>{(pwMap[e.password]=pwMap[e.password]||[]).push(e);});
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
    const c=await checkPwned(e.password);
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
      breached.forEach(e=>{html+=`<div class="breach-row"><div class="h-dot red"></div><div style="flex:1"><div class="breach-site">${esc(e.site)}</div><div class="breach-user">${esc(e.username)}</div></div><div class="breach-count">${e.count.toLocaleString(document.documentElement.lang==='en'?'en-US':'tr-TR')}${t('hibpBreachedCount')}</div><button class="act-btn" style="opacity:1" onclick="openAddModal('${e.id}')" title="${t('hibpChangeBtn')}">✎</button></div>`;});
    }
    if(errors.length) html+=`<div style="font-family:var(--mono);font-size:11px;color:var(--mu);margin-top:8px">⚠ ${errors.length} ${t('hibpCheckFailed')}</div>`;
  }
  html+='</div>';
  el.innerHTML=html;
  btn.disabled=false; btn.textContent=t('healthScanBtnAgain');
  toast(breached.length?`${breached.length} ${t('hibpFoundToast')}`:t('hibpCleanToast'));
}

// ── AIR-GAP SYNC ──────────────────────────────────────────────────
async function openSyncWindow() {
  if (!master) { toast(t('toastLoginFirst')); return; }
  toast(t('toastSyncOpening'));
  try {
    const enc = await api.loadData();
    if (!enc) { toast(t('toastNoDataToSync')); return; }
    await api.openSyncWindow(master, enc);
  } catch(e) {
    toast(t('toastSyncFailed') + e.message);
  }
}

// ── IMPORT / EXPORT ───────────────────────────────────────────────
async function exportJSON() {
  const c=JSON.stringify(entries,null,2);
  await api.exportFile({content:c,defaultName:'fuin-yedek.json',filters:[{name:'JSON',extensions:['json']}]});
  toast(t('toastJsonExported'));
}
async function exportCSV() {
  const rows=['site,category,username,password,url,note'];
  entries.forEach(e=>rows.push([e.site,e.category||'Diğer',e.username,e.password,e.url||'',e.note||''].map(v=>`"${(v||'').replace(/"/g,'""')}"`).join(',')));
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

    // Bitwarden JSON formatı: { encrypted: false, items: [...] }
    if (imp.items) imp = imp.items;
    // 1Password JSON: array of objects with "fields"
    // Fuin/Kekkai: doğrudan array

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
      return { ...e, id: e.id || crypto.randomUUID() };
    });

    const newEntries = normalized.filter(x =>
      x.site && x.password &&
      !entries.find(e => e.site === x.site && e.username === x.username)
    );
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
    for (const line of lines.slice(1)) {
      if (!line.trim()) continue;
      const cols  = parseCSVLine(line);
      const entry = csvRowToEntry(cols, colMap);
      if (!entry) continue;
      if (entries.find(e => e.site === entry.site && e.username === entry.username)) continue;
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
  const c='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_';
  const cLen = c.length; // 74
  // Modulo bias önlemi: cLen'in tam katına kadar olan değerleri kabul et
  const limit = 256 - (256 % cLen);
  let pw = '';
  while (pw.length < 20) {
    const rnd = crypto.getRandomValues(new Uint8Array(40));
    for (let i = 0; i < rnd.length && pw.length < 20; i++) {
      if (rnd[i] < limit) pw += c[rnd[i] % cLen];
    }
  }
  const inp=document.getElementById('f-pw');
  inp.value=pw; inp.type='text'; onPwInput();
  toast(t('toastStrongPwGenerated'));
  setTimeout(()=>{inp.type='password';},2000);
}

function esc(s){return(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

let toastT;
function toast(msg){
  clearTimeout(toastT);
  document.getElementById('toastMsg').textContent=msg;
  document.getElementById('toast').classList.add('show');
  toastT=setTimeout(()=>document.getElementById('toast').classList.remove('show'),3000);
}

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeModal('addOverlay');closeTOTP();closeForgot();closeHardReset();}
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
async function checkForUpdates() {
  const btn = document.getElementById('updateBtn');
  const msg = document.getElementById('updateMsg');
  if (!btn || !msg) return;
  btn.disabled = true;
  btn.textContent = '...';
  msg.textContent = '';
  
  try {
    // TODO: GitHub'da projeyi yayınladıktan sonra 'kadir/fuin' kısmını kendi GitHub kullanıcı ve repo adınla değiştir.
    // Örnek: 'https://api.github.com/repos/KULLANICI_ADI/REPO_ADI/releases/latest'
    const res = await fetch('https://api.github.com/repos/kadir/fuin/releases/latest');
    if (!res.ok) throw new Error('API error');
    const data = await res.json();
    const latestVersion = data.tag_name; // örn: "v1.1.0"
    const currentVersion = 'v1.0.0';
    
    // Sürüm kontrolü (Eğer GitHub'daki sürüm v1.0.0'dan farklıysa güncelleme uyarısı ver)
    if (latestVersion && latestVersion !== currentVersion && latestVersion !== 'v' + currentVersion) {
      msg.innerHTML = `<span style="color:var(--green)">Yeni sürüm mevcut: ${latestVersion}</span> <a href="#" onclick="window.kekkai?.openUrl('${data.html_url}')" style="color:var(--text);text-decoration:underline;margin-left:8px;cursor:pointer">İndir</a>`;
    } else {
      msg.textContent = 'En güncel sürümü kullanıyorsunuz.';
    }
  } catch (err) {
    msg.textContent = 'Kontrol edilemedi. İnternet bağlantısını kontrol edin veya depo adresini ayarlayın.';
  } finally {
    btn.disabled = false;
    btn.textContent = t('sysUpdateBtn');
  }
}
