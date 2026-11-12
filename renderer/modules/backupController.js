(function () {
  'use strict';

  function formatBackupReason(reason, t) {
    const tr = typeof t === 'function' ? t : (k) => k;
    if (reason === 'manual' || reason === 'manual-snapshot') return tr('backupReasonManual');
    if (reason === 'pre-restore') return tr('backupReasonPreRestore');
    if (
      reason === 'pre-reset' ||
      reason === 'recovery-regen' ||
      reason === 'recovery-rotation' ||
      reason === 'recovery-save'
    ) {
      return tr('backupReasonRecovery');
    }
    return tr('backupReasonAuto');
  }

  function extractSnapshotsFromResponse(res) {
    if (!res) return [];
    if (Array.isArray(res.backups)) return res.backups;
    if (Array.isArray(res.snapshots)) return res.snapshots;
    return [];
  }

  function renderBackupHistoryItems({
    listEl,
    healBanner,
    res,
    lang,
    t,
    esc,
    onRestoreSnapshot,
  }) {
    if (!listEl) return;
    const tr = typeof t === 'function' ? t : (k) => k;
    const escape = typeof esc === 'function' ? esc : (s) => String(s || '');
    const snaps = extractSnapshotsFromResponse(res);
    const locale = lang === 'en' ? 'en-US' : 'tr-TR';

    if (healBanner) {
      if (res && res.lastAutoHeal && res.lastAutoHeal.timestamp) {
        const d = new Date(res.lastAutoHeal.timestamp).toLocaleString(locale);
        healBanner.textContent = `${tr('backupAutoHealNotice')} (${d})`;
        healBanner.style.display = 'block';
      } else {
        healBanner.style.display = 'none';
      }
    }

    if (!snaps.length) {
      listEl.innerHTML = `<div style="font-family:var(--mono);font-size:12px;color:var(--mu);text-align:center;padding:20px 16px;">${escape(tr('backupHistoryEmpty'))}</div>`;
      return;
    }

    listEl.innerHTML = snaps
      .map((snap) => {
        const fname = snap.file || snap.filename || '';
        const d = new Date(snap.timestamp).toLocaleString(locale);
        const kb = Math.max(1, Math.round((snap.size || 0) / 1024));
        const hashShort = (snap.fullSha256 || snap.sha256 || '').slice(0, 10) || '—';
        const reasonLabel = formatBackupReason(snap.reason, tr);
        const isVerified = snap.verified !== false && Boolean(snap.sha256 || snap.fullSha256);
        const badgeLabel = isVerified ? tr('backupVerifiedBadge') : tr('backupCorruptBadge');
        return `
        <div class="backup-history-item">
          <div style="display:flex;flex-direction:column;gap:4px;overflow:hidden;flex:1;">
            <div style="font-size:12px;font-weight:600;color:var(--text);display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
              <span>${escape(d)}</span>
              <span style="font-family:var(--mono);font-size:10px;padding:2px 8px;border-radius:4px;background:rgba(90,154,110,0.14);color:var(--ac2);">${escape(reasonLabel)}</span>
            </div>
            <div style="font-family:var(--mono);font-size:11px;color:var(--mu);">
              ${kb} KB · SHA-256: ${escape(hashShort)}… · ${escape(badgeLabel)}
            </div>
          </div>
          <button type="button" class="btn-io" data-restore-snap="${escape(fname)}" style="font-size:11px;">
            ${escape(tr('backupRestoreBtn'))}
          </button>
        </div>
      `;
      })
      .join('');

    if (typeof onRestoreSnapshot === 'function') {
      listEl.querySelectorAll('[data-restore-snap]').forEach((btn) => {
        btn.addEventListener('click', () => {
          const fname = btn.getAttribute('data-restore-snap');
          if (fname) onRestoreSnapshot(fname);
        });
      });
    }
  }

  function extractCiphertextFromFuinFile(raw) {
    const trimmed = String(raw || '').trim();
    let ciphertext = '';
    if (trimmed.startsWith('{') || trimmed.startsWith('"')) {
      const parsedJson = JSON.parse(trimmed);
      if (typeof parsedJson === 'string') {
        ciphertext = parsedJson;
      } else if (parsedJson && typeof parsedJson.ciphertext === 'string') {
        ciphertext = parsedJson.ciphertext;
      } else if (parsedJson && typeof parsedJson.data === 'string' && !parsedJson.iv) {
        ciphertext = parsedJson.data;
      }
    } else {
      ciphertext = trimmed;
    }
    if (typeof ciphertext !== 'string' || ciphertext.length < 80) {
      throw new Error('invalid-format');
    }
    return ciphertext;
  }

  function buildEncryptedBackupEnvelope(ciphertext) {
    return JSON.stringify(
      {
        format: 'fuin-encrypted-backup',
        version: 1,
        exportedAt: Date.now(),
        ciphertext,
      },
      null,
      2
    );
  }

  function buildPlaintextCsv(exportEntries) {
    const rows = ['site,category,username,password,url,note'];
    (exportEntries || []).forEach((e) => {
      rows.push(
        [e.site, e.category || 'Diğer', e.username, e.password, e.url || '', e.note || '']
          .map((v) => `"${(v || '').replace(/"/g, '""')}"`)
          .join(',')
      );
    });
    return rows.join('\n');
  }

  const FuinBackupController = {
    formatBackupReason,
    extractSnapshotsFromResponse,
    renderBackupHistoryItems,
    extractCiphertextFromFuinFile,
    buildEncryptedBackupEnvelope,
    buildPlaintextCsv,
  };

  if (typeof window !== 'undefined') {
    window.FuinBackupController = FuinBackupController;
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = FuinBackupController;
  }
})();
