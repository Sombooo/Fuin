// ═══════════════════════════════════════════════════════════════════
// FUIN WHAT'S NEW CONTROLLER
// renderer/modules/whatsNewController.js
// 100% Offline, distraction-free changelog modal and release navigator.
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  let currentSelectedVersion = null;

  function getLang() {
    if (typeof document !== 'undefined' && document.documentElement && document.documentElement.lang) {
      return document.documentElement.lang.toLowerCase();
    }
    if (typeof localStorage !== 'undefined') {
      return (localStorage.getItem('fuin-lang') || 'tr').toLowerCase();
    }
    return 'tr';
  }

  function getIconSvg(iconName) {
    const stroke = 'currentColor';
    const common = 'width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="' + stroke + '" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
    switch (iconName) {
      case 'scroll':
        return '<svg ' + common + '><path d="M19 20H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2z"/><polyline points="16 2 16 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="17" x2="13" y2="17"/></svg>';
      case 'download-cloud':
        return '<svg ' + common + '><polyline points="8 17 12 21 16 17"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.88 18.09A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.29"/></svg>';
      case 'puzzle':
        return '<svg ' + common + '><path d="M20 16a2 2 0 0 0-2-2h-1V9a2 2 0 0 0-2-2h-3V6a2 2 0 1 0-4 0v1H5a2 2 0 0 0-2 2v5h1a2 2 0 1 1 0 4H3v2a2 2 0 0 0 2 2h5v-1a2 2 0 1 1 4 0v1h4a2 2 0 0 0 2-2v-3h1a2 2 0 0 0 2-2z"/></svg>';
      case 'sliders':
        return '<svg ' + common + '><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>';
      case 'shield-check':
      case 'shield':
        return '<svg ' + common + '><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>';
      case 'smartphone':
        return '<svg ' + common + '><rect x="5" y="2" width="14" height="20" rx="2" ry="2"/><line x1="12" y1="18" x2="12.01" y2="18"/></svg>';
      case 'package':
        return '<svg ' + common + '><line x1="16.5" y1="9.4" x2="7.5" y2="4.21"/><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>';
      case 'database':
        return '<svg ' + common + '><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/></svg>';
      case 'key':
        return '<svg ' + common + '><circle cx="7.5" cy="15.5" r="4.5"/><path d="M21 2l-9.6 9.6"/><path d="M15.5 7.5l3 3L22 7l-2-2"/></svg>';
      case 'wifi':
        return '<svg ' + common + '><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>';
      case 'lock':
      default:
        return '<svg ' + common + '><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>';
    }
  }

  function getBadgeColorStyles(badge) {
    switch (badge) {
      case 'license':
        return 'background:rgba(200,128,64,0.14); color:var(--amber); border:1px solid rgba(200,128,64,0.3);';
      case 'update':
      case 'mobile':
        return 'background:rgba(90,154,110,0.14); color:var(--ac); border:1px solid rgba(90,154,110,0.3);';
      case 'extension':
      case 'ui':
        return 'background:rgba(120,140,180,0.14); color:#9ab0d4; border:1px solid rgba(120,140,180,0.25);';
      case 'storage':
      case 'crypto':
      case 'sync':
      case 'security':
      default:
        return 'background:rgba(90,154,110,0.14); color:var(--ac); border:1px solid rgba(90,154,110,0.3);';
    }
  }

  function renderTabs(entries, selectedVer) {
    const tabsContainer = document.getElementById('whatsNewVersionTabs');
    if (!tabsContainer) return;

    tabsContainer.innerHTML = '';
    const isEn = getLang() === 'en';

    entries.forEach(entry => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'whatsnew-tab' + (entry.version === selectedVer ? ' active' : '');
      const latestSuffix = typeof window.t === 'function' ? window.t('whatsNewLatestTab') : (isEn ? ' (Latest)' : '');
      btn.textContent = entry.tag + (entry.isCurrent ? latestSuffix : '');
      btn.addEventListener('click', () => {
        selectVersion(entry.version);
      });
      tabsContainer.appendChild(btn);
    });
  }

  function renderContent(entry) {
    const headerEl = document.getElementById('whatsNewHeader');
    const highlightsEl = document.getElementById('whatsNewHighlights');
    if (!headerEl || !highlightsEl) return;

    const isEn = getLang() === 'en';
    const title = isEn ? (entry.titleEn || entry.title) : entry.title;
    const date = isEn ? (entry.dateEn || entry.date) : entry.date;
    const summary = isEn ? (entry.summaryEn || entry.summary) : entry.summary;
    const latestBadge = typeof window.t === 'function' ? window.t('whatsNewLatestBadge') : (isEn ? 'LATEST' : '');

    headerEl.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:8px;">
          <span class="whatsnew-badge-pill" style="font-family:var(--mono);font-size:11px;font-weight:700;color:var(--ac);background:rgba(90,154,110,0.14);padding:3px 8px;border-radius:4px;border:1px solid rgba(90,154,110,0.3);letter-spacing:0.5px;">${entry.tag}</span>
          ${entry.isCurrent ? `<span style="font-family:var(--mono);font-size:10px;font-weight:600;color:var(--amber);background:rgba(200,128,64,0.14);padding:2px 7px;border-radius:3px;border:1px solid rgba(200,128,64,0.3);letter-spacing:0.5px;">${latestBadge}</span>` : ''}
        </div>
        <span style="font-family:var(--mono);font-size:11px;color:var(--mu);">${date}</span>
      </div>
      <div style="font-size:13.5px;font-weight:600;color:var(--text);margin-bottom:6px;line-height:1.45;">${title}</div>
      <div style="font-size:12px;color:var(--mu);line-height:1.6;">${summary}</div>
    `;

    highlightsEl.innerHTML = '';
    entry.highlights.forEach(item => {
      const card = document.createElement('div');
      card.className = 'whatsnew-card';

      const itemTitle = isEn ? (item.titleEn || item.title) : item.title;
      const itemDesc = isEn ? (item.descEn || item.desc) : item.desc;
      const badgeText = isEn ? (item.badgeTextEn || item.badgeText) : item.badgeText;
      const badgeStyle = getBadgeColorStyles(item.badge);
      const iconHtml = getIconSvg(item.icon);

      card.innerHTML = `
        <div class="whatsnew-icon-box">
          ${iconHtml}
        </div>
        <div style="flex:1;min-width:0;">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;flex-wrap:wrap;">
            <span class="whatsnew-badge" style="${badgeStyle}">${badgeText}</span>
            <span style="font-size:13px;font-weight:600;color:var(--text);">${itemTitle}</span>
          </div>
          <div style="font-size:12px;color:var(--mu);line-height:1.5;">${itemDesc}</div>
        </div>
      `;
      highlightsEl.appendChild(card);
    });
  }

  function selectVersion(ver) {
    const entries = window.FuinChangelog?.CHANGELOG_ENTRIES || [];
    const entry = window.FuinChangelog?.getEntryByVersion(ver) || entries[0];
    if (!entry) return;

    currentSelectedVersion = entry.version;
    renderTabs(entries, entry.version);
    renderContent(entry);

    const bodyEl = document.querySelector('.whatsnew-body') || document.querySelector('#whatsNewOverlay .modal-body');
    if (bodyEl) bodyEl.scrollTop = 0;
  }

  function openModal(ver) {
    const overlay = document.getElementById('whatsNewOverlay');
    if (!overlay) return;

    const entries = window.FuinChangelog?.CHANGELOG_ENTRIES || [];
    const targetVer = ver || (entries[0] ? entries[0].version : '1.0.0-beta.8');
    selectVersion(targetVer);

    overlay.classList.add('open');
  }

  function onLanguageChanged() {
    const entries = window.FuinChangelog?.CHANGELOG_ENTRIES || [];
    const targetVer = currentSelectedVersion || (entries[0] ? entries[0].version : '1.0.0-beta.8');
    renderTabs(entries, targetVer);
    const entry = window.FuinChangelog?.getEntryByVersion(targetVer) || entries[0];
    if (entry) renderContent(entry);
  }

  function closeModal() {
    const overlay = document.getElementById('whatsNewOverlay');
    if (overlay) {
      overlay.classList.remove('open');
    }
  }

  function markSeen(ver) {
    const entries = window.FuinChangelog?.CHANGELOG_ENTRIES || [];
    const target = ver || (entries[0] ? entries[0].version : '1.0.0-beta.8');
    localStorage.setItem('fuin_last_seen_changelog', target);
  }

  function checkOnUnlock(currentAppVersion) {
    const ver = String(currentAppVersion || '1.0.0-beta.8').trim().replace(/^v/i, '');
    const lastSeen = localStorage.getItem('fuin_last_seen_changelog');

    // If never seen or newer version exists, show changelog
    if (!lastSeen || (window.FuinUpdateManager && window.FuinUpdateManager.isNewerVersion(ver, lastSeen))) {
      setTimeout(() => {
        openModal(ver);
      }, 500);
    }
  }

  function init() {
    // Button in Settings
    const openBtn = document.getElementById('btnOpenWhatsNew');
    if (openBtn) {
      openBtn.addEventListener('click', () => {
        openModal();
      });
    }

    // Modal close button
    const closeBtn = document.getElementById('btnCloseWhatsNew');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        closeModal();
      });
    }

    // Modal dismiss / "Got It" button
    const dismissBtn = document.getElementById('btnDismissWhatsNew');
    if (dismissBtn) {
      dismissBtn.addEventListener('click', () => {
        const entries = window.FuinChangelog?.CHANGELOG_ENTRIES || [];
        const latest = entries[0] ? entries[0].version : '1.0.0-beta.8';
        markSeen(latest);
        closeModal();
      });
    }

    // Background overlay click
    const overlay = document.getElementById('whatsNewOverlay');
    if (overlay) {
      overlay.addEventListener('mousedown', (e) => {
        if (e.target.id === 'whatsNewOverlay') {
          closeModal();
        }
      });
    }
  }

  window.FuinWhatsNewController = {
    init,
    openModal,
    closeModal,
    markSeen,
    checkOnUnlock,
    selectVersion,
    onLanguageChanged
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinWhatsNewController;
  }
})(typeof window !== 'undefined' ? window : globalThis);
