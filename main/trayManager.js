'use strict';

const path = require('path');
const fs = require('fs');

let tray = null;
let currentOptions = null;
let currentLang = 'tr';
let currentDarwinContextMenu = null;

const TRAY_I18N = {
  tr: {
    show: 'Göster',
    lock: 'Kilitle',
    quit: 'Çıkış',
    tooltip: 'Fuin',
    vaultLockedTitle: 'Kasa Kilitlendi',
    vaultLockedBody: 'Fuin kasası güvenlik amacıyla kilitlendi.',
    clipboardClearedTitle: 'Pano Temizlendi',
    clipboardClearedBody: 'Hassas parola panodan güvenli şekilde silindi.'
  },
  en: {
    show: 'Show',
    lock: 'Lock',
    quit: 'Quit',
    tooltip: 'Fuin',
    vaultLockedTitle: 'Vault Locked',
    vaultLockedBody: 'Fuin vault has been locked for security.',
    clipboardClearedTitle: 'Clipboard Cleared',
    clipboardClearedBody: 'Sensitive password securely cleared from clipboard.'
  }
};

function buildContextMenu() {
  if (!currentOptions) return null;
  const { Menu, getMainWindow = () => null, onLock = () => {}, onQuit = () => {} } = currentOptions;
  const t = TRAY_I18N[currentLang] || TRAY_I18N.tr;

  return Menu.buildFromTemplate([
    {
      label: t.show,
      click: () => {
        const win = getMainWindow();
        if (win) {
          if (typeof win.isMinimized === 'function' && win.isMinimized()) win.restore();
          win.show();
          if (typeof win.focus === 'function') win.focus();
        }
      }
    },
    {
      label: t.lock,
      click: () => onLock('tray')
    },
    { type: 'separator' },
    {
      label: t.quit,
      click: () => onQuit()
    }
  ]);
}

function initTray(options = {}) {
  if (tray) return tray;
  const {
    Menu,
    Tray,
    nativeImage,
    baseDir = path.join(__dirname, '..'),
    getMainWindow = () => null,
    lang = 'tr'
  } = options;

  if (!Tray || !Menu || !nativeImage) return null;

  currentOptions = options;
  currentLang = (lang === 'en' ? 'en' : 'tr');

  const iconPath = path.join(baseDir, 'assets', 'icon.png');
  let icon = nativeImage.createFromPath(iconPath);
  if (process.platform === 'darwin' && icon && typeof icon.resize === 'function') {
    icon = icon.resize({ width: 16, height: 16 });
  }

  try {
    tray = new Tray(icon);
  } catch (e) {
    return null;
  }

  const t = TRAY_I18N[currentLang] || TRAY_I18N.tr;
  tray.setToolTip(t.tooltip);

  const contextMenu = buildContextMenu();
  if (process.platform === 'darwin') {
    currentDarwinContextMenu = contextMenu;
    tray.on('right-click', () => {
      if (currentDarwinContextMenu) tray.popUpContextMenu(currentDarwinContextMenu);
    });
  } else if (contextMenu) {
    tray.setContextMenu(contextMenu);
  }

  tray.on('click', () => {
    const win = getMainWindow();
    if (win) {
      if (typeof win.isVisible === 'function' && win.isVisible()) win.hide();
      else {
        if (typeof win.isMinimized === 'function' && win.isMinimized()) win.restore();
        win.show();
        if (typeof win.focus === 'function') win.focus();
      }
    }
  });

  return tray;
}

function updateLanguage(lang) {
  currentLang = (lang === 'en' ? 'en' : 'tr');
  if (!tray || !currentOptions) return;

  const t = TRAY_I18N[currentLang] || TRAY_I18N.tr;
  try { tray.setToolTip(t.tooltip); } catch {}

  const contextMenu = buildContextMenu();
  if (process.platform === 'darwin') {
    currentDarwinContextMenu = contextMenu;
  } else if (contextMenu) {
    try { tray.setContextMenu(contextMenu); } catch {}
  }
}

function getLanguage() {
  return currentLang;
}

function showNotification(key, customOptions = {}) {
  try {
    const Notif = currentOptions?.Notification || (function() {
      try {
        const electron = require('electron');
        return electron.Notification;
      } catch {
        return null;
      }
    })();

    if (!Notif) return false;
    if (typeof Notif.isSupported === 'function' && !Notif.isSupported()) return false;

    const t = TRAY_I18N[currentLang] || TRAY_I18N.tr;
    let title = customOptions.title;
    let body = customOptions.body;
    if (!title && key) {
      title = t[`${key}Title`] || customOptions.fallbackTitle || 'Fuin';
      body = t[`${key}Body`] || customOptions.fallbackBody || '';
    }
    if (!title) return false;

    const baseDir = currentOptions?.baseDir || path.join(__dirname, '..');
    const iconPath = path.join(baseDir, 'assets', 'icon.png');
    const n = new Notif({
      title,
      body,
      icon: fs.existsSync(iconPath) ? iconPath : undefined,
      silent: customOptions.silent !== undefined ? customOptions.silent : false
    });
    n.show();
    return true;
  } catch {
    return false;
  }
}

function getTray() {
  return tray;
}

function destroyTray() {
  if (tray) {
    try { tray.destroy(); } catch {}
    tray = null;
  }
  currentOptions = null;
  currentDarwinContextMenu = null;
}

module.exports = {
  initTray,
  getTray,
  destroyTray,
  updateLanguage,
  getLanguage,
  showNotification,
  TRAY_I18N
};
