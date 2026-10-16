'use strict';

const path = require('path');

let tray = null;

function initTray(options = {}) {
  if (tray) return tray;
  const {
    Menu,
    Tray,
    nativeImage,
    baseDir = path.join(__dirname, '..'),
    getMainWindow = () => null,
    onLock = () => {},
    onQuit = () => {}
  } = options;

  if (!Tray || !Menu || !nativeImage) return null;

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

  tray.setToolTip('Fuin');

  const contextMenu = Menu.buildFromTemplate([
    {
      label: 'Göster',
      click: () => {
        const win = getMainWindow();
        if (win) win.show();
      }
    },
    {
      label: 'Kilitle',
      click: () => onLock('tray')
    },
    { type: 'separator' },
    {
      label: 'Çıkış',
      click: () => onQuit()
    }
  ]);

  if (process.platform === 'darwin') {
    tray.on('right-click', () => { tray.popUpContextMenu(contextMenu); });
  } else {
    tray.setContextMenu(contextMenu);
  }

  tray.on('click', () => {
    const win = getMainWindow();
    if (win) {
      if (win.isVisible()) win.hide();
      else win.show();
    }
  });

  return tray;
}

function getTray() {
  return tray;
}

function destroyTray() {
  if (tray) {
    try { tray.destroy(); } catch {}
    tray = null;
  }
}

module.exports = {
  initTray,
  getTray,
  destroyTray
};
