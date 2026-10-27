'use strict';

const { powerMonitor } = require('electron');

let idlePollTimer = null;
let warningActive = false;
let idleLockSeconds = 5 * 60; // 5 min default
const IDLE_WARNING_SECONDS = 30; // 30s before lock
let lastActivityTime = Date.now();

let _getIsUnlocked = () => false;
let _onForceLock = () => {};
let _onWarning = () => {};
let _onWarningCancel = () => {};
let _getMainWindow = () => null;

/**
 * Initialize power monitor listeners and callbacks.
 * @param {Object} options
 * @param {Function} options.getIsUnlocked
 * @param {Function} options.onForceLock
 * @param {Function} options.onWarning
 * @param {Function} options.onWarningCancel
 * @param {Function} options.getMainWindow
 */
function initPowerMonitor({ getIsUnlocked, onForceLock, onWarning, onWarningCancel, getMainWindow } = {}) {
  if (getIsUnlocked) _getIsUnlocked = getIsUnlocked;
  if (onForceLock) _onForceLock = onForceLock;
  if (onWarning) _onWarning = onWarning;
  if (onWarningCancel) _onWarningCancel = onWarningCancel;
  if (getMainWindow) _getMainWindow = getMainWindow;

  if (powerMonitor) {
    powerMonitor.on('lock-screen', () => {
      if (_getIsUnlocked()) _onForceLock('lock-screen');
    });
    powerMonitor.on('suspend', () => {
      if (_getIsUnlocked()) _onForceLock('suspend');
    });
  }
}

function recordActivity() {
  lastActivityTime = Date.now();
  if (warningActive) {
    warningActive = false;
    _onWarningCancel();
  }
}

function startIdleWatcher() {
  if (idlePollTimer) return;
  lastActivityTime = Date.now();
  idlePollTimer = setInterval(() => {
    if (!_getIsUnlocked()) return;
    if (idleLockSeconds === 0) return; // Asla kilitlenmesin secenegi

    const win = _getMainWindow ? _getMainWindow() : null;
    const isWindowActive = Boolean(
      win &&
      (typeof win.isDestroyed !== 'function' || !win.isDestroyed()) &&
      (typeof win.isVisible !== 'function' || win.isVisible()) &&
      (typeof win.isFocused !== 'function' || win.isFocused())
    );

    if (isWindowActive) {
      lastActivityTime = Date.now();
    }

    const now = Date.now();
    const systemIdleSec = (powerMonitor && typeof powerMonitor.getSystemIdleTime === 'function')
      ? powerMonitor.getSystemIdleTime()
      : 0;

    // Arka planda kalma süresi (uygulama odakta değilken geçen saniye):
    const bgInactiveSec = isWindowActive ? 0 : Math.floor((now - lastActivityTime) / 1000);

    // Kilitlenme için en etkili süre: Ya kullanıcı bilgisayarı terk etmiştir (systemIdleSec),
    // ya da Fuin arka planda kullanılmadan bırakılmıştır (bgInactiveSec):
    const effectiveIdleSec = Math.max(systemIdleSec, bgInactiveSec);
    const remaining = idleLockSeconds - effectiveIdleSec;

    const warningThreshold = idleLockSeconds <= 60 ? 10 : IDLE_WARNING_SECONDS;

    if (remaining <= 0) {
      _onForceLock('idle');
    } else if (remaining <= warningThreshold && isWindowActive) {
      warningActive = true;
      _onWarning(Math.ceil(remaining));
    } else if (warningActive && (!isWindowActive || remaining > warningThreshold)) {
      warningActive = false;
      _onWarningCancel();
    }
  }, 1000);
}

function stopIdleWatcher() {
  if (idlePollTimer) {
    clearInterval(idlePollTimer);
    idlePollTimer = null;
  }
  warningActive = false;
}

function setIdleLockSeconds(seconds) {
  const val = parseInt(seconds, 10);
  if (isNaN(val) || val < 0) return;
  idleLockSeconds = Math.min(Math.max(val, 0), 86400); // Max 24 hours
  recordActivity();
}

function getIdleLockSeconds() {
  return idleLockSeconds;
}

module.exports = {
  initPowerMonitor,
  startIdleWatcher,
  stopIdleWatcher,
  setIdleLockSeconds,
  getIdleLockSeconds,
  recordActivity,
  IDLE_WARNING_SECONDS
};
