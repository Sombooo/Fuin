'use strict';

const { powerMonitor } = require('electron');

let idlePollTimer = null;
let warningActive = false;
let idleLockSeconds = 5 * 60; // 5 min default
const IDLE_WARNING_SECONDS = 30; // 30s before lock

let _getIsUnlocked = () => false;
let _onForceLock = () => {};
let _onWarning = () => {};
let _onWarningCancel = () => {};

/**
 * Initialize power monitor listeners and callbacks.
 * @param {Object} options
 * @param {Function} options.getIsUnlocked
 * @param {Function} options.onForceLock
 * @param {Function} options.onWarning
 * @param {Function} options.onWarningCancel
 */
function initPowerMonitor({ getIsUnlocked, onForceLock, onWarning, onWarningCancel } = {}) {
  if (getIsUnlocked) _getIsUnlocked = getIsUnlocked;
  if (onForceLock) _onForceLock = onForceLock;
  if (onWarning) _onWarning = onWarning;
  if (onWarningCancel) _onWarningCancel = onWarningCancel;

  if (powerMonitor) {
    powerMonitor.on('lock-screen', () => {
      if (_getIsUnlocked()) _onForceLock('lock-screen');
    });
    powerMonitor.on('suspend', () => {
      if (_getIsUnlocked()) _onForceLock('suspend');
    });
  }
}

function startIdleWatcher() {
  if (idlePollTimer) return;
  idlePollTimer = setInterval(() => {
    if (!_getIsUnlocked()) return;
    if (!powerMonitor || typeof powerMonitor.getSystemIdleTime !== 'function') return;

    const idleSec = powerMonitor.getSystemIdleTime();
    const remaining = idleLockSeconds - idleSec;

    if (idleLockSeconds === 0) return; // Asla kilitlenmesin secenegi

    if (remaining <= 0) {
      _onForceLock('idle');
    } else if (remaining <= IDLE_WARNING_SECONDS) {
      warningActive = true;
      _onWarning(Math.ceil(remaining));
    } else if (warningActive) {
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
  IDLE_WARNING_SECONDS
};
