/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN CRYPTO SERVICE: totpEngine.js
 *
 * RFC 4648 Base32 Decoding & RFC 6238 Time-Based One-Time Password (TOTP) Engine
 * Dual-crypto architecture supporting Web Crypto API and Node.js native crypto.
 *
 * Conforms to:
 * - RFC 4648 Section 6: Base32 Encoding / Decoding
 * - RFC 6238: TOTP: Time-Based One-Time Password Algorithm
 * - RFC 4226: HOTP: An HMAC-Based One-Time Password Algorithm
 *
 * Universal Module Definition (UMD) for Browser, Node.js, and React Native.
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    var exports = factory();
    root.TotpEngine = exports;
    if (typeof root === 'object') {
      root.getTOTP = exports.getTOTP;
      root.b32dec = exports.b32dec;
      root.calculateTOTP = exports.calculateTOTP;
      root.generateTOTP = exports.generateTOTP;
      root.startTOTPTicker = exports.startTOTPTicker;
    }
  }
})(typeof globalThis !== 'undefined' ? globalThis : typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var RFC_BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  /**
   * Detects Node.js runtime environment with native crypto module.
   */
  function hasNodeCrypto() {
    try {
      return (
        typeof process !== 'undefined' &&
        Boolean(process.versions && process.versions.node) &&
        typeof require === 'function'
      );
    } catch (_) {
      return false;
    }
  }

  function getNodeCrypto() {
    if (!hasNodeCrypto()) return null;
    try {
      return require('crypto');
    } catch (_) {
      return null;
    }
  }

  /**
   * Retrieves Web Crypto Subtle API across browser/worker/global scopes.
   */
  function getWebCryptoSubtle() {
    if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.subtle) {
      return globalThis.crypto.subtle;
    }
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
      return window.crypto.subtle;
    }
    if (typeof self !== 'undefined' && self.crypto && self.crypto.subtle) {
      return self.crypto.subtle;
    }
    return null;
  }

  /**
   * Extracts raw Base32 secret from string, stripping whitespace or otpauth:// URIs.
   *
   * @param {string} input - Raw secret or otpauth:// URI
   * @returns {string} Sanitized Base32 secret string
   */
  function extractSecret(input) {
    if (typeof input !== 'string') {
      throw new TypeError('TOTP secret must be a string');
    }
    var str = input.trim();
    if (str.toLowerCase().indexOf('otpauth://') === 0) {
      try {
        var url = new URL(str);
        var sec = url.searchParams.get('secret');
        if (sec) str = sec;
      } catch (_) {
        var match = str.match(/[?&]secret=([A-Za-z2-7=]+)/i);
        if (match) str = match[1];
      }
    }
    return str;
  }

  /**
   * RFC 4648 Base32 Decoder.
   * Tolerant to whitespace, hyphens, lowercase characters, and padding '=' signs.
   *
   * @param {string} input - Base32 encoded string
   * @param {Object} [options]
   * @param {boolean} [options.loose=false] - If true, skips unrecognized characters instead of throwing
   * @returns {Uint8Array} Decoded byte array
   */
  function base32Decode(input, options) {
    if (typeof input !== 'string') {
      throw new TypeError('Base32 input must be a string');
    }
    options = options || {};
    var str = extractSecret(input);
    str = str.toUpperCase().replace(/[\s=-]/g, '');
    if (str.length === 0) return new Uint8Array(0);

    var bits = 0;
    var value = 0;
    var output = [];

    for (var i = 0; i < str.length; i++) {
      var char = str[i];
      var idx = RFC_BASE32_ALPHABET.indexOf(char);
      if (idx === -1) {
        if (options.loose) continue;
        throw new Error('Invalid Base32 character: "' + char + '" at position ' + i);
      }
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) {
        output.push((value >>> (bits - 8)) & 0xff);
        bits -= 8;
      }
    }

    return new Uint8Array(output);
  }

  /**
   * RFC 4648 Base32 Encoder.
   *
   * @param {Uint8Array|Array<number>} bytes - Bytes to encode
   * @param {boolean} [pad=true] - Whether to include '=' padding
   * @returns {string} Encoded Base32 string
   */
  function base32Encode(bytes, pad) {
    if (pad === undefined) pad = true;
    if (!bytes) return '';
    var buf = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (buf.length === 0) return '';

    var bits = 0;
    var value = 0;
    var output = '';

    for (var i = 0; i < buf.length; i++) {
      value = (value << 8) | buf[i];
      bits += 8;
      while (bits >= 5) {
        output += RFC_BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
        bits -= 5;
      }
    }

    if (bits > 0) {
      output += RFC_BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }

    if (pad) {
      while (output.length % 8 !== 0) {
        output += '=';
      }
    }

    return output;
  }

  /**
   * Converts 64-bit integer counter to 8-byte big-endian buffer.
   *
   * @param {number|BigInt} counter - Time-step counter
   * @returns {Uint8Array} 8-byte buffer
   */
  function counterToBuffer(counter) {
    var c = BigInt(counter);
    if (c < 0n) throw new RangeError('Counter value must be non-negative');
    var buf = new Uint8Array(8);
    for (var i = 7; i >= 0; i--) {
      buf[i] = Number((c >> BigInt(8 * (7 - i))) & 0xffn);
    }
    return buf;
  }

  /**
   * RFC 4226 Dynamic Truncation.
   *
   * @param {Uint8Array} hmacBytes - HMAC digest
   * @param {number} [digits=6] - Desired code length
   * @returns {string} Zero-padded code string
   */
  function truncate(hmacBytes, digits) {
    if (digits === undefined) digits = 6;
    var offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    var binary =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);
    var modulo = Math.pow(10, digits);
    var otp = binary % modulo;
    return String(otp).padStart(digits, '0');
  }

  /**
   * Normalizes timestamp input into epoch seconds.
   */
  function parseTimestampSec(timestamp, isMilliseconds) {
    if (typeof timestamp === 'number') {
      if (isMilliseconds || timestamp > 1e11) {
        return Math.floor(timestamp / 1000);
      }
      return Math.floor(timestamp);
    }
    if (timestamp instanceof Date) {
      return Math.floor(timestamp.getTime() / 1000);
    }
    return Math.floor(Date.now() / 1000);
  }

  /**
   * Computes HMAC using Node.js native crypto module.
   */
  function computeHMACNode(keyBytes, messageBytes, algorithm) {
    algorithm = algorithm || 'SHA-1';
    var nodeCrypto = getNodeCrypto();
    if (!nodeCrypto) {
      throw new Error('Node.js crypto is not available in current environment');
    }
    var algoMap = { 'SHA-1': 'sha1', 'SHA-256': 'sha256', 'SHA-512': 'sha512' };
    var algo = algoMap[algorithm.toUpperCase()] || 'sha1';
    var hmac = nodeCrypto.createHmac(algo, Buffer.from(keyBytes));
    hmac.update(Buffer.from(messageBytes));
    return new Uint8Array(hmac.digest());
  }

  /**
   * Computes HMAC using Web Crypto Subtle API.
   */
  async function computeHMACWebCrypto(keyBytes, messageBytes, algorithm) {
    algorithm = algorithm || 'SHA-1';
    var subtle = getWebCryptoSubtle();
    if (!subtle) {
      throw new Error('Web Crypto API (crypto.subtle) is not available');
    }
    var algoMap = { 'SHA-1': 'SHA-1', 'SHA-256': 'SHA-256', 'SHA-512': 'SHA-512' };
    var hash = algoMap[algorithm.toUpperCase()] || 'SHA-1';
    var importedKey = await subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: { name: hash } },
      false,
      ['sign']
    );
    var sig = await subtle.sign('HMAC', importedKey, messageBytes);
    return new Uint8Array(sig);
  }

  /**
   * Unified HMAC dispatcher supporting dual crypto environments.
   */
  async function computeHMAC(keyBytes, messageBytes, options) {
    options = options || {};
    var algorithm = options.algorithm || 'SHA-1';
    var forceCrypto = options.cryptoBackend;

    if (forceCrypto === 'node') {
      return computeHMACNode(keyBytes, messageBytes, algorithm);
    }
    if (forceCrypto === 'web') {
      return computeHMACWebCrypto(keyBytes, messageBytes, algorithm);
    }

    // Default auto-detection: prefer Web Crypto if available, fallback to Node
    var subtle = getWebCryptoSubtle();
    if (subtle) {
      return computeHMACWebCrypto(keyBytes, messageBytes, algorithm);
    }
    return computeHMACNode(keyBytes, messageBytes, algorithm);
  }

  /**
   * Computes RFC 6238 TOTP code asynchronously.
   *
   * @param {string} secret - Base32 secret key or otpauth:// URI
   * @param {Object} [options]
   * @returns {Promise<string>} TOTP code
   */
  async function generateTOTP(secret, options) {
    if (!secret) throw new Error('Secret key is required');
    options = options || {};
    var digits = options.digits || 6;
    var period = options.period || 30;
    var algorithm = options.algorithm || 'SHA-1';
    var keyBytes = base32Decode(secret, options);
    if (keyBytes.length === 0) throw new Error('Decoded secret key is empty');

    var timeSec = parseTimestampSec(options.timestamp, options.isMilliseconds);
    if (timeSec < 0) throw new RangeError('Timestamp must be non-negative');

    var counter = Math.floor(timeSec / period);
    var counterBuf = counterToBuffer(counter);
    var hmacBytes = await computeHMAC(keyBytes, counterBuf, {
      algorithm: algorithm,
      cryptoBackend: options.cryptoBackend
    });
    return truncate(hmacBytes, digits);
  }

  /**
   * Synchronous TOTP calculation for Node.js environments.
   *
   * @param {string} secret - Base32 secret key
   * @param {Object} [options]
   * @returns {string} TOTP code
   */
  function generateTOTPSync(secret, options) {
    if (!secret) throw new Error('Secret key is required');
    options = options || {};
    var digits = options.digits || 6;
    var period = options.period || 30;
    var algorithm = options.algorithm || 'SHA-1';
    var keyBytes = base32Decode(secret, options);
    if (keyBytes.length === 0) throw new Error('Decoded secret key is empty');

    var timeSec = parseTimestampSec(options.timestamp, options.isMilliseconds);
    if (timeSec < 0) throw new RangeError('Timestamp must be non-negative');

    var counter = Math.floor(timeSec / period);
    var counterBuf = counterToBuffer(counter);
    var hmacBytes = computeHMACNode(keyBytes, counterBuf, algorithm);
    return truncate(hmacBytes, digits);
  }

  /**
   * Formats a token with a visual space in the middle for readability.
   * 6 digits: "123 456", 8 digits: "1234 5678"
   */
  function formatToken(token) {
    if (!token || typeof token !== 'string') return '';
    var clean = token.replace(/\s/g, '');
    if (clean.length === 6) {
      return clean.slice(0, 3) + ' ' + clean.slice(3);
    }
    if (clean.length === 8) {
      return clean.slice(0, 4) + ' ' + clean.slice(4);
    }
    return clean;
  }

  /**
   * Calculates comprehensive TOTP state including progress and countdown.
   *
   * @param {string} secret - Base32 secret key
   * @param {number|Date} [timestamp] - Timestamp in ms, seconds, or Date (default: Date.now())
   * @param {Object} [options]
   * @returns {Promise<Object>} Calculation result
   */
  async function calculateTOTP(secret, timestamp, options) {
    options = options || {};
    var period = options.period || 30;
    var digits = options.digits || 6;
    var nowSec = parseTimestampSec(timestamp, options.isMilliseconds);
    var elapsedInPeriod = nowSec % period;
    var secondsRemaining = period - elapsedInPeriod;
    var progressPercent = Math.round((secondsRemaining / period) * 100);

    var genOpts = Object.assign({}, options);
    delete genOpts.isMilliseconds;
    genOpts.timestamp = nowSec;
    genOpts.digits = digits;
    genOpts.period = period;

    try {
      var token = await generateTOTP(secret, genOpts);
      return {
        token: token,
        formattedToken: formatToken(token),
        secondsRemaining: secondsRemaining,
        progressPercent: progressPercent,
        valid: true,
        period: period,
        digits: digits
      };
    } catch (err) {
      var placeholder = '-'.repeat(digits);
      return {
        token: placeholder,
        formattedToken: formatToken(placeholder),
        secondsRemaining: 0,
        progressPercent: 0,
        valid: false,
        period: period,
        digits: digits,
        error: err.message
      };
    }
  }

  /**
   * Interval ticker manager. Fires callback immediately and every intervalMs (default 1000ms).
   *
   * @param {string} secret - Base32 secret key
   * @param {Function} callback - Invoked with TOTPCalculationResult
   * @param {Object} [options]
   * @returns {Object} Ticker controller { stop(), updateSecret(), isRunning() }
   */
  function startTOTPTicker(secret, callback, options) {
    options = options || {};
    var intervalMs = options.intervalMs || 1000;
    var currentSecret = secret;
    var timerId = null;
    var isStopped = false;

    async function tick() {
      if (isStopped) return;
      var res = await calculateTOTP(currentSecret, Date.now(), options);
      if (isStopped) return;
      if (typeof callback === 'function') {
        callback(res);
      }
    }

    tick();
    timerId = setInterval(tick, intervalMs);

    return {
      stop: function () {
        if (!isStopped) {
          isStopped = true;
          if (timerId) {
            clearInterval(timerId);
            timerId = null;
          }
        }
      },
      updateSecret: function (newSecret) {
        currentSecret = newSecret;
        tick();
      },
      isRunning: function () {
        return !isStopped;
      }
    };
  }

  /**
   * Verifies a user-supplied token against secret with window drift tolerance.
   *
   * @param {string} token - User input token
   * @param {string} secret - Base32 secret key
   * @param {Object} [options]
   * @param {number} [options.window=1] - Allowed steps drift (+-1 = 30s before or after)
   * @returns {Promise<Object>} { valid: boolean, delta: number|null }
   */
  async function verifyTOTP(token, secret, options) {
    options = options || {};
    var window = options.window !== undefined ? options.window : 1;
    var digits = options.digits || 6;
    var period = options.period || 30;
    var nowSec = parseTimestampSec(options.timestamp, options.isMilliseconds);
    var cleanToken = String(token).replace(/\s/g, '');

    var verifyOpts = Object.assign({}, options);
    delete verifyOpts.timestamp;
    verifyOpts.digits = digits;
    verifyOpts.period = period;

    for (var offset = -window; offset <= window; offset++) {
      var stepTime = nowSec + (offset * period);
      if (stepTime < 0) continue;
      verifyOpts.timestamp = stepTime;
      var expected = await generateTOTP(secret, verifyOpts);
      if (expected === cleanToken) {
        return { valid: true, delta: offset };
      }
    }
    return { valid: false, delta: null };
  }

  /**
   * Backwards-compatible helper matching legacy Desktop renderer signature.
   * Returns 6-digit code or '------' on failure.
   *
   * @param {string} secret - Base32 secret key
   * @returns {Promise<string>} 6-digit code or '------'
   */
  async function getTOTP(secret) {
    try {
      return await generateTOTP(secret);
    } catch (_) {
      return '------';
    }
  }

  return {
    base32Decode: base32Decode,
    base32Encode: base32Encode,
    generateTOTP: generateTOTP,
    generateTOTPSync: generateTOTPSync,
    calculateTOTP: calculateTOTP,
    startTOTPTicker: startTOTPTicker,
    verifyTOTP: verifyTOTP,
    formatToken: formatToken,
    extractSecret: extractSecret,
    computeHMACNode: computeHMACNode,
    computeHMACWebCrypto: computeHMACWebCrypto,
    // Legacy renderer aliases
    getTOTP: getTOTP,
    b32dec: base32Decode
  };
});
