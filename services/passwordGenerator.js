/**
 * Fuin Secure Password Generator Service
 *
 * Headless, cross-platform CSPRNG password generation service.
 * Supports Browser (renderer without bundler), Node.js (CommonJS), and React Native.
 *
 * Cryptographic Invariants:
 * 1. Zero modulo bias rejection sampling across all charset lengths.
 * 2. Dual crypto provider support: Web Crypto (crypto.getRandomValues) and Node/RN (crypto.randomBytes).
 * 3. Never falls back to insecure Math.random().
 * 4. 5-level strength scoring (0 to 4 / 0 to 100) based on entropy and diversity.
 */
(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    var exports = factory();
    root.PasswordGenerator = exports;
    if (typeof root === 'object') {
      root.generatePassword = exports.generatePassword;
      root.calculatePasswordStrength = exports.calculatePasswordStrength;
      root.getCharset = exports.getCharset;
    }
  }
}(typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : this, function () {
  'use strict';

  // ── CONSTANTS & CHARSETS ─────────────────────────────────────────
  var CHARSETS = {
    upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower: 'abcdefghijklmnopqrstuvwxyz',
    digits: '0123456789',
    symbols: '!@#$%^&*()_+~`|}{[]:;?><,./-=',
    similar: 'il1Lo0O'
  };

  var DEFAULT_OPTIONS = {
    length: 16,
    includeUpper: true,
    includeLower: true,
    includeDigits: true,
    includeSymbols: true,
    excludeSimilar: true,
    customCharset: '',
    ensureDiversity: false
  };

  var SCORE_LABELS = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong'];
  var SCORE_LEVELS = ['veryWeak', 'weak', 'medium', 'strong', 'veryStrong'];
  var SCORE_PERCENTS = [15, 35, 60, 80, 100];

  // ── OPTION NORMALIZATION ─────────────────────────────────────────
  function normalizeOptions(options) {
    if (typeof options === 'number') {
      options = { length: options };
    } else if (!options || typeof options !== 'object') {
      options = {};
    }

    var length = 16;
    if (typeof options.length === 'number' && !isNaN(options.length)) {
      length = Math.max(0, Math.floor(options.length));
    } else if (typeof options.len === 'number' && !isNaN(options.len)) {
      length = Math.max(0, Math.floor(options.len));
    }

    var includeUpper = options.includeUpper !== undefined ? !!options.includeUpper
      : (options.useUpper !== undefined ? !!options.useUpper : true);

    var includeLower = options.includeLower !== undefined ? !!options.includeLower
      : (options.useLower !== undefined ? !!options.useLower : true);

    var includeDigits = options.includeDigits !== undefined ? !!options.includeDigits
      : (options.useDigits !== undefined ? !!options.useDigits
      : (options.includeNumbers !== undefined ? !!options.includeNumbers
      : (options.useNumbers !== undefined ? !!options.useNumbers
      : (options.useNum !== undefined ? !!options.useNum : true))));

    var includeSymbols = options.includeSymbols !== undefined ? !!options.includeSymbols
      : (options.useSymbols !== undefined ? !!options.useSymbols
      : (options.useSym !== undefined ? !!options.useSym : true));

    var excludeSimilar = options.excludeSimilar !== undefined ? !!options.excludeSimilar
      : (options.exc !== undefined ? !!options.exc : true);

    var customCharset = typeof options.customCharset === 'string' ? options.customCharset : '';
    var ensureDiversity = !!(options.ensureDiversity || options.enforceDiversity);

    return {
      length: length,
      includeUpper: includeUpper,
      includeLower: includeLower,
      includeDigits: includeDigits,
      includeSymbols: includeSymbols,
      excludeSimilar: excludeSimilar,
      customCharset: customCharset,
      ensureDiversity: ensureDiversity,
      crypto: options.crypto
    };
  }

  // ── CHARSET BUILDER ──────────────────────────────────────────────
  function filterSimilar(str, exclude) {
    if (!exclude) return str;
    var out = '';
    for (var i = 0; i < str.length; i++) {
      if (CHARSETS.similar.indexOf(str[i]) === -1) {
        out += str[i];
      }
    }
    return out;
  }

  function getCharset(options) {
    var opts = normalizeOptions(options);
    var raw = '';

    if (opts.includeUpper) raw += CHARSETS.upper;
    if (opts.includeLower) raw += CHARSETS.lower;
    if (opts.includeDigits) raw += CHARSETS.digits;
    if (opts.includeSymbols) raw += CHARSETS.symbols;

    if (opts.customCharset) {
      raw += opts.customCharset;
    }

    if (opts.excludeSimilar) {
      raw = filterSimilar(raw, true);
    }

    // Deduplicate characters to avoid sampling bias
    var seen = {};
    var unique = '';
    for (var i = 0; i < raw.length; i++) {
      var ch = raw[i];
      if (!seen[ch]) {
        seen[ch] = true;
        unique += ch;
      }
    }

    return unique;
  }

  // ── CRYPTO PROVIDER ABSTRACTION ──────────────────────────────────
  function getCryptoProvider(customCrypto) {
    if (customCrypto) {
      if (typeof customCrypto.getRandomValues === 'function') {
        return {
          type: 'webcrypto',
          getRandomValues: function (arr) { return customCrypto.getRandomValues(arr); }
        };
      }
      if (typeof customCrypto.randomBytes === 'function') {
        return {
          type: 'node',
          randomBytes: function (n) { return customCrypto.randomBytes(n); }
        };
      }
      if (typeof customCrypto === 'function') {
        return {
          type: 'node',
          randomBytes: customCrypto
        };
      }
    }

    // 1. Web Crypto API (Browser window, Electron renderer, modern Node globalThis.crypto)
    if (typeof globalThis !== 'undefined' && globalThis.crypto && typeof globalThis.crypto.getRandomValues === 'function') {
      return {
        type: 'webcrypto',
        getRandomValues: function (arr) { return globalThis.crypto.getRandomValues(arr); }
      };
    }

    if (typeof window !== 'undefined' && window.crypto && typeof window.crypto.getRandomValues === 'function') {
      return {
        type: 'webcrypto',
        getRandomValues: function (arr) { return window.crypto.getRandomValues(arr); }
      };
    }

    // 2. Node.js 'crypto' module
    if (typeof require === 'function') {
      try {
        var nodeCrypto = require('crypto');
        if (nodeCrypto && typeof nodeCrypto.randomBytes === 'function') {
          return {
            type: 'node',
            randomBytes: function (n) { return nodeCrypto.randomBytes(n); }
          };
        }
      } catch (_) {}

      // 3. React Native quick-crypto
      try {
        var quickCrypto = require('react-native-quick-crypto');
        if (quickCrypto && typeof quickCrypto.randomBytes === 'function') {
          return {
            type: 'node',
            randomBytes: function (n) { return quickCrypto.randomBytes(n); }
          };
        }
      } catch (_) {}
    }

    throw new Error('Fuin PasswordGenerator: No cryptographic random number generator available in this environment');
  }

  // ── 32-BIT BUFFERED RANDOM READER ────────────────────────────────
  function createRandomUint32Reader(provider) {
    var BATCH_SIZE = 64; // 64 x 32-bit uints = 256 bytes
    var uint32Buffer = new Uint32Array(BATCH_SIZE);
    var bufferIndex = BATCH_SIZE; // Force initial refill

    function refill() {
      if (provider.type === 'webcrypto') {
        provider.getRandomValues(uint32Buffer);
      } else {
        var rawBytes = provider.randomBytes(BATCH_SIZE * 4);
        var view = new DataView(rawBytes.buffer, rawBytes.byteOffset, rawBytes.byteLength);
        for (var i = 0; i < BATCH_SIZE; i++) {
          uint32Buffer[i] = view.getUint32(i * 4, true);
        }
      }
      bufferIndex = 0;
    }

    return function nextUint32() {
      if (bufferIndex >= BATCH_SIZE) {
        refill();
      }
      return uint32Buffer[bufferIndex++];
    };
  }

  // ── REJECTION SAMPLING (ZERO MODULO BIAS) ─────────────────────────
  function getRandomIndex(charsetLength, nextUint32) {
    if (charsetLength <= 1) return 0;
    // 0x100000000 = 2^32 = 4294967296
    var maxValid = 0x100000000 - (0x100000000 % charsetLength);
    var r;
    do {
      r = nextUint32();
    } while (r >= maxValid);
    return r % charsetLength;
  }

  // ── STRENGTH SCORING ─────────────────────────────────────────────
  function calculatePasswordStrength(password, customCharsetLength) {
    if (!password || typeof password !== 'string') {
      return {
        score: 0,
        percent: 0,
        entropy: 0,
        level: SCORE_LEVELS[0],
        label: SCORE_LABELS[0],
        diversity: {
          length: 0,
          hasUpper: false,
          hasLower: false,
          hasDigits: false,
          hasSymbols: false,
          uniqueChars: 0
        },
        warning: 'Empty password'
      };
    }

    var len = password.length;
    var hasUpper = /[A-Z]/.test(password);
    var hasLower = /[a-z]/.test(password);
    var hasDigits = /[0-9]/.test(password);
    var hasSymbols = /[^A-Za-z0-9]/.test(password);

    var uniqueSet = {};
    for (var i = 0; i < len; i++) {
      uniqueSet[password[i]] = true;
    }
    var uniqueChars = Object.keys(uniqueSet).length;

    // Determine character pool size
    var poolSize = 0;
    if (typeof customCharsetLength === 'number' && customCharsetLength > 0) {
      poolSize = customCharsetLength;
    } else {
      if (hasUpper) poolSize += 26;
      if (hasLower) poolSize += 26;
      if (hasDigits) poolSize += 10;
      if (hasSymbols) poolSize += 33;
    }

    if (poolSize === 0) poolSize = 1;

    // Information Entropy: E = L * log2(Pool)
    var rawEntropy = len * (Math.log(poolSize) / Math.LN2);

    // Repetition / Low-entropy penalty
    var uniqueRatio = uniqueChars / len;
    var entropy = rawEntropy;
    if (uniqueRatio < 0.6) {
      entropy = rawEntropy * uniqueRatio;
    }

    // Sequence / Pattern detection penalty (e.g., 1234, abcd)
    var warning = '';
    if (uniqueChars === 1 && len > 1) {
      entropy = Math.min(entropy, 5);
      warning = 'Repeated identical characters';
    } else if (/^[0-9]+$/.test(password)) {
      entropy = Math.min(entropy, 25);
      warning = 'Digits only';
    } else if (/^[a-zA-Z]+$/.test(password)) {
      entropy = entropy * 0.85;
      warning = 'Letters only';
    }

    // Multi-factor 5-level scoring (0 to 4)
    var poolCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigits ? 1 : 0) + (hasSymbols ? 1 : 0);
    var score = 0;

    if (len < 6 || entropy < 28) {
      score = 0;
    } else if (entropy < 46 || len < 8 || poolCount < 2) {
      score = 1;
    } else if (entropy < 66 || len < 11 || poolCount < 3) {
      score = 2;
    } else if (entropy < 86 || len < 14) {
      score = 3;
    } else {
      score = 4;
    }

    // Hard ceiling for very short passwords
    if (len < 8 && score > 1) score = 1;
    if (len < 6) score = 0;

    entropy = Math.round(entropy * 10) / 10;

    return {
      score: score,
      percent: SCORE_PERCENTS[score],
      entropy: entropy,
      level: SCORE_LEVELS[score],
      label: SCORE_LABELS[score],
      diversity: {
        length: len,
        hasUpper: hasUpper,
        hasLower: hasLower,
        hasDigits: hasDigits,
        hasSymbols: hasSymbols,
        uniqueChars: uniqueChars
      },
      warning: warning
    };
  }

  // ── GENERATE PASSWORD ────────────────────────────────────────────
  function generatePassword(options) {
    var opts = normalizeOptions(options);

    if (opts.length <= 0) {
      return {
        password: '',
        score: 0,
        percent: 0,
        entropy: 0,
        level: SCORE_LEVELS[0],
        label: SCORE_LABELS[0],
        length: 0,
        charsetLength: 0,
        toString: function () { return this.password; }
      };
    }

    var charset = getCharset(opts);
    if (!charset) {
      return {
        password: '',
        score: 0,
        percent: 0,
        entropy: 0,
        level: SCORE_LEVELS[0],
        label: SCORE_LABELS[0],
        length: 0,
        charsetLength: 0,
        toString: function () { return this.password; }
      };
    }

    var provider = getCryptoProvider(opts.crypto);
    var nextUint32 = createRandomUint32Reader(provider);
    var chars = [];

    // Optional diversity enforcement: guarantee at least one char from each enabled pool
    if (opts.ensureDiversity && opts.length >= 4) {
      var activePools = [];
      if (opts.includeUpper) activePools.push(filterSimilar(CHARSETS.upper, opts.excludeSimilar));
      if (opts.includeLower) activePools.push(filterSimilar(CHARSETS.lower, opts.excludeSimilar));
      if (opts.includeDigits) activePools.push(filterSimilar(CHARSETS.digits, opts.excludeSimilar));
      if (opts.includeSymbols) activePools.push(filterSimilar(CHARSETS.symbols, opts.excludeSimilar));

      var validPools = activePools.filter(function (p) { return p && p.length > 0; });
      if (opts.length >= validPools.length) {
        for (var pIdx = 0; pIdx < validPools.length; pIdx++) {
          var pool = validPools[pIdx];
          var charIdx = getRandomIndex(pool.length, nextUint32);
          chars.push(pool[charIdx]);
        }
      }
    }

    // Fill remaining password length with uniform rejection sampling
    while (chars.length < opts.length) {
      var idx = getRandomIndex(charset.length, nextUint32);
      chars.push(charset[idx]);
    }

    // If diversity was enforced, perform Fisher-Yates CSPRNG shuffle
    if (opts.ensureDiversity && chars.length > 1) {
      for (var i = chars.length - 1; i > 0; i--) {
        var j = getRandomIndex(i + 1, nextUint32);
        var temp = chars[i];
        chars[i] = chars[j];
        chars[j] = temp;
      }
    }

    var password = chars.join('');
    var strength = calculatePasswordStrength(password, charset.length);

    return {
      password: password,
      score: strength.score,
      percent: strength.percent,
      entropy: strength.entropy,
      level: strength.level,
      label: strength.label,
      length: password.length,
      charsetLength: charset.length,
      diversity: strength.diversity,
      toString: function () { return this.password; }
    };
  }

  // ── EXPORT CONTRACT ──────────────────────────────────────────────
  return {
    generatePassword: generatePassword,
    calculatePasswordStrength: calculatePasswordStrength,
    getCharset: getCharset,
    CHARSETS: CHARSETS,
    DEFAULT_OPTIONS: DEFAULT_OPTIONS,
    SCORE_LABELS: SCORE_LABELS,
    SCORE_LEVELS: SCORE_LEVELS,
    SCORE_PERCENTS: SCORE_PERCENTS
  };
}));
