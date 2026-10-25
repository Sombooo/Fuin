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
  var SCORE_PERCENTS = [20, 40, 60, 80, 100];

  var KEYBOARD_ROWS = [
    '1234567890-=',
    '!@#$%^&*()_+',
    'qwertyuiop[]',
    'asdfghjkl;\'',
    'zxcvbnm,./',
    '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/'
  ];

  var COMMON_DICTIONARY_STEMS = [
    'password', 'passw0rd', 'qwerty', 'admin', 'welcome', 'letmein', 'monkey',
    'dragon', 'master', 'shadow', 'baseball', 'football', 'iloveyou', 'trustno1',
    'sunshine', 'princess', 'starwars', 'batman', 'superman', 'michael', 'charlie',
    'donald', 'mustang', 'access', 'secret', 'freedom', 'whatever', 'computer',
    'security', 'anker', 'istanbul', 'turkiye', 'fenerbahce', 'galatasaray', 'besiktas'
  ];

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

  // ── BITWARDEN / ZXCVBN-ALIGNED SCIENTIFIC STRENGTH SCORING ───────
  function normalizeL33t(str) {
    return str
      .toLowerCase()
      .replace(/@|4/g, 'a')
      .replace(/0/g, 'o')
      .replace(/1|!/g, 'i')
      .replace(/3/g, 'e')
      .replace(/\$|5/g, 's')
      .replace(/7|\+/g, 't');
  }

  function countSequenceChars(password) {
    var seqChars = 0;
    var run = 1;
    var prevDiff = null;
    var lower = password.toLowerCase();
    for (var i = 1; i < lower.length; i++) {
      var diff = lower.charCodeAt(i) - lower.charCodeAt(i - 1);
      if ((diff === 1 || diff === -1) && (prevDiff === null || diff === prevDiff)) {
        run++;
        prevDiff = diff;
      } else {
        if (run >= 3) seqChars += (run - 2);
        run = (diff === 1 || diff === -1) ? 2 : 1;
        prevDiff = (diff === 1 || diff === -1) ? diff : null;
      }
    }
    if (run >= 3) seqChars += (run - 2);
    return seqChars;
  }

  function countKeyboardWalkChars(password) {
    var lower = password.toLowerCase();
    var walkChars = 0;
    for (var r = 0; r < KEYBOARD_ROWS.length; r++) {
      var row = KEYBOARD_ROWS[r];
      var rev = row.split('').reverse().join('');
      for (var i = 0; i <= lower.length - 4; i++) {
        var sub = lower.slice(i, i + 4);
        if (row.indexOf(sub) !== -1 || rev.indexOf(sub) !== -1) {
          walkChars += 2;
        }
      }
    }
    return Math.min(walkChars, Math.max(0, password.length - 2));
  }

  function formatCrackTime(entropyBits) {
    // Bitwarden / zxcvbn standard offline fast-hashing & KDF model
    // Average guesses = 2^(entropyBits - 1), evaluated at 10^10 guesses/sec (GPU cluster)
    var guessesLog10 = entropyBits * (Math.LN2 / Math.LN10);
    var seconds = Math.pow(2, Math.max(0, entropyBits - 1)) / 1e10;

    if (entropyBits < 28 || seconds < 1) {
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'instant', en: 'less than a second', tr: '1 saniyeden az' };
    }
    if (seconds < 60) {
      var s = Math.max(1, Math.round(seconds));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'seconds', en: s + ' seconds', tr: s + ' saniye' };
    }
    var minutes = seconds / 60;
    if (minutes < 60) {
      var m = Math.max(1, Math.round(minutes));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'minutes', en: m + ' minutes', tr: m + ' dakika' };
    }
    var hours = minutes / 60;
    if (hours < 24) {
      var h = Math.max(1, Math.round(hours));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'hours', en: h + ' hours', tr: h + ' saat' };
    }
    var days = hours / 24;
    if (days < 31) {
      var d = Math.max(1, Math.round(days));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'days', en: d + ' days', tr: d + ' gün' };
    }
    var months = days / 30.4375;
    if (months < 12) {
      var mo = Math.max(1, Math.round(months));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'months', en: mo + ' months', tr: mo + ' ay' };
    }
    var years = days / 365.25;
    if (years < 100) {
      var y = Math.max(1, Math.round(years));
      return { seconds: seconds, guessesLog10: guessesLog10, key: 'years', en: y + ' years', tr: y + ' yıl' };
    }
    return { seconds: seconds, guessesLog10: guessesLog10, key: 'centuries', en: 'centuries', tr: 'yüzyıllar' };
  }

  function calculatePasswordStrength(password, customCharsetLength) {
    if (!password || typeof password !== 'string') {
      return {
        score: 0,
        percent: 0,
        entropy: 0,
        guessesLog10: 0,
        crackTime: 'less than a second',
        crackTimeTr: '1 saniyeden az',
        crackTimeKey: 'instant',
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

    // Determine effective character pool size from observed character classes
    var observedPool = 0;
    if (hasUpper) observedPool += 26;
    if (hasLower) observedPool += 26;
    if (hasDigits) observedPool += 10;
    if (hasSymbols) observedPool += 33;

    var poolSize = observedPool;
    if (typeof customCharsetLength === 'number' && customCharsetLength > 0) {
      // Respect custom/filtered charset cap while reflecting actual observed classes
      poolSize = observedPool > 0 ? Math.min(observedPool, customCharsetLength) : customCharsetLength;
    }
    if (poolSize <= 0) poolSize = 1;

    var bitsPerChar = Math.log(poolSize) / Math.LN2;
    var warning = '';

    // 1. Deduct predictable pattern lengths (repeats, sequences, keyboard walks, dictionary stems)
    var penaltyChars = 0;

    // Repeated identical character runs (e.g., 'aaaa')
    var repeatMatches = password.match(/(.)\1{2,}/g);
    if (repeatMatches) {
      for (var rm = 0; rm < repeatMatches.length; rm++) {
        penaltyChars += (repeatMatches[rm].length - 1.5);
      }
      warning = 'Repeated character pattern';
    }

    // Repeated multi-character blocks (e.g., 'abcabc', '121212')
    var blockRepeat = password.match(/(.{2,5})\1+/g);
    if (blockRepeat) {
      for (var br = 0; br < blockRepeat.length; br++) {
        penaltyChars += (blockRepeat[br].length * 0.55);
      }
      if (!warning) warning = 'Repeating pattern';
    }

    // Sequential runs (e.g., '12345', 'abcdef')
    var seqCount = countSequenceChars(password);
    if (seqCount > 0) {
      penaltyChars += seqCount * 0.75;
      if (!warning) warning = 'Sequential characters';
    }

    // Keyboard walks (e.g., 'qwerty', 'asdfgh')
    var walkCount = countKeyboardWalkChars(password);
    if (walkCount > 0) {
      penaltyChars += walkCount * 0.75;
      if (!warning) warning = 'Keyboard pattern';
    }

    // Dictionary stems & L33t substitutions
    var deLeeted = normalizeL33t(password);
    for (var dIdx = 0; dIdx < COMMON_DICTIONARY_STEMS.length; dIdx++) {
      var stem = COMMON_DICTIONARY_STEMS[dIdx];
      if (deLeeted.indexOf(stem) !== -1) {
        // A known dictionary word adds ~11 bits total instead of stem.length * bitsPerChar
        penaltyChars += Math.max(0, stem.length - (11 / Math.max(1, bitsPerChar)));
        if (!warning) warning = 'Common dictionary pattern';
        break;
      }
    }

    // 4-digit years (1900-2099)
    if (/(19\d\d|20\d\d)/.test(password)) {
      penaltyChars += 1.8;
    }

    var effectiveLen = Math.max(1, len - penaltyChars);
    var entropy = effectiveLen * bitsPerChar;

    // 2. Low unique-character diversity damping
    var uniqueRatio = uniqueChars / len;
    if (uniqueRatio < 0.65) {
      entropy = entropy * (0.4 + 0.6 * uniqueRatio);
    }

    // 3. Special structural warnings & ceilings
    if (uniqueChars === 1 && len > 1) {
      entropy = Math.min(entropy, 5);
      warning = 'Repeated identical characters';
    } else if (/^[0-9]+$/.test(password)) {
      if (len <= 12) entropy = Math.min(entropy, 34);
      warning = 'Digits only';
    } else if (/^[a-zA-Z]+$/.test(password) && len < 14) {
      entropy = entropy * 0.88;
      if (!warning) warning = 'Letters only';
    }

    // 4. Bitwarden / zxcvbn 5-tier score mapping (0 to 4) based on effective entropy bits
    // Score 0 (< 28 bits): < 1 second
    // Score 1 (28 - 44 bits): seconds to minutes
    // Score 2 (45 - 63 bits): hours to days
    // Score 3 (64 - 82 bits): months to years
    // Score 4 (>= 83 bits): centuries
    var score = 0;
    if (len < 6 || entropy < 28) {
      score = 0;
    } else if (entropy < 45 || len < 8) {
      score = 1;
    } else if (entropy < 64 || len < 10) {
      score = 2;
    } else if (entropy < 83 || len < 12) {
      score = 3;
    } else {
      score = 4;
    }

    // Hard ceiling for very short passwords
    if (len < 8 && score > 1) score = 1;
    if (len < 6) score = 0;

    entropy = Math.round(entropy * 10) / 10;
    var crackInfo = formatCrackTime(entropy);

    return {
      score: score,
      percent: SCORE_PERCENTS[score],
      entropy: entropy,
      guessesLog10: Math.round(crackInfo.guessesLog10 * 10) / 10,
      crackTime: crackInfo.en,
      crackTimeTr: crackInfo.tr,
      crackTimeKey: crackInfo.key,
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
        guessesLog10: 0,
        crackTime: 'less than a second',
        crackTimeTr: '1 saniyeden az',
        crackTimeKey: 'instant',
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
        guessesLog10: 0,
        crackTime: 'less than a second',
        crackTimeTr: '1 saniyeden az',
        crackTimeKey: 'instant',
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
      guessesLog10: strength.guessesLog10,
      crackTime: strength.crackTime,
      crackTimeTr: strength.crackTimeTr,
      crackTimeKey: strength.crackTimeKey,
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
