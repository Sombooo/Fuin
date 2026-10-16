/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN IMPORT SERVICE: csvImporter.js
 *
 * RFC 4180-compliant CSV parser and password manager normalizer:
 * - Robust state-machine tokenizer supporting multiline cells and escaped quotes
 * - UTF-8 BOM stripping
 * - Accurate column mapping for Bitwarden, LastPass, 1Password, Chrome, Fuin
 * - Strict preservation of password whitespace
 * - Standard Fuin schema generation with backward-compatibility aliases
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['./detector'], factory);
  } else if (typeof module === 'object' && module.exports) {
    var detector = require('./detector');
    module.exports = factory(detector);
  } else {
    root.FuinImporters = root.FuinImporters || {};
    root.FuinImporters.csv = factory(root.FuinImporters.detector);
  }
}(typeof self !== 'undefined' ? self : typeof globalThis !== 'undefined' ? globalThis : this, function (detector) {
  'use strict';

  /**
   * Universal UUID v4 generator compatible with Browser, Node, and React Native.
   */
  function generateUUID() {
    if (typeof crypto !== 'undefined') {
      if (typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
      }
      if (typeof crypto.getRandomValues === 'function') {
        var b = new Uint8Array(16);
        crypto.getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40; // Version 4
        b[8] = (b[8] & 0x3f) | 0x80; // Variant 10
        var h = Array.from(b, function (x) { return x.toString(16).padStart(2, '0'); }).join('');
        return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
      }
    }
    // Fallback RFC 4122 v4
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      var v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * RFC 4180 compliant CSV tokenizer.
   * Parses the full text into a 2D array of strings.
   * Correctly preserves newlines inside quoted fields and unescapes double quotes ("" -> ").
   * @param {string} text Full CSV text content.
   * @returns {string[][]} Array of rows, each containing an array of column values.
   */
  function parseCSV(text) {
    if (typeof text !== 'string') return [];

    // Strip BOM
    var str = text.charCodeAt(0) === 0xFEFF ? text.slice(1) : text;
    if (!str.trim()) return [];

    var rows = [];
    var row = [];
    var field = '';
    var inQuotes = false;
    var len = str.length;

    for (var i = 0; i < len; i++) {
      var c = str[i];

      if (inQuotes) {
        if (c === '"') {
          if (i + 1 < len && str[i + 1] === '"') {
            // Escaped quote: "" represents a single literal quote
            field += '"';
            i++;
          } else {
            // Closing quote
            inQuotes = false;
          }
        } else {
          // Inside quotes, all characters (including \r, \n, commas) are literal
          field += c;
        }
      } else {
        if (c === '"') {
          inQuotes = true;
        } else if (c === ',') {
          row.push(field);
          field = '';
        } else if (c === '\r') {
          // Normalize CRLF -> skip \n if immediately following
          if (i + 1 < len && str[i + 1] === '\n') {
            i++;
          }
          row.push(field);
          rows.push(row);
          row = [];
          field = '';
        } else if (c === '\n') {
          row.push(field);
          rows.push(row);
          row = [];
          field = '';
        } else {
          field += c;
        }
      }
    }

    // Flush remaining buffer
    if (field.length > 0 || row.length > 0) {
      row.push(field);
      rows.push(row);
    }

    // Ignore trailing empty line if present
    if (rows.length > 0) {
      var last = rows[rows.length - 1];
      if (last.length === 1 && last[0] === '') {
        rows.pop();
      }
    }

    return rows;
  }

  /**
   * Field synonym dictionaries for resilient column mapping.
   */
  var FIELD_SYNONYMS = {
    title: ['name', 'title', 'site', 'service', 'item_name', 'login_name'],
    url: ['url', 'login_uri', 'website', 'web_address', 'login_url', 'uri', 'address'],
    username: ['username', 'login_username', 'user', 'email', 'login', 'user_name', 'account'],
    password: ['password', 'login_password', 'pass', 'secret', 'user_password'],
    notes: ['notes', 'note', 'extra', 'comments', 'comment', 'description'],
    totp: ['totp', 'login_totp', 'otpauth', 'one-time password', 'otp', '2fa', 'authenticator'],
    category: ['category', 'grouping', 'folder', 'group', 'type', 'vault'],
    favorite: ['favorite', 'fav', 'starred']
  };

  /**
   * Build column mapping from normalized header names.
   * @param {string[]} headers Array of header strings.
   * @param {string} [format='fuin'] Specific format name if known.
   * @returns {Record<string, number>} Map of standard field names to column indexes.
   */
  function buildColMap(headers, format) {
    if (!Array.isArray(headers)) {
      return {
        title: -1,
        url: -1,
        username: -1,
        password: -1,
        notes: -1,
        totp: -1,
        category: -1,
        favorite: -1
      };
    }

    var h = headers.map(function (x) {
      return String(x != null ? x : '').trim().toLowerCase().replace(/^["']|["']$/g, '');
    });
    var idx = function (k) { return h.indexOf(k); };

    var map = {
      title: -1,
      url: -1,
      username: -1,
      password: -1,
      notes: -1,
      totp: -1,
      category: -1,
      favorite: -1
    };

    if (format === 'bitwarden') {
      map.title = idx('name');
      map.url = idx('login_uri');
      map.username = idx('login_username');
      map.password = idx('login_password');
      map.notes = idx('notes') > -1 ? idx('notes') : idx('extra');
      map.totp = idx('login_totp');
      map.category = idx('folder');
      map.favorite = idx('favorite');
    } else if (format === 'lastpass') {
      map.title = idx('name') > -1 ? idx('name') : idx('url');
      map.url = idx('url');
      map.username = idx('username');
      map.password = idx('password');
      map.notes = idx('extra');
      map.totp = idx('totp');
      map.category = idx('grouping');
      map.favorite = idx('fav');
    } else if (format === '1password') {
      map.title = idx('title');
      map.url = idx('url') > -1 ? idx('url') : idx('website');
      map.username = idx('username');
      map.password = idx('password');
      map.notes = idx('notes') > -1 ? idx('notes') : idx('note');
      map.totp = idx('otpauth') > -1 ? idx('otpauth') : idx('one-time password');
      map.category = idx('category') > -1 ? idx('category') : idx('type');
      map.favorite = idx('favorite');
    } else if (format === 'chrome') {
      map.title = idx('name');
      map.url = idx('url');
      map.username = idx('username');
      map.password = idx('password');
      map.notes = idx('note');
    } else {
      // Fuin native format
      map.title = idx('site') > -1 ? idx('site') : idx('title');
      map.url = idx('url');
      map.username = idx('username');
      map.password = idx('password');
      map.notes = idx('note') > -1 ? idx('note') : idx('notes');
      map.totp = idx('totp');
      map.category = idx('category');
      map.favorite = idx('fav');
    }

    // Apply synonym fallbacks for any unmapped standard fields
    for (var field in FIELD_SYNONYMS) {
      if (map[field] === -1 || map[field] === undefined) {
        var synonyms = FIELD_SYNONYMS[field];
        for (var s = 0; s < synonyms.length; s++) {
          var found = idx(synonyms[s]);
          if (found > -1) {
            map[field] = found;
            break;
          }
        }
      }
    }

    return map;
  }

  /**
   * Convert a single CSV row to a normalized Fuin vault entry.
   * @param {string[]} cols Columns in this row.
   * @param {Record<string, number>} colMap Column index map.
   * @param {object} [options] Custom options (e.g. defaultCategory, now, idGenerator).
   * @returns {object|null} Normalized entry or null if invalid (missing title or password).
   */
  function csvRowToEntry(cols, colMap, options) {
    if (!Array.isArray(cols)) return null;
    colMap = colMap || {};
    options = options || {};

    var get = function (key) {
      var i = colMap[key];
      if (i === undefined || i === -1 || i >= cols.length) return '';
      return cols[i] !== undefined && cols[i] !== null ? String(cols[i]) : '';
    };

    var title = (get('title') || get('site') || '').trim();
    var url = (get('url') || '').trim();

    // Fallback: Use URL hostname or URL string as title if title is empty
    if (!title && url) {
      try {
        title = new URL(url).hostname || url;
      } catch (_) {
        title = url;
      }
    }

    // Password: preserve exact internal whitespace (do NOT trim)
    var password = get('password');

    // Entry MUST have at least title and password
    if (!title || !password) {
      return null;
    }

    var username = (get('username') || '').trim();
    var notes = get('notes') || get('note') || '';
    var totp = (get('totp') || '').trim();
    var category = String(get('category') || options.defaultCategory || 'Diğer').trim() || 'Diğer';
    var rawFav = get('favorite');
    var fav = rawFav === '1' || rawFav.toLowerCase() === 'true' || rawFav.toLowerCase() === 'yes';

    var now = typeof options.now === 'number' && !isNaN(options.now) ? options.now : Date.now();
    var id = typeof options.generateId === 'function' ? options.generateId() : generateUUID();
    if (!id || typeof id !== 'string') id = generateUUID();

    return {
      id: id,
      title: title,
      site: title,           // Backward compatibility with Fuin Desktop & Mobile
      username: username,
      password: password,
      url: url,
      notes: notes,
      note: notes,           // Backward compatibility with Fuin Desktop & Mobile
      totp: totp,
      category: category,
      fav: fav,
      isDeleted: false,
      deletedAt: null,
      created: now,
      createdAt: now,
      updated: now,
      updatedAt: now
    };
  }

  /**
   * Import all entries from a raw CSV text.
   * @param {string} text Full CSV file content.
   * @param {object} [options] Import options.
   * @param {string} [options.format] Force specific format ('bitwarden', 'lastpass', '1password', 'chrome', 'fuin').
   * @param {Array} [options.existingEntries] Current entries to check against for deduplication.
   * @param {string} [options.defaultCategory='Diğer'] Default category name.
   * @returns {{ format: string, entries: object[], totalRows: number, count: number, skippedCount: number }}
   */
  function importCSV(text, options) {
    options = options || {};
    var rows = parseCSV(text);
    if (rows.length < 2) {
      return { format: 'unknown', entries: [], totalRows: 0, count: 0, skippedCount: 0 };
    }

    var headerRow = rows[0];
    var detectedFormat = options.format || (detector ? detector.detectFormat(text) : 'fuin');
    var colMap = buildColMap(headerRow, detectedFormat);

    var existingEntries = Array.isArray(options.existingEntries) ? options.existingEntries : [];
    var isDuplicate = function (candidate) {
      return existingEntries.some(function (e) {
        return e && (e.site === candidate.site || e.title === candidate.title) &&
          e.username === candidate.username &&
          e.password === candidate.password;
      });
    };

    var entries = [];
    var skippedCount = 0;
    var now = Date.now();

    for (var i = 1; i < rows.length; i++) {
      var row = rows[i];
      if (!row || !Array.isArray(row) || row.length === 0 || (row.length === 1 && !String(row[0] || '').trim())) {
        continue; // Skip blank lines
      }

      var entryOpts = Object.assign({}, options, { now: now });
      var entry = csvRowToEntry(row, colMap, entryOpts);
      if (!entry) {
        skippedCount++;
        continue;
      }

      if (isDuplicate(entry)) {
        skippedCount++;
        continue;
      }

      entries.push(entry);
    }

    return {
      format: detectedFormat,
      entries: entries,
      totalRows: rows.length - 1,
      count: entries.length,
      skippedCount: skippedCount
    };
  }

  return {
    parseCSV: parseCSV,
    buildColMap: buildColMap,
    csvRowToEntry: csvRowToEntry,
    importCSV: importCSV,
    generateUUID: generateUUID
  };
}));
