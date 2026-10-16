/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN IMPORT SERVICE: detector.js
 *
 * Fast, accurate format detection for password manager exports:
 * - Bitwarden (CSV and JSON)
 * - LastPass (CSV)
 * - 1Password (CSV - Classic & Modern)
 * - Google Chrome / Edge / Brave (CSV)
 * - Fuin native (CSV and JSON)
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.FuinImporters = root.FuinImporters || {};
    root.FuinImporters.detector = factory();
  }
}(typeof self !== 'undefined' ? self : typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  /**
   * Strip UTF-8 Byte Order Mark (BOM) if present.
   */
  function stripBOM(str) {
    if (typeof str !== 'string') return '';
    return str.charCodeAt(0) === 0xFEFF ? str.slice(1) : str;
  }

  /**
   * Parse the first line/row of CSV to extract normalized headers.
   * Single-pass RFC 4180 compliant tokenizer:
   * - Preserves escaped quotes ("" -> ") within field content
   * - Commas inside quoted fields are never treated as column delimiters
   * - Preserves newlines inside quoted fields without premature row termination
   * - Stops cleanly at the first unquoted CRLF / LF / CR
   * - Strips BOM, trims whitespace, converts to lowercase, and strips outer quotes
   * @param {string} text Full or partial CSV text content.
   * @returns {string[]} Array of normalized header column names.
   */
  function extractCSVHeaders(text) {
    if (typeof text !== 'string') return [];
    var clean = stripBOM(text).trim();
    if (!clean) return [];

    var headers = [];
    var cur = '';
    var inQuotes = false;
    var len = clean.length;

    for (var i = 0; i < len; i++) {
      var c = clean[i];

      if (inQuotes) {
        if (c === '"') {
          if (i + 1 < len && clean[i + 1] === '"') {
            // Escaped quote: "" represents a single literal quote
            cur += '"';
            i++;
          } else {
            // Closing quote
            inQuotes = false;
          }
        } else {
          // Inside quotes, all characters (commas, newlines, etc.) are literal
          cur += c;
        }
      } else {
        if (c === '"') {
          inQuotes = true;
        } else if (c === ',') {
          headers.push(cur.trim().toLowerCase().replace(/^["']|["']$/g, ''));
          cur = '';
        } else if (c === '\r' || c === '\n') {
          break;
        } else {
          cur += c;
        }
      }
    }

    headers.push(cur.trim().toLowerCase().replace(/^["']|["']$/g, ''));
    return headers.filter(Boolean);
  }

  /**
   * Detailed format detection returning metadata.
   * @param {string} text Raw file content.
   * @returns {{ format: string, type: 'csv'|'json', confidence: 'high'|'medium'|'low'|'none', isEncrypted?: boolean }}
   */
  function detectFormatDetails(text) {
    if (typeof text !== 'string' || !text.trim()) {
      return { format: 'unknown', type: 'csv', confidence: 'none' };
    }

    var clean = stripBOM(text).trim();

    // 1. Check for JSON format
    if (clean.charAt(0) === '{' || clean.charAt(0) === '[') {
      try {
        var parsed = JSON.parse(clean);
        // Bitwarden JSON export
        if (parsed && typeof parsed === 'object') {
          if (parsed.encrypted === true) {
            return { format: 'bitwarden', type: 'json', confidence: 'high', isEncrypted: true };
          }
          if (Array.isArray(parsed.items) || (parsed.folders && Array.isArray(parsed.folders))) {
            return { format: 'bitwarden', type: 'json', confidence: 'high', isEncrypted: false };
          }
          // Fuin native full vault JSON
          if (parsed.type === 'fuin/vault' || (parsed.entries && Array.isArray(parsed.entries))) {
            return { format: 'fuin', type: 'json', confidence: 'high', isEncrypted: false };
          }
        }
        // Bare Fuin entries array JSON
        if (Array.isArray(parsed) && parsed.length > 0) {
          var first = parsed[0];
          if (first && (first.site !== undefined || (first.title !== undefined && first.password !== undefined))) {
            return { format: 'fuin', type: 'json', confidence: 'high', isEncrypted: false };
          }
        }
      } catch (_) {
        // Not valid JSON, continue to CSV detection
      }
    }

    // 2. Check for CSV format
    var headers = extractCSVHeaders(clean);
    if (headers.length === 0) {
      return { format: 'unknown', type: 'csv', confidence: 'none' };
    }

    var has = function (k) { return headers.indexOf(k) !== -1; };
    var hasAny = function (arr) {
      for (var k = 0; k < arr.length; k++) {
        if (headers.indexOf(arr[k]) !== -1) return true;
      }
      return false;
    };

    // Bitwarden CSV: folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
    if (has('login_username') || has('login_password') || has('login_uri') || has('login_totp')) {
      return { format: 'bitwarden', type: 'csv', confidence: 'high' };
    }

    // LastPass CSV: url,username,password,totp,extra,name,grouping,fav
    if (has('grouping') || (has('extra') && (has('url') || has('username')))) {
      return { format: 'lastpass', type: 'csv', confidence: 'high' };
    }

    // 1Password CSV: Title,URL,Username,Password,Notes,OTPAuth OR title,website,username,password,notes,one-time password
    if (has('otpauth') || has('one-time password') || (has('title') && has('website')) || (has('title') && has('username') && (has('notes') || has('url')))) {
      return { format: '1password', type: 'csv', confidence: 'high' };
    }

    // Google Chrome / Edge / Brave CSV: name,url,username,password,note
    if (has('name') && has('url') && has('username') && has('password')) {
      return { format: 'chrome', type: 'csv', confidence: 'high' };
    }

    // Fuin native CSV: site,category,username,password,url,note,totp
    if (has('site') && (has('password') || has('username'))) {
      return { format: 'fuin', type: 'csv', confidence: 'high' };
    }

    // Fallback: Generic CSV if title/name and password columns exist
    if (hasAny(['title', 'name', 'site', 'service', 'url']) && hasAny(['password', 'pass', 'secret'])) {
      return { format: 'fuin', type: 'csv', confidence: 'medium' };
    }

    return { format: 'unknown', type: 'csv', confidence: 'none' };
  }

  /**
   * Primary detection entry point matching project contract:
   * returns 'bitwarden' | 'lastpass' | '1password' | 'chrome' | 'fuin' | 'unknown'
   * @param {string} text Raw file content.
   * @returns {string} Detected format name.
   */
  function detectFormat(text) {
    return detectFormatDetails(text).format;
  }

  return {
    detectFormat: detectFormat,
    detectFormatDetails: detectFormatDetails,
    stripBOM: stripBOM,
    extractCSVHeaders: extractCSVHeaders
  };
}));
