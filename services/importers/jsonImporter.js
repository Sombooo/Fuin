/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN IMPORT SERVICE: jsonImporter.js
 *
 * JSON parser for Bitwarden and Fuin Vault export formats:
 * - Bitwarden unencrypted JSON parser with folder-to-category resolution
 * - Strict rejection of Bitwarden encrypted exports (encrypted: true)
 * - Fuin native JSON full vault schema and bare entries array parser
 * - Schema normalization and safe property filtering
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.FuinImporters = root.FuinImporters || {};
    root.FuinImporters.json = factory();
  }
}(typeof self !== 'undefined' ? self : typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function generateUUID() {
    if (typeof crypto !== 'undefined') {
      if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
      if (typeof crypto.getRandomValues === 'function') {
        var b = new Uint8Array(16);
        crypto.getRandomValues(b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        var h = Array.from(b, function (x) { return x.toString(16).padStart(2, '0'); }).join('');
        return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
      }
    }
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      var v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  /**
   * Convert a single Bitwarden item object to a normalized Fuin vault entry.
   * Defensively sanitizes null, undefined, or missing values for all fields.
   * @param {object} item Bitwarden item.
   * @param {Map<string, string>|object} [folderMap] Map of folder IDs to folder names.
   * @param {object} [options] Custom options.
   * @returns {object|null} Normalized entry or null if invalid (missing title or password).
   */
  function bitwardenItemToEntry(item, folderMap, options) {
    if (!item || typeof item !== 'object') return null;
    var login = item.login;
    if (!login || typeof login !== 'object') return null;

    options = options || {};
    var title = String(item.name || '').trim();
    var password = login.password != null ? String(login.password) : '';

    var firstUri = Array.isArray(login.uris) && login.uris.length > 0 ? login.uris[0] : null;
    var rawUrl = (firstUri && typeof firstUri === 'object') ? firstUri.uri : (typeof firstUri === 'string' ? firstUri : '');
    var url = String(rawUrl || '').trim();

    // Fallback: URL hostname or URL as title if name is empty
    if (!title && url) {
      try {
        title = new URL(url).hostname || url;
      } catch (_) {
        title = url;
      }
    }

    if (!title || !password) return null;

    var username = (login.username != null ? String(login.username) : '').trim();
    var notes = item.notes != null ? String(item.notes) : '';
    var totp = (login.totp != null ? String(login.totp) : '').trim();

    var folderName = '';
    if (item.folderId && folderMap) {
      folderName = (typeof folderMap.get === 'function') ? folderMap.get(item.folderId) : folderMap[item.folderId];
    }
    var category = String(folderName || options.defaultCategory || 'Diğer').trim() || 'Diğer';
    var fav = Boolean(item.favorite);

    var now = typeof options.now === 'number' && !isNaN(options.now) ? options.now : Date.now();
    var id = typeof options.generateId === 'function' ? options.generateId() : generateUUID();
    if (!id || typeof id !== 'string') id = generateUUID();

    return {
      id: id,
      title: title,
      site: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      note: notes,
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
   * Convert a single Fuin item/entry object to a normalized Fuin vault entry.
   * Defensively sanitizes null, undefined, or missing values for all fields.
   * @param {object} e Raw Fuin entry object.
   * @param {object} [options] Custom options.
   * @returns {object|null} Normalized entry or null if invalid (missing title or password).
   */
  function fuinItemToEntry(e, options) {
    if (!e || typeof e !== 'object') return null;

    options = options || {};
    var title = String(e.site || e.title || '').trim();
    var password = e.password != null ? String(e.password) : '';
    var url = String(e.url || '').trim();

    if (!title && url) {
      try {
        title = new URL(url).hostname || url;
      } catch (_) {
        title = url;
      }
    }

    if (!title || !password) return null;

    var username = (e.username != null ? String(e.username) : '').trim();
    var notes = String(e.note != null ? e.note : (e.notes != null ? e.notes : ''));
    var totp = (e.totp != null ? String(e.totp) : '').trim();
    var category = String(e.category || options.defaultCategory || 'Diğer').trim() || 'Diğer';
    var fav = Boolean(e.fav);
    var isDeleted = Boolean(e.isDeleted);
    var d = e.deletedAt != null ? Number(e.deletedAt) : null;
    var deletedAt = (typeof d === 'number' && !isNaN(d) && d > 0) ? d : null;

    var now = typeof options.now === 'number' && !isNaN(options.now) ? options.now : Date.now();
    var c = Number(e.created || e.createdAt);
    var created = !isNaN(c) && c > 0 ? c : now;
    var u = Number(e.updated || e.updatedAt);
    var updated = !isNaN(u) && u > 0 ? u : now;

    var id = (e.id && typeof e.id === 'string' && e.id.length >= 10)
      ? e.id
      : (typeof options.generateId === 'function' ? options.generateId() : generateUUID());
    if (!id || typeof id !== 'string') id = generateUUID();

    return {
      id: id,
      title: title,
      site: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      note: notes,
      totp: totp,
      category: category,
      fav: fav,
      isDeleted: isDeleted,
      deletedAt: deletedAt,
      created: created,
      createdAt: created,
      updated: updated,
      updatedAt: updated
    };
  }

  /**
   * Parse Bitwarden JSON export.
   * @param {object} parsed JSON object.
   * @param {object} [options] Import options.
   * @returns {{ entries: object[], categories: string[] }}
   */
  function importBitwardenJSON(parsed, options) {
    if (!parsed || typeof parsed !== 'object') {
      throw new Error('Geçersiz Bitwarden JSON verisi');
    }

    if (parsed.encrypted === true) {
      throw new Error('Bitwarden şifreli JSON dışa aktarımı desteklenmemektedir. Lütfen Bitwarden üzerinden şifrelenmemiş (unencrypted) JSON veya CSV olarak aktarın.');
    }

    if (!Array.isArray(parsed.items)) {
      throw new Error('Bitwarden JSON "items" dizisi bulunamadı');
    }

    // Map folderId to folder name
    var folderMap = new Map();
    var categories = [];
    if (Array.isArray(parsed.folders)) {
      parsed.folders.forEach(function (f) {
        if (f && f.id && f.name) {
          folderMap.set(f.id, f.name);
          if (categories.indexOf(f.name) === -1) categories.push(f.name);
        }
      });
    }

    var entries = [];
    var now = Date.now();
    var entryOpts = Object.assign({}, options, { now: now });

    parsed.items.forEach(function (item) {
      var entry = bitwardenItemToEntry(item, folderMap, entryOpts);
      if (entry) {
        entries.push(entry);
      }
    });

    return { entries: entries, categories: categories };
  }

  /**
   * Parse Fuin native JSON export.
   * @param {object|Array} parsed JSON object or array.
   * @param {object} [options] Import options.
   * @returns {{ entries: object[], categories: string[] }}
   */
  function importFuinJSON(parsed, options) {
    var rawEntries = [];
    var categories = [];

    if (parsed && typeof parsed === 'object') {
      if (parsed.encrypted === true) {
        throw new Error('Bitwarden şifreli JSON dışa aktarımı desteklenmemektedir. Lütfen Bitwarden üzerinden şifrelenmemiş (unencrypted) JSON veya CSV olarak aktarın.');
      }
      if (parsed.type === 'fuin/vault') {
        rawEntries = Array.isArray(parsed.entries) ? parsed.entries : [];
        categories = Array.isArray(parsed.categories) ? parsed.categories : [];
      } else if (Array.isArray(parsed.entries)) {
        rawEntries = parsed.entries;
        categories = Array.isArray(parsed.categories) ? parsed.categories : [];
      } else if (Array.isArray(parsed)) {
        rawEntries = parsed;
      }
    }

    if (!Array.isArray(rawEntries)) {
      throw new Error('Geçersiz Fuin JSON formatı');
    }

    var now = Date.now();
    var entries = [];
    var entryOpts = Object.assign({}, options, { now: now });

    rawEntries.forEach(function (e) {
      var entry = fuinItemToEntry(e, entryOpts);
      if (entry) {
        entries.push(entry);
        if (categories.indexOf(entry.category) === -1) {
          categories.push(entry.category);
        }
      }
    });

    return { entries: entries, categories: categories };
  }

  /**
   * Unified JSON import function.
   * @param {string|object} textOrObj Raw JSON string or already parsed JSON object.
   * @param {object} [options] Import options.
   * @returns {{ format: string, entries: object[], categories: string[], count: number, skippedCount: number }}
   */
  function importJSON(textOrObj, options) {
    options = options || {};
    var parsed = textOrObj;
    if (typeof textOrObj === 'string') {
      var clean = textOrObj.charCodeAt(0) === 0xFEFF ? textOrObj.slice(1) : textOrObj;
      if (!clean.trim()) {
        return { format: 'unknown', entries: [], categories: [], count: 0, skippedCount: 0 };
      }
      parsed = JSON.parse(clean);
    }

    if (parsed && typeof parsed === 'object') {
      if (parsed.encrypted === true) {
        throw new Error('Bitwarden şifreli JSON dışa aktarımı desteklenmemektedir. Lütfen Bitwarden üzerinden şifrelenmemiş (unencrypted) JSON veya CSV olarak aktarın.');
      }
    }

    var result;
    var format = 'fuin';

    if (parsed && typeof parsed === 'object' && (parsed.items || (parsed.folders && !parsed.entries))) {
      format = 'bitwarden';
      result = importBitwardenJSON(parsed, options);
    } else {
      format = 'fuin';
      result = importFuinJSON(parsed, options);
    }

    var existingEntries = Array.isArray(options.existingEntries) ? options.existingEntries : [];
    var isDuplicate = function (candidate) {
      return existingEntries.some(function (e) {
        return e && (e.site === candidate.site || e.title === candidate.title) &&
          e.username === candidate.username &&
          e.password === candidate.password;
      });
    };

    var finalEntries = [];
    var skippedCount = 0;

    result.entries.forEach(function (e) {
      if (isDuplicate(e)) {
        skippedCount++;
      } else {
        finalEntries.push(e);
      }
    });

    return {
      format: format,
      entries: finalEntries,
      categories: result.categories,
      count: finalEntries.length,
      skippedCount: skippedCount
    };
  }

  return {
    importJSON: importJSON,
    importBitwardenJSON: importBitwardenJSON,
    importFuinJSON: importFuinJSON,
    bitwardenItemToEntry: bitwardenItemToEntry,
    fuinItemToEntry: fuinItemToEntry,
    generateUUID: generateUUID
  };
}));
