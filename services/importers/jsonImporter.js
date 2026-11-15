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

  function deriveTitleFromUrl(url) {
    if (!url) return '';
    var androidMatch = String(url).match(/^android:\/\/[^@]+@([^/\s?#]+)/i);
    if (androidMatch && androidMatch[1]) {
      return androidMatch[1];
    }
    try {
      return new URL(url).hostname || url;
    } catch (_) {
      return url;
    }
  }

  function normalizeCardLastFour(cardNumber, providedLastFour) {
    if (providedLastFour) return String(providedLastFour).trim();
    var digits = String(cardNumber || '').replace(/\D/g, '');
    return digits.length >= 4 ? digits.slice(-4) : '';
  }

  function formatBitwardenExpiry(expMonth, expYear) {
    var m = expMonth != null ? String(expMonth).replace(/\D/g, '') : '';
    var y = expYear != null ? String(expYear).replace(/\D/g, '') : '';
    if (!m && !y) return '';
    if (m && y) return m.padStart(2, '0') + '/' + (y.length > 2 ? y.slice(-2) : y.padStart(2, '0'));
    return m || y;
  }

  function buildNormalizedEntry(fields, options) {
    options = options || {};
    var now = typeof options.now === 'number' && !isNaN(options.now) ? options.now : Date.now();
    var id = (fields.id && typeof fields.id === 'string' && fields.id.length >= 10)
      ? fields.id
      : (typeof options.generateId === 'function' ? options.generateId() : generateUUID());
    if (!id || typeof id !== 'string') id = generateUUID();

    var created = typeof fields.created === 'number' && !isNaN(fields.created) && fields.created > 0 ? fields.created : now;
    var updated = typeof fields.updated === 'number' && !isNaN(fields.updated) && fields.updated > 0 ? fields.updated : now;
    var notes = fields.notes != null ? String(fields.notes) : '';

    var entry = {
      id: id,
      type: fields.type || 'login',
      title: fields.title,
      site: fields.title,
      username: fields.username || '',
      password: fields.password || '',
      url: fields.url || '',
      notes: notes,
      note: notes,
      totp: fields.totp || '',
      category: fields.category,
      fav: Boolean(fields.fav),
      reprompt: Boolean(fields.reprompt),
      isDeleted: Boolean(fields.isDeleted),
      deletedAt: fields.deletedAt || null,
      created: created,
      createdAt: fields.createdAt || created,
      updated: updated,
      updatedAt: fields.updatedAt || updated
    };

    if (entry.type === 'card') {
      entry.cardholderName = fields.cardholderName || '';
      entry.cardNumber = fields.cardNumber || '';
      entry.cardExpiry = fields.cardExpiry || '';
      entry.cardCvv = fields.cardCvv || '';
      entry.cardPin = fields.cardPin || '';
      if (fields.cardBrand) entry.cardBrand = fields.cardBrand;
      var last4 = normalizeCardLastFour(entry.cardNumber, fields.cardLastFour);
      if (last4) entry.cardLastFour = last4;
    } else if (entry.type === 'note') {
      entry.secureNote = fields.secureNote != null ? String(fields.secureNote) : notes;
    }

    return entry;
  }

  /**
   * Convert a single Bitwarden item object to a normalized Fuin vault entry.
   * Supports Login (type 1), Secure Note (type 2), and Card (type 3).
   * Defensively sanitizes null, undefined, or missing values for all fields.
   * @param {object} item Bitwarden item.
   * @param {Map<string, string>|object} [folderMap] Map of folder IDs to folder names.
   * @param {object} [options] Custom options.
   * @returns {object|null} Normalized entry or null if unsupported/invalid.
   */
  function bitwardenItemToEntry(item, folderMap, options) {
    if (!item || typeof item !== 'object') return null;

    options = options || {};
    var folderName = '';
    if (item.folderId && folderMap) {
      folderName = (typeof folderMap.get === 'function') ? folderMap.get(item.folderId) : folderMap[item.folderId];
    }
    var defaultCat = options.defaultCategory || 'Diğer';
    var notes = item.notes != null ? String(item.notes) : '';
    var title = String(item.name || '').trim();
    var fav = Boolean(item.favorite);
    var reprompt = Boolean(item.reprompt);

    if (item.type === 3 && item.card && typeof item.card === 'object' && !item.login) {
      var card = item.card;
      var cardholderName = String(card.cardholderName || '').trim();
      var cardNumber = String(card.number || '').trim();
      var cardExpiry = formatBitwardenExpiry(card.expMonth, card.expYear);
      var cardCvv = String(card.code || '').trim();
      var cardPin = String(card.pin || '').trim();
      var cardBrand = String(card.brand || '').trim();
      if (!title) title = cardBrand || cardholderName;
      if (!title || !(cardNumber || cardholderName || notes)) return null;

      var cardCat = String(folderName || defaultCat).trim() || defaultCat;
      return buildNormalizedEntry({
        type: 'card',
        title: title,
        notes: notes,
        category: cardCat,
        fav: fav,
        reprompt: reprompt,
        cardholderName: cardholderName,
        cardNumber: cardNumber,
        cardExpiry: cardExpiry,
        cardCvv: cardCvv,
        cardPin: cardPin,
        cardBrand: cardBrand
      }, options);
    }

    if (item.type === 2 && !item.login) {
      if (!title || !notes) return null;
      var noteCat = String(folderName || defaultCat).trim() || defaultCat;
      return buildNormalizedEntry({
        type: 'note',
        title: title,
        notes: notes,
        secureNote: notes,
        category: noteCat,
        fav: fav,
        reprompt: reprompt
      }, options);
    }

    var login = item.login;
    if (!login || typeof login !== 'object') return null;

    var password = login.password != null ? String(login.password) : '';
    var firstUri = Array.isArray(login.uris) && login.uris.length > 0 ? login.uris[0] : null;
    var rawUrl = (firstUri && typeof firstUri === 'object') ? firstUri.uri : (typeof firstUri === 'string' ? firstUri : '');
    var url = String(rawUrl || '').trim();

    if (!title && url) {
      title = deriveTitleFromUrl(url);
    }

    if (!title || !password) return null;

    var username = (login.username != null ? String(login.username) : '').trim();
    var totp = (login.totp != null ? String(login.totp) : '').trim();
    var category = String(folderName || defaultCat).trim() || defaultCat;

    return buildNormalizedEntry({
      type: 'login',
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      totp: totp,
      category: category,
      fav: fav,
      reprompt: reprompt
    }, options);
  }

  /**
   * Convert a single Fuin item/entry object to a normalized Fuin vault entry.
   * Preserves login, card, and secure note entries without dropping card/note items.
   * Defensively sanitizes null, undefined, or missing values for all fields.
   * @param {object} e Raw Fuin entry object.
   * @param {object} [options] Custom options.
   * @returns {object|null} Normalized entry or null if invalid.
   */
  function fuinItemToEntry(e, options) {
    if (!e || typeof e !== 'object') return null;

    options = options || {};
    var defaultCat = options.defaultCategory || 'Diğer';
    var rawType = String(e.type || '').trim().toLowerCase();
    var entryType = (rawType === 'card' || rawType === 'note' || rawType === 'login')
      ? rawType
      : (e.cardNumber ? 'card' : (e.secureNote !== undefined && !e.password ? 'note' : 'login'));

    var title = String(e.site || e.title || '').trim();
    var notes = String(e.note != null ? e.note : (e.notes != null ? e.notes : ''));
    var category = String(e.category || defaultCat).trim() || defaultCat;
    var fav = Boolean(e.fav);
    var reprompt = Boolean(e.reprompt);
    var isDeleted = Boolean(e.isDeleted);
    var d = e.deletedAt != null ? Number(e.deletedAt) : null;
    var deletedAt = (typeof d === 'number' && !isNaN(d) && d > 0) ? d : null;
    var c = Number(e.created || e.createdAt);
    var created = !isNaN(c) && c > 0 ? c : undefined;
    var u = Number(e.updated || e.updatedAt);
    var updated = !isNaN(u) && u > 0 ? u : undefined;

    if (entryType === 'card') {
      var cardholderName = String(e.cardholderName || e.username || '').trim();
      var cardNumber = String(e.cardNumber || '').trim();
      var cardExpiry = String(e.cardExpiry || '').trim();
      var cardCvv = String(e.cardCvv || '').trim();
      var cardPin = String(e.cardPin || '').trim();
      var cardBrand = String(e.cardBrand || '').trim();
      if (!title) title = cardBrand || cardholderName;
      if (!title || !(cardNumber || cardholderName || cardExpiry || cardCvv || cardPin || notes)) return null;

      return buildNormalizedEntry({
        id: e.id,
        type: 'card',
        title: title,
        notes: notes,
        category: category,
        fav: fav,
        reprompt: reprompt,
        isDeleted: isDeleted,
        deletedAt: deletedAt,
        created: created,
        updated: updated,
        cardholderName: cardholderName,
        cardNumber: cardNumber,
        cardExpiry: cardExpiry,
        cardCvv: cardCvv,
        cardPin: cardPin,
        cardBrand: cardBrand,
        cardLastFour: e.cardLastFour
      }, options);
    }

    if (entryType === 'note') {
      var secureNote = e.secureNote != null ? String(e.secureNote) : notes;
      if (!title || !secureNote) return null;

      return buildNormalizedEntry({
        id: e.id,
        type: 'note',
        title: title,
        notes: notes || secureNote,
        secureNote: secureNote,
        category: category,
        fav: fav,
        reprompt: reprompt,
        isDeleted: isDeleted,
        deletedAt: deletedAt,
        created: created,
        updated: updated
      }, options);
    }

    var password = e.password != null ? String(e.password) : '';
    var url = String(e.url || '').trim();

    if (!title && url) {
      title = deriveTitleFromUrl(url);
    }

    if (!title || !password) return null;

    var username = (e.username != null ? String(e.username) : '').trim();
    var totp = (e.totp != null ? String(e.totp) : '').trim();

    return buildNormalizedEntry({
      id: e.id,
      type: 'login',
      title: title,
      username: username,
      password: password,
      url: url,
      notes: notes,
      totp: totp,
      category: category,
      fav: fav,
      reprompt: reprompt,
      isDeleted: isDeleted,
      deletedAt: deletedAt,
      created: created,
      updated: updated
    }, options);
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
      var candType = candidate.type || 'login';
      return existingEntries.some(function (e) {
        if (!e || e.isDeleted) return false;
        var eType = e.type || 'login';
        if (eType !== candType) return false;
        if (e.site !== candidate.site && e.title !== candidate.title) return false;
        if (candType === 'card') {
          var eNum = String(e.cardNumber || '').replace(/[\s-]/g, '');
          var cNum = String(candidate.cardNumber || '').replace(/[\s-]/g, '');
          return eNum === cNum && (e.cardholderName || '') === (candidate.cardholderName || '');
        }
        if (candType === 'note') {
          var eNote = e.secureNote != null ? String(e.secureNote) : String(e.note || e.notes || '');
          var cNote = candidate.secureNote != null ? String(candidate.secureNote) : String(candidate.note || candidate.notes || '');
          return eNote === cNote;
        }
        return (e.username || '') === (candidate.username || '') &&
          (e.password || '') === (candidate.password || '');
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
