/**
 * ═══════════════════════════════════════════════════════════════════════════════
 * FUIN IMPORT SERVICE: index.js
 *
 * Unified entry point for all password vault importers:
 * - detectFormat(text) -> string
 * - detectFormatDetails(text) -> object
 * - parseCSV(text) -> string[][]
 * - importFromText(text, options) -> { format, type, entries, count, skippedCount }
 * - importCSV(text, options)
 * - importJSON(textOrObj, options)
 * - importEntries(content, format, options) -> VaultEntry[] (matches PROJECT.md interface contract)
 * ═══════════════════════════════════════════════════════════════════════════════
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define(['./detector', './csvImporter', './jsonImporter'], factory);
  } else if (typeof module === 'object' && module.exports) {
    var detector = require('./detector');
    var csv = require('./csvImporter');
    var json = require('./jsonImporter');
    module.exports = factory(detector, csv, json);
  } else {
    var detector = (root.FuinImporters && root.FuinImporters.detector) || (typeof require === 'function' ? require('./detector') : null);
    var csv = (root.FuinImporters && root.FuinImporters.csv) || (typeof require === 'function' ? require('./csvImporter') : null);
    var json = (root.FuinImporters && root.FuinImporters.json) || (typeof require === 'function' ? require('./jsonImporter') : null);
    root.FuinImporters = factory(detector, csv, json);
  }
}(typeof self !== 'undefined' ? self : typeof globalThis !== 'undefined' ? globalThis : this, function (detector, csv, json) {
  'use strict';

  if (!detector && typeof require === 'function') detector = require('./detector');
  if (!csv && typeof require === 'function') csv = require('./csvImporter');
  if (!json && typeof require === 'function') json = require('./jsonImporter');

  /**
   * Import credentials directly from raw text, auto-detecting format and serialization.
   * @param {string} text Raw CSV or JSON file contents.
   * @param {object} [options] Import configuration.
   * @param {string} [options.format] Optional format override ('bitwarden', 'lastpass', '1password', 'chrome', 'fuin').
   * @param {Array} [options.existingEntries] Current vault entries for deduplication.
   * @param {string} [options.defaultCategory='Diğer'] Default category for entries.
   * @returns {{ format: string, type: 'csv'|'json', entries: object[], count: number, skippedCount: number }}
   */
  function importFromText(text, options) {
    options = options || {};
    if (typeof text !== 'string' || !text.trim()) {
      return { format: 'unknown', type: 'csv', entries: [], count: 0, skippedCount: 0 };
    }

    var details = detector.detectFormatDetails(text);
    if (details.isEncrypted) {
      throw new Error('Bitwarden şifreli JSON dışa aktarımı desteklenmemektedir. Lütfen Bitwarden üzerinden şifrelenmemiş (unencrypted) JSON veya CSV olarak aktarın.');
    }

    if (details.type === 'json') {
      var resJson = json.importJSON(text, options);
      return {
        format: resJson.format,
        type: 'json',
        entries: resJson.entries,
        categories: resJson.categories,
        count: resJson.count,
        skippedCount: resJson.skippedCount
      };
    }

    // CSV Path
    var targetFormat = options.format || details.format;
    var resCsv = csv.importCSV(text, Object.assign({}, options, { format: targetFormat }));
    return {
      format: resCsv.format,
      type: 'csv',
      entries: resCsv.entries,
      totalRows: resCsv.totalRows,
      count: resCsv.count,
      skippedCount: resCsv.skippedCount
    };
  }

  /**
   * Pure array return contract matching PROJECT.md interface contract:
   * importEntries(content, format) -> Array<VaultEntry>
   * @param {string} content Raw text content.
   * @param {string} [format] Optional format name.
   * @param {object} [options] Deduplication and category options.
   * @returns {object[]} Array of normalized VaultEntry objects.
   */
  function importEntries(content, format, options) {
    var opts = Object.assign({}, options);
    if (format && format !== 'auto') opts.format = format;
    var result = importFromText(content, opts);
    return result.entries;
  }

  return {
    // Detection
    detectFormat: detector ? detector.detectFormat : null,
    detectFormatDetails: detector ? detector.detectFormatDetails : null,

    // Parsers
    parseCSV: csv ? csv.parseCSV : null,
    buildColMap: csv ? csv.buildColMap : null,
    csvRowToEntry: csv ? csv.csvRowToEntry : null,

    // High-level importers
    importFromText: importFromText,
    importCSV: csv ? csv.importCSV : null,
    importJSON: json ? json.importJSON : null,
    importEntries: importEntries,

    // Submodules
    detector: detector,
    csv: csv,
    json: json
  };
}));
