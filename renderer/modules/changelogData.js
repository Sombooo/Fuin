// ═══════════════════════════════════════════════════════════════════
// FUIN CHANGELOG DATA
// renderer/modules/changelogData.js
// 100% Offline, static release notes catalog for Fuin ecosystem.
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  const CHANGELOG_ENTRIES = [
    {
      version: '1.0.0-beta.7',
      tag: 'v1.0.0-beta.7',
      date: 'Kasım 2026',
      dateEn: 'November 2026',
      isCurrent: true,
      title: 'Resmi AGPLv3 Lisansı, Uygulama İçi Güncelleme & Dokunsal Arayüz',
      titleEn: 'Official AGPLv3 License, In-App Update Management & Tactile UI',
      summary: "Fuin'in sıfır-bulut felsefesini tam metin GNU AGPL-3.0 standardına taşırken; tek tıkla güncelleme indirici, tarayıcı eklentisi v1.0.2 güvenliği ve dokunsal arayüz mikro-geçişleri sunar.",
      summaryEn: 'Transfers Fuin to the official GNU AGPL-3.0 open-source standard with in-app direct updater, browser extension v1.0.2 hardening, and 120ms tactile UI transitions.',
      highlights: [
        {
          badge: 'license',
          badgeText: 'LİSANS',
          badgeTextEn: 'LICENSE',
          icon: 'scroll',
          title: 'Resmi GNU AGPL-3.0 Lisansı',
          titleEn: 'Official GNU AGPL-3.0 License',
          desc: 'Projenin açık kaynak mirasını ve kullanıcı gizliliğini korumak amacıyla tam resmi GNU AGPLv3 lisansına geçildi ve package.json standartlarına bağlandı.',
          descEn: 'Adopted full official GNU Affero GPLv3 to preserve permanent open-source user rights and zero-knowledge privacy.'
        },
        {
          badge: 'update',
          badgeText: 'GÜNCELLEME',
          badgeTextEn: 'UPDATE',
          icon: 'download-cloud',
          title: 'Uygulama İçi Doğrudan Güncelleme & İndirici',
          titleEn: 'In-App Direct Update & Downloader',
          desc: 'Ayarlar > Sistem altına açılışta güncelleme denetimi açma/kapama seçeneği eklendi. Yeni sürüm çıktığında harici tarayıcıya gitmeden DMG/EXE/APK tek tıkla indirilip kurulabilir.',
          descEn: 'Settings toggle for automatic startup update checks with direct one-click DMG/EXE downloading and installer launching from within the app.'
        },
        {
          badge: 'extension',
          badgeText: 'EKLENTİ',
          badgeTextEn: 'EXTENSION',
          icon: 'puzzle',
          title: 'Tarayıcı Eklentisi (v1.0.2) Dayanıklılığı & Paritesi',
          titleEn: 'Browser Extension (v1.0.2) Resilience & Parity',
          desc: 'Firefox Promise API tam uyumluluğu, kayıt istemi reddedildiğinde RAM/form sıfırlaması, sıkı Content-Security-Policy ve sender.id izolasyon muhafızları getirildi.',
          descEn: 'Full Firefox Promise API compatibility, RAM/form zeroization upon dismiss, strict CSP, and top-frame sender.id isolation guards.'
        },
        {
          badge: 'ui',
          badgeText: 'ARAYÜZ',
          badgeTextEn: 'UI / UX',
          icon: 'sliders',
          title: 'Dokunsal Arayüz & Şifre Üretici Buton Cilalaması',
          titleEn: 'Tactile Micro-Transitions & Generator UI Polish',
          desc: 'Gelişmiş şifre üretici modalındaki buton tabana sıfır (border-radius: 0 0 3px 3px) oturtuldu ve tüm gezinme menülerine 120ms dokunsal mikro-geçiş standardı tanımlandı.',
          descEn: 'Flush button alignment in password generator modal with snappy 120ms micro-transitions across all interactive sidebar and button controls.'
        },
        {
          badge: 'security',
          badgeText: 'GÜVENLİK',
          badgeTextEn: 'SECURITY',
          icon: 'shield-check',
          title: '21/21 Kapsamlı Güvenlik Testi Doğrulaması',
          titleEn: '21/21 Exhaustive Security Verification',
          desc: 'NIST KAT vektörleri, Argon2id KDF, WAL veri dayanıklılığı ve LAN P2P senkronizasyon test paketleri %100 başarıyla onaylandı.',
          descEn: 'Cryptographic KATs, Argon2id KDF bounds, WAL crash durability, and LAN P2P pairing suites verified with zero regressions.'
        }
      ]
    },
    {
      version: '1.0.0-beta.6',
      tag: 'v1.0.0-beta.6',
      date: 'Kasım 2026',
      dateEn: 'November 2026',
      isCurrent: false,
      title: 'Yerel Android Autofill & Doğrulanmış APK Güncelleyici',
      titleEn: 'Native Android Autofill & Verified APK Self-Updater',
      summary: 'Tam yerel Android AutofillService ile donanım destekli Android Keystore AES-256-GCM zarfı, ters-domain ve phishing koruması, doğrulanmış APK self-updater ve WAL veri dayanıklılığı.',
      summaryEn: 'Hardware-backed Android Keystore AES-256-GCM envelope storage, reverse-domain phishing defenses, verified in-app APK self-updater, and WAL crash durability.',
      highlights: [
        {
          badge: 'mobile',
          badgeText: 'MOBİL',
          badgeTextEn: 'MOBILE',
          icon: 'smartphone',
          title: 'Yerel Android Autofill Servisi',
          titleEn: 'Native Android AutofillService',
          desc: 'Android Keystore AES-256-GCM donanım zarfı ile Chrome ve mobil uygulamalarda tek dokunuşla otomatik doldurma ve şifre kaydetme desteği.',
          descEn: 'Hardware-backed Android Keystore AES-256-GCM envelope storage with seamless autofill and credential save across Chrome and mobile apps.'
        },
        {
          badge: 'security',
          badgeText: 'GÜVENLİK',
          badgeTextEn: 'SECURITY',
          icon: 'shield',
          title: 'Ters-Domain ve Phishing Engelleme',
          titleEn: 'Reverse-Domain & Phishing Guard',
          desc: 'Kimlik bilgisi sızdırmaya çalışan sahte paket adları ve @-userinfo phishing saldırılarına karşı akıllı alan adı eşleştirici geliştirildi.',
          descEn: 'Heuristic domain matcher preventing package-name spoofing and userinfo-based phishing attempts.'
        },
        {
          badge: 'update',
          badgeText: 'GÜNCELLEME',
          badgeTextEn: 'UPDATE',
          icon: 'package',
          title: 'Doğrulanmış Uygulama İçi APK Güncelleyici',
          titleEn: 'Verified In-App APK Self-Updater',
          desc: 'GitHub Releases üzerinden SHA-256 sağlama toplamı, X.509 APK sertifika doğrulaması ve sürüm düşürme (anti-downgrade) koruması.',
          descEn: 'Direct in-app APK downloads with streaming SHA-256 checksum and anti-downgrade verification.'
        },
        {
          badge: 'storage',
          badgeText: 'DEPOLAMA',
          badgeTextEn: 'STORAGE',
          icon: 'database',
          title: 'WAL (Write-Ahead Logging) ve Çökme İzolasyonu',
          titleEn: 'Write-Ahead Log (WAL) Durability',
          desc: 'Beklenmeyen güç kesintisi veya işletim sistemi kapanmalarında kasa verisinin bozulmasını önleyen atomik yazma mimarisi.',
          descEn: 'Atomic crash-resilient persistence ensuring zero data corruption during unexpected system power loss.'
        }
      ]
    },
    {
      version: '1.0.0-beta.5',
      tag: 'v1.0.0-beta.5',
      date: 'Ekim 2026',
      dateEn: 'October 2026',
      isCurrent: false,
      title: 'NIST KAT Standartları & P2P Yerel Ağ Eşitlemesi',
      titleEn: 'NIST KAT Standards & LAN P2P Sync',
      summary: 'NIST SP 800-38D AES-GCM standart test vektörleri, tek seferlik optik QR cihaz eşleştirmesi, yerel ağ senkronizasyonu ve kilit ekranı RAM sıfırlama güvenliği.',
      summaryEn: 'Validated against NIST SP 800-38D test vectors, one-time optical QR pairing, direct LAN encrypted sync, and in-memory RAM zeroization.',
      highlights: [
        {
          badge: 'crypto',
          badgeText: 'KRİPTO',
          badgeTextEn: 'CRYPTO',
          icon: 'key',
          title: 'NIST SP 800-38D AES-GCM KAT Testleri',
          titleEn: 'NIST SP 800-38D Known Answer Tests',
          desc: 'Resmi NIST kriptografik test vektörleri ve 10.000 CSPRNG nonce çakışmasızlık doğrulaması eksiksiz onaylandı.',
          descEn: 'Validated against NIST SP 800-38D standard test vectors with 10,000 CSPRNG collision-free IV generations.'
        },
        {
          badge: 'sync',
          badgeText: 'EŞİTLEME',
          badgeTextEn: 'SYNC',
          icon: 'wifi',
          title: 'Hava Boşluklu QR & LAN Eşitlemesi',
          titleEn: 'Air-Gapped QR & Direct LAN Sync',
          desc: 'Cihazlar arası tek seferlik optik QR eşleştirme ve yerel ağ (Wi-Fi/Hotspot) üzerinden uçtan uca şifreli doğrudan kasa senkronizasyonu.',
          descEn: 'One-time optical QR pairing followed by direct LAN/Hotspot encrypted vault sync without third-party servers.'
        },
        {
          badge: 'security',
          badgeText: 'GÜVENLİK',
          badgeTextEn: 'SECURITY',
          icon: 'lock',
          title: 'RAM Bellek Sıfırlama (Zeroization)',
          titleEn: 'In-Memory RAM Zeroization',
          desc: 'Kasa kilitlendiğinde geçici oturum anahtarları ve şifre değişkenleri RAM arabelleğinden kalıcı olarak temizlenir.',
          descEn: 'Ephemeral session keys and credentials wiped from memory immediately upon vault lock to prevent RAM dumping.'
        }
      ]
    }
  ];

  window.FuinChangelog = {
    CHANGELOG_ENTRIES,
    getLatestEntry() {
      return CHANGELOG_ENTRIES[0];
    },
    getEntryByVersion(ver) {
      if (!ver) return CHANGELOG_ENTRIES[0];
      const clean = String(ver).trim().replace(/^v/i, '');
      return CHANGELOG_ENTRIES.find(e => e.version === clean) || CHANGELOG_ENTRIES[0];
    }
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = window.FuinChangelog;
  }
})(typeof window !== 'undefined' ? window : globalThis);
