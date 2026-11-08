// ═══════════════════════════════════════════════════════════════════
// FUIN CHANGELOG DATA
// renderer/modules/changelogData.js
// 100% Offline, static release notes catalog for Fuin ecosystem.
// ═══════════════════════════════════════════════════════════════════

(function(window) {
  'use strict';

  const CHANGELOG_ENTRIES = [
    {
      version: '1.0.0-beta.9',
      tag: 'v1.0.0-beta.9',
      date: 'Kasım 2026',
      dateEn: 'November 2026',
      isCurrent: true,
      title: 'SHA-256 Yedek Geçmişi, Kurtarma Anahtarı Doğrulama & Acil Durum Kiti Yenilemesi',
      titleEn: 'SHA-256 Backup History, Recovery Key Self-Test & Emergency Kit Redesign',
      summary: 'SHA-256 bütünlük doğrulamalı kasa yedek günlüğü, anlık yedek geri yükleme, şifreli .fuin yedeği, Kurtarma Anahtarı kendi kendine doğrulama (Self-Test) ve yenilenen çevrimdışı Acil Durum Kiti sunar.',
      summaryEn: 'Introduces SHA-256 integrity-verified backup history, point-in-time snapshot restore, encrypted .fuin vault backups, Recovery Key self-verification, and a redesigned offline Emergency Kit.',
      highlights: [
        {
          badge: 'storage',
          badgeText: 'YEDEKLEME',
          badgeTextEn: 'BACKUP & WAL',
          icon: 'database',
          title: 'SHA-256 Yedek Geçmişi & Anlık Geri Yükleme',
          titleEn: 'SHA-256 Backup History & Point-in-Time Restore',
          desc: 'Otomatik ve manuel kasa yedekleri SHA-256 bütünlük imzasıyla kaydedilir; Ayarlar > Otomatik Yedekler üzerinden tek tıkla doğrulanıp geri yüklenebilir.',
          descEn: 'Automatic and manual vault snapshots are tracked with SHA-256 integrity verification and one-click point-in-time restore.'
        },
        {
          badge: 'crypto',
          badgeText: 'KURTARMA',
          badgeTextEn: 'RECOVERY',
          icon: 'key',
          title: 'Kurtarma Anahtarı Doğrulama (Self-Test) & .fuin Yedeği',
          titleEn: 'Recovery Key Self-Test & Encrypted .fuin Backup',
          desc: 'Kurtarma anahtarınızı kasanızı sıfırlamadan çevrimdışı test edebilir ve kasanızı Argon2id + AES-256-GCM şifreli .fuin dosyası olarak dışa/içe aktarabilirsiniz.',
          descEn: 'Verify your Recovery Key offline without resetting your vault, and export/import portable Argon2id + AES-256-GCM encrypted .fuin backups.'
        },
        {
          badge: 'ui',
          badgeText: 'ACİL DURUM KİTİ',
          badgeTextEn: 'EMERGENCY KIT',
          icon: 'scroll',
          title: 'Warm Dark & Warm Paper Acil Durum Kiti Tasarımı',
          titleEn: 'Warm Dark & Warm Paper Emergency Kit Redesign',
          desc: 'Acil Durum Kiti HTML çıktısı Fuin renk paleti, resmi altıgen logo, açık/koyu tema geçişi, A4 baskı optimizasyonu ve sıkı çevrimdışı CSP ile yenilendi.',
          descEn: 'Redesigned Emergency Kit HTML with Fuin warm palette, official flat-top hexagon logo, light/dark toggle, A4 print layout, and strict offline CSP.'
        },
        {
          badge: 'security',
          badgeText: 'GÜVENLİK',
          badgeTextEn: 'SECURITY',
          icon: 'shield-check',
          title: 'Derin Güvenlik Sertleştirmesi & Eklenti Bellek Korunumu',
          titleEn: 'Deep Security Hardening & Extension Memory Scrubbing',
          desc: 'Yedek IPC kilit doğrulaması, lstatSync sembolik bağ koruması, tarayıcı eklentisinde tohumlu özet (keyed digest) ve kilitlenmede tam DOM/closure temizliği eklendi.',
          descEn: 'Enforced unlocked-vault guard and lstatSync symlink rejection on backup IPCs, keyed digests in extension memory, and full DOM/closure scrubbing on lock.'
        }
      ]
    },
    {
      version: '1.0.0-beta.8',
      tag: 'v1.0.0-beta.8',
      date: 'Kasım 2026',
      dateEn: 'November 2026',
      isCurrent: false,
      title: "Neler Yeni (What's New) Modalı, Dinamik Dil Senkronizasyonu & Gelişmiş UI Cilalaması",
      titleEn: "What's New Modal, Reactive Dynamic i18n Sync & UI Refinement",
      summary: "Kullanıcıların en son güncellemeleri ve güvenlik iyileştirmelerini çevrimdışı inceleyebileceği 'Neler Yeni?' yama modalı, yeniden başlatma gerektirmeyen anlık reaktif dil senkronizasyonu ve sadeleştirilmiş dikkatsiz-tasarım arayüzü sunar.",
      summaryEn: "Introduces an offline-first 'What's New?' changelog modal, instant dynamic multi-language reactivity without application restart, and distraction-free centered action layouts.",
      highlights: [
        {
          badge: 'ui',
          badgeText: 'ARAYÜZ',
          badgeTextEn: 'UI / UX',
          icon: 'scroll',
          title: "Çevrimdışı 'Neler Yeni?' ve Yama Notları Gezgini",
          titleEn: "Offline 'What's New?' & Release Navigator",
          desc: "Ayarlar ve kasa açılışında en son sürüm değişikliklerini, güvenlik iyileştirmelerini ve özelliklerini gösteren sıcak organik koyu temalı sürüm gezgini eklendi.",
          descEn: "Integrated a warm organic dark release explorer showing latest features, security enhancements, and changelog history directly within the vault."
        },
        {
          badge: 'ui',
          badgeText: 'DİL & i18N',
          badgeTextEn: 'i18N / SYNC',
          icon: 'sliders',
          title: 'Anlık Reaktif Çoklu Dil (TR / EN) Senkronizasyonu',
          titleEn: 'Instant Reactive Multi-Language (TR / EN) Parity',
          desc: "Dinamik arayüz bileşenleri için onLanguageChanged reaktif kancası tanımlandı; dil değiştiğinde modallar, rozetler ve sürüm sekmeleri yeniden başlatmaya gerek kalmadan anında çevrilir.",
          descEn: "Reactive onLanguageChanged hook for dynamic components ensuring tabs, badges, and modals translate immediately upon language toggle without app restart."
        },
        {
          badge: 'ui',
          badgeText: 'SADELİK',
          badgeTextEn: 'CLEAN UX',
          icon: 'lock',
          title: 'Sakin ve Odaklı Modal Mimarisi (Quietly Secure)',
          titleEn: 'Calm & Centered Action Hierarchy',
          desc: "Aksiyon modallarındaki gereksiz alt sloganlar ve yinelenen linkler kaldırıldı; onay butonları tam odaklı, ortalanmış ve konforlu genişliğe (max 360px) kavuşturuldu.",
          descEn: "Removed repetitive marketing slogans from modal footers; action buttons are now prominently centered, comfortably wide, and free of visual noise."
        },
        {
          badge: 'security',
          badgeText: 'GÜVENLİK',
          badgeTextEn: 'SECURITY',
          icon: 'shield-check',
          title: 'Kapsamlı Karşıt Güvenlik & Regresyon Doğrulaması',
          titleEn: 'Exhaustive Adversarial Security Verification',
          desc: "41 statik kontrol ve 22/22 masaüstü güvenlik paketi (NIST KAT, WAL çökme dayanıklılığı, IPC izolasyonu, RFC1918 kısıtı) sıfır regresyonla doğrulandı.",
          descEn: "Verified 41 static checks and 22/22 desktop security suites (NIST KATs, WAL crash durability, IPC isolation, RFC1918 constraints) with zero regressions."
        }
      ]
    },
    {
      version: '1.0.0-beta.7',
      tag: 'v1.0.0-beta.7',
      date: 'Kasım 2026',
      dateEn: 'November 2026',
      isCurrent: false,
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
