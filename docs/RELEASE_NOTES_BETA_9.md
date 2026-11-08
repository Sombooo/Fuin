# Fuin 1.0.0-Beta.9 — Sürüm Notları (Release Notes)

> **"SHA-256 Yedek Geçmişi, Kurtarma Anahtarı Doğrulama & Acil Durum Kiti Yenilemesi"**  
> *Sürüm:* `1.0.0-beta.9`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 9 Neler Getiriyor?

Fuin `v1.0.0-beta.9`, sunucusuz ve %100 çevrimdışı kurtarma mimarisini bir üst seviyeye taşır. Otomatik ve manuel kasa yedeklerini SHA-256 bütünlük imzasıyla takip eden **Yedek Geçmişi**, tek tıkla geçmiş yedeğe dönme, taşınabilir şifreli `.fuin` kasa yedeği, **Kurtarma Anahtarı Kendi Kendine Doğrulama (Self-Test)** aracı ve Fuin'in sıcak organik tasarım sistemine uygun olarak baştan tasarlanan **Acil Durum Kiti** sunar.

---

## 🛡️ Başlıca Değişiklikler ve İyileştirmeler

1. **SHA-256 Bütünlük Doğrulamalı Yedek Geçmişi & Anlık Geri Yükleme:**
   - Otomatik ve manuel yedekler `fuin.backup-log.json` içinde SHA-256 özetiyle kaydedilir ve yinelenen kayıtlar otomatik ayıklanır.
   - Ayarlar > Otomatik Yedekler üzerinden yedek geçmişi incelenebilir ve tek tıkla güvenli geri yükleme yapılabilir.

2. **Kurtarma Anahtarı Doğrulama (Self-Test) & Şifreli `.fuin` Yedeği:**
   - Kasanızı sıfırlamaya gerek kalmadan Kurtarma Anahtarınızın doğruluğunu çevrimdışı test edebilirsiniz.
   - Kasanızı Argon2id + AES-256-GCM ile şifrelenmiş taşınabilir `.fuin` yedek dosyası olarak dışa ve içe aktarabilirsiniz.

3. **Warm Dark & Warm Paper Acil Durum Kiti Tasarımı:**
   - Dışa aktarılan Acil Durum Kiti HTML belgesi, Fuin'in sıcak koyu (`#1a1816`) ve sıcak kağıt (`#f5f0e8`) paletine, resmi altıgen logosuna, açık/koyu tema değiştiricisine, A4 baskı düzenine ve sıkı çevrimdışı CSP kurallarına kavuşturuldu.

4. **Derin Güvenlik Sertleştirmesi (`SEC-01`..`SEC-05`):**
   - Yedek IPC uçlarında kilitli kasa koruması (`isUnlocked`) ve `fs.lstatSync` sembolik bağ (symlink) reddi zorunlu kılındı.
   - Tarayıcı eklentisinde reddedilen/kaydedilen şifrelerin bellekte düz metin tutulması engellenerek oturum bazlı tek yönlü özet (`hashDismissedKey`) mimarisine geçildi.
   - Kasa kilitlendiğinde (`lock()`) tüm bekleyen doğrulama closure'ları ve hassas modal DOM düğümleri temizlenir.

---

## 📦 Kurulum ve Dosya Doğrulama

İndirdiğiniz kurulum dosyasının bütünlüğünü doğrulamak için:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 Fuin-1.0.0-beta.9-arm64.dmg
```
