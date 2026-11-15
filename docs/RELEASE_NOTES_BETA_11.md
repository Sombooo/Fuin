# Fuin 1.0.0-Beta.11 — Sürüm Notları (Release Notes)

> **"2FA QR Tarayıcı, Eklenti Protokol Kontrolü & Kart/Not Kopyalama ve Taşınabilir Yedek Eşliği"**  
> *Sürüm:* `1.0.0-beta.11`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 11 Neler Getiriyor?

Fuin `v1.0.0-beta.11`, masaüstü, tarayıcı eklentisi ve Fuin Mobile ekosistemini bir araya getiren kritik kullanım ve güvenlik iyileştirmelerini sunar. Tarayıcı eklentisi ile Native Host arasında zorunlu protokol sürüm kontrolü devreye alınırken, eklenti açılır penceresi artık sıfır-bilgi mimarisinde **Kredi Kartı** ve **Şifreli Güvenli Not** kopyalamayı destekler. Mobil tarafta tam ekran **2FA `otpauth://` QR kamera tarayıcı**, canlı **30 sn TOTP sayacı**, tek adım biyometrik kilit açma, çapraz uyumlu `.fuin` kasa yedekleme ve kurumsal/yurt Wi-Fi ağları için **AP İzolasyonu (Hotspot)** rehberliği sunulur.

---

## 🛡️ Başlıca Değişiklikler ve İyileştirmeler

1. **Native Host ↔ Tarayıcı Eklentisi Protokol Kontrolü & Kart/Not Kopyalama:**
   - Native Messaging köprüsünde `PROTOCOL_VERSION = 1` zorunlu el sıkışması (handshake) ile sürüm uyumsuzlukları erken yakalanır.
   - Eklenti açılır penceresine **Girişler**, **Kartlar** ve **Notlar** sekmeleri eklendi (`popup.html` / `popup.js`).
   - Kart numarası, CVV ve güvenli notlar tarayıcı eklentisi belleğine ham olarak indirilmeden masaüstü üzerinden **30 saniyede otomatik temizlenen** panoya kopyalanır; `reprompt` korumalı kayıtlar sessiz kopyalamaya kapatılır.
   - Eklenti arayüzü sistem diline göre tam **TR/EN** yerelleştirme kazanır.

2. **Evrensel 2FA QR (`otpauth://`) & Taşınabilir `.fuin` / CSV / JSON Aktarım:**
   - `otpauth://totp/...` URI ayrıştırma motoru (`totpEngine.js`) masaüstü ve mobil arasında eşitlendi.
   - Bitwarden, 1Password, LastPass ve Chrome CSV/JSON içe aktarma motorları kart ve güvenli not tiplerini destekleyecek şekilde genişletildi (`services/importers/`).
   - Argon2id ve PBKDF2-SHA512 KDF başlıkları ile şifreli `.fuin` yedekleri masaüstü ve mobil arasında doğrudan taşınabilir hale getirildi.

3. **Fuin Mobile 2FA QR Tarayıcı, Canlı TOTP & Tek Adım Biyometrik Kilit:**
   - Android tam ekran QR kamera düzenindeki siyah ekran ve odak retikülü hizalama hatası çözüldü.
   - 2FA kayıtları için kart üzerinde canlı 30 saniyelik TOTP kodu ve geri sayım çubuğu eklendi.
   - Uygulama kilidi açılışındaki çift biyometrik doğrulama istemi tek pürüzsüz adıma indirildi.

4. **Yerel Ağ Eşitlemesinde AP İzolasyonu (Hotspot) Rehberliği:**
   - Kurumsal veya öğrenci yurdu Wi-Fi ağlarında AP İzolasyonu nedeniyle cihazların birbirini göremediği durumlar için masaüstü LAN Sync penceresine, zaman aşımı bildirimine ve mobil eşleştirme/hata diyaloglarına Kişisel Erişim Noktası (Hotspot) ipucu eklendi.

---

## 📦 Kurulum ve Bütünlük Doğrulama

İkili kurulum paketleri (`dmg`, `exe`) ve `SHA256SUMS.txt`, sürüm derlemesi (`npm run build-mac` / `npm run build-win` + `npm run checksums`) tamamlandığında GitHub Release ekleri ile birlikte doğrulanır:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 dist/Fuin-1.0.0-beta.11-arm64.dmg
```
