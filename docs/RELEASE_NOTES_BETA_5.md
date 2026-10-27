# Fuin 1.0.0-Beta.5 — Sürüm Notları (Release Notes)

> **"En Kararlı, Bağımsız Denetlenmiş ve Sessizce Güvenli Beta"**  
> *Sürüm:* `1.0.0-beta.5`  
> *Yayın Tarihi:* Ekim 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 5 Neden Önemli?

Fuin Beta 5, yalnızca yeni özelliklerin eklendiği bir sürüm değil; uygulamanın temellerinin bağımsız endüstri standartlarında (Cloudflare Security Audit ilkeleri, RFC 9116 ve NIST SP 800-38D) test edilip onaylandığı en olgun ara sürümdür.

Kullanıcılarımızın bize "güvenmesini" beklemiyoruz; denetlenebilir, şeffaf ve matematiksel olarak doğrulanabilir bir güvenlik modeli sunuyoruz.

---

## 🛡️ Güvenlik ve Kriptografi İyileştirmeleri

1. **Bağımsız Adversarial Güvenlik Denetim Paketi (20/20 Test Paketi, 290+ Test, 0 Hata):**
   - **Prototype Pollution Savunması:** Dışarıdan içe aktarılan hiçbir JSON veya CSV dosyası (`__proto__`, `constructor`) JavaScript prototiplerini kirletemez.
   - **IPC ve Protokol İzolasyonu:** Electron `preload.js` köprüsü üzerinden işletim sistemi kabuğuna veya yetkisiz protokollere (`file:`, `javascript:`, `ms-msdt:`, `data:`) sızıntı yapılması kesin olarak engellendi.
   - **HMAC Korumalı Kilitlenme Durumu:** Yanlış parola denemelerindeki bekleme süresi, disk üzerinde HMAC-SHA256 ile imzalanarak saklanır. Dosyayı silmek veya değiştirmek kasayı otomatik güvenli kilit durumuna alır.
   - **AEAD Bit-Değiştirme Koruması:** Disk üzerindeki şifreli kasada tek bir bit dahi değiştirilirse işlem sessizce çökmek yerine doğrulamayı derhal durdurur ve sıfır veri sızdırır.

2. **Cihaz Eşleme ve Yerel Ağ (LAN P2P) Ayrımı:**
   - **QR Kod:** Yalnızca tek seferlik ilk cihaz eşleştirmesinde (`pairKey`) kullanılır.
   - **Senkronizasyon:** Kasa verileri hiçbir zaman optik video/QR ile aktarılmaz; doğrudan ev Wi-Fi ağınız veya telefonunuzun kişisel erişim noktası (hotspot) üzerinden **XChaCha20-Poly1305** ile şifrelenerek P2P aktarılır.
   - 120 saniyelik geçici port ömrü, kasa kilitlendiğinde anında kapanma ve RFC1918 özel IP jailing güvenceye alındı.

3. **Üretim Seviyesinde Ekran Koruması:**
   - Masaüstü pencerelerinde `setContentProtection(true)`, mobilde `FLAG_SECURE` varsayılan olarak devrededir. Ekran kaydı veya yetkisiz pencere yakalama uygulamaları kasanızı kaydedemez.

4. **Resmi Güvenlik Standartları ve İletişim:**
   - **RFC 9116 `security.txt`:** Bağımsız güvenlik araştırmacıları için `/.well-known/security.txt` ve `SECURITY.md` yayınlandı.
   - **Fuin Tehdit Modeli Dokümanı:** [docs/SECURITY_MODEL.md](file:///Users/kadir/Fuin/docs/SECURITY_MODEL.md) adresinde neyi koruduğumuzu ve varsayımlarımızı şeffafça ilan ettik.

---

## 🚀 Geliştirici ve CI Altyapısı

- **GitHub Actions Security CI:** Her kod değişikliğinde (push ve PR) tüm güvenlik, NIST KAT ve P2P testleri otomatik çalışır.
- **Haftalık Dependabot Taraması:** Bağımlılıklardaki güvenlik açıkları haftalık olarak otomatik taranır.
- **Şeffaf İkili Doğrulama (SHA256SUMS.txt):** Yayınlanan her derleme `.dmg`, `.exe` ve `.apk` paketi için SHA-256 sağlama toplamları yayınlanır.

---

## 📦 Kurulum ve Dosya Doğrulama

İndirdiğiniz dosyanın orijinal ve değiştirilmemiş olduğunu doğrulamak için terminalde çalıştırın:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol
shasum -a 256 Fuin-1.0.0-beta.5-arm64.dmg
```

---

## 💬 Geri Bildirim ve Katkı

- **Güvenlik İletişimi:** `hellofuin@gmail.com`
- **Kaynak Kod:** [github.com/Sombooo/Fuin](https://github.com/Sombooo/Fuin)
