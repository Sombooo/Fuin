# Fuin 1.0.0-Beta.6 — Sürüm Notları (Release Notes)

> **"Akıllı Otomatik Doldurma, Güçlendirilmiş Eklenti Köprüsü ve API Sınır Güvenliği"**  
> *Sürüm:* `1.0.0-beta.6`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 6 Neler Getiriyor?

Fuin Desktop `v1.0.0-beta.6`, tarayıcı eklentisi otomatik doldurma ve kayıt yakalama akışını Bitwarden/1Password seviyesinde pürüzsüzleştirirken; Native Messaging köprüsü, harici API sınırları (GitHub Releases & HIBP k-Anonymity) ve Ana Şifre Yeniden Doğrulama (`reprompt`) katmanlarını derinlemesine sıkılaştırır.

---

## 🛡️ Güvenlik ve Otomatik Doldurma İyileştirmeleri

1. **Bitwarden Seviyesi Otomatik Doldurma ve Kayıt Yakalama:**
   - **İki Adımlı (Split-Login) ve SPA Desteği:** E-posta ve şifrenin ayrı adımlarda girildiği veya özel butonlarla gönderildiği modern giriş formlarında (`chess.com`, Google vb.) kullanıcı adı ve şifre kayıpsız yakalanır.
   - **Kapalı Shadow DOM Kayıt Bildirimi:** Sayfa yönlendirmesi sonrasında dahi aynı site izolasyonu (`isSameSiteSafe`) korunarak güvenli, kapalı Shadow DOM üzerinden kaydetme/güncelleme bildirimi sunulur.
   - **Zenginleştirilmiş Eklenti Penceresi ve Kısayol (`Cmd+Shift+L` / `Ctrl+Shift+L`):** Tek tuşla doldurma, 30 saniye süreli güvenli pano kopyalama ve uygulama içi Chrome eklenti kimliği tanımlama eklendi.

2. **Native Messaging Köprüsü ve Yerel IPC Sıkılaştırması:**
   - **HMAC Tabanlı Windows Named Pipe Koruması:** Windows'ta sabit pipe adı yerine kullanıcı token'ından türetilen HMAC-SHA256 pipe yolu kullanılarak yerel pipe-squatting saldırıları engellendi.
   - **Sıkı İzin ve Bellek Sınırları:** POSIX soket ve token dosyalarında `0o600` izin ve UID sahiplik doğrulaması, 1 MB mesaj tavanı ve bekleyen IPC kuyruğu sınırı devreye alındı.
   - **Multi-Tenant Alan Adı İzolasyonu:** `github.io`, `vercel.app`, `pages.dev`, `netlify.app` gibi paylaşımlı platformlarda alt alan adı genişletmesi engellendi; `sender.frameId === 0` ile alt çerçeve (iframe) oltalama istekleri reddedildi.

3. **Harici API ve Kasa Güvenliği İyileştirmeleri (21/21 Test Paketi, 0 Hata):**
   - **Sıkı API Sınırları:** GitHub sürüm denetimi ve HIBP sızıntı taramasında 8 saniyelik `AbortController` zaman aşımı, `redirect: 'error'` ile açık yönlendirme engeli ve resmi `https://github.com/Sombooo/Fuin/` URL doğrulaması zorunlu kılındı.
   - **TOTP Reprompt ve Acil Durum Kiti Koruması:** `reprompt` korumalı kayıtlarda 2FA (TOTP) görüntüleme öncesi Ana Şifre doğrulaması zorunlu hale getirildi; Acil Durum Kiti HTML çıktısında tam XSS kaçışı (`safeEsc`) sağlandı ve gelişmiş şifre üretici kopyalaması 30 saniyelik güvenli panoya bağlandı.

---

## 📦 Kurulum ve Dosya Doğrulama

İndirdiğiniz kurulum dosyasının bütünlüğünü doğrulamak için terminalde çalıştırın:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol
shasum -a 256 Fuin-1.0.0-beta.6-arm64.dmg
```

---

## 💬 Geri Bildirim ve Katkı

- **Güvenlik İletişimi:** `hellofuin@gmail.com`
- **Kaynak Kod:** [github.com/Sombooo/Fuin](https://github.com/Sombooo/Fuin)
