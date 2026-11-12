# Fuin 1.0.0-Beta.10 — Sürüm Notları (Release Notes)

> **"Kredi Kartı & Güvenli Not Kasası, Otomatik Formatlama ve Kurumsal Güvenlik Denetimi"**  
> *Sürüm:* `1.0.0-beta.10`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 10 Neler Getiriyor?

Fuin `v1.0.0-beta.10`, kasa deneyimini genişleterek **Kredi Kartı** ve **Şifreli Güvenli Not** kasa türlerini sisteme dahil eder. Kart numaraları için akıllı 4'lü gruplama (`0000 0000 0000 0000`), son kullanma tarihi (`AA/YY`) ve CVV maskelemesi ile kart markası (Visa, Mastercard, Troy vb.) otomatik tanınır. Açık pencerelerde dinamik TR/EN anlık dil geçişi, iyileştirilmiş 2FA arayüz düzeni ve kurumsal seviye siber güvenlik ve sızıntı denetimi doğrulaması sunar.

---

## 🛡️ Başlıca Değişiklikler ve İyileştirmeler

1. **Kredi Kartı Kasası & Akıllı Otomatik Formatlama:**
   - Kart numarası girilirken anlık 4'lü gruplama, AA/YY son kullanma tarihi ve 3-4 haneli CVV otomatik formatlanır.
   - Kart markası (Visa, Mastercard, Troy, Amex) yerel regex ile otomatik tespit edilir.
   - Kart numarası ve CVV için tek tıkla güvenli panoya kopyalama butonları (`copy-card-num`, `copy-cvv`) eklendi.

2. **AES-256-GCM Şifreli Güvenli Notlar (Secure Notes):**
   - Sunucu şifreleri, kurtarma kodları, gizli notlar veya hassas metinler için sıfır bilgi mimarisinde güvenli not saklama ve kopyalama desteği sunuldu.

3. **Dinamik Çoklu Dil Eşliği (i18n Parity) ve Arayüz İyileştirmeleri:**
   - Kart veya Not ekleme/düzenleme modalı açıkken dil değiştirildiğinde (TR/EN) alanların anında yerelleşmesi sağlandı.
   - Kart sahibi alanı için tarafsız ve profesyonel `"İsim Soyisim"` (TR) / `"First & Last Name"` (EN) yer tutucusu uygulandı.
   - İki Faktörlü Doğrulama (2FA) üst ayırıcı çizgi boşluğu flexbox ile ferahlatıldı.
   - Ayarlar panelindeki Güvenlik Bilgisi kartı tam genişlik düzenine kavuşturuldu; kilit ekranındaki Touch ID butonunun kenarlığı (`border: none`) kuralına uygun hale getirildi.

4. **Kurumsal Seviye Kapsamlı Güvenlik Denetimi & Depo Hijyeni:**
   - AST regex tarayıcısı ile tüm depolarda anahtar ve token sızıntısı taraması yapıldı (0 sızıntı doğrulandı).
   - Tüm `.DS_Store` kalıntıları temizlendi, electron-builder paketinde gereksiz 10 MB promo video installer dışına çıkarıldı.
   - 29 Desktop ve 10 Mobile test paketi ile sıfır regresyon garantilendi.

---

## 📦 Kurulum ve Dosya Doğrulama

| Platform | Dosya | Mimari | SHA-256 |
|---|---|---|---|
| **macOS** | `Fuin-1.0.0-beta.10-arm64.dmg` | Apple Silicon (M1/M2/M3/M4) | `093e85889900620119291a5fb4dc2e0d57c6881296ab0101919e81bc4e4d7365` |
| **Windows** | `Fuin Setup 1.0.0-beta.10.exe` | Windows 10 / 11 (64-bit) | `1c9c8b1f09a4ec3f8007d7144c9daea69a800849fb0f6ede00c6f7805a70ffed` |
| **Bütünlük** | `SHA256SUMS.txt` | Checksum Doğrulama | — |

İndirdiğiniz kurulum dosyasının bütünlüğünü doğrulamak için:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 Fuin-1.0.0-beta.10-arm64.dmg
```
