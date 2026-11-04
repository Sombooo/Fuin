# Fuin 1.0.0-Beta.7 — Sürüm Notları (Release Notes)

> **"AGPLv3 Resmi Lisansı, Uygulama İçi Güncelleme Yönetimi, Eklenti v1.0.1 ve Dokunsal Arayüz İyileştirmeleri"**  
> *Sürüm:* `1.0.0-beta.7`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 7 Neler Getiriyor?

Fuin Desktop `v1.0.0-beta.7`, resmi proje lisansını tam metin **GNU Affero General Public License Version 3 (AGPL-3.0)** standardına taşırken; uygulama içinden otomatik güncelleme denetimi/yükleyici başlatıcısı, tarayıcı eklentisinde `v1.0.1` derin güvenlik sıkılaştırması ve gelişmiş şifre üreticide pürüzsüz dokunsal arayüz geçişleri sunar.

---

## 🛡️ Başlıca Değişiklikler ve Güvenlik İyileştirmeleri

1. **Resmi AGPLv3 Lisansına Geçiş:**
   - Projenin özgür yazılım mirasını ve kullanıcı gizliliğini korumak amacıyla resmi GNU AGPL-3.0 tam lisans metni projeye dahil edildi ve `package.json` standardına bağlandı.

2. **Uygulama İçi Güncelleme Denetimi & İndirici:**
   - **Kullanıcı Kontrollü Ağ İsteği:** Ayarlar > Sistem altına *"Açılışta Güncellemeleri Denetle"* seçeneği eklendi. Kullanıcı istediğinde bu isteği tamamen kapatabilir.
   - **Tek Tıkla Doğrudan İndirme:** Yeni sürüm tespit edildiğinde harici tarayıcıya gitmeye gerek kalmadan DMG / EXE dosyası uygulama içinden güvenle indirilip kurulum başlatılabilir.

3. **Tarayıcı Eklentisi (v1.0.1) Güvenlik & Bellek Sıkılaştırması:**
   - **RAM Zeroization & Form Temizliği:** Kayıt istemi reddedildiğinde veya gönderildiğinde arabellekteki kullanıcı adı ve şifre değişkenleri anında bellekten sıfırlanır (`userInput.value = ''; pwInput.value = '';`).
   - **Çok Katmanlı CSP & Sender Güvenliği:** Eklenti sayfalarına sıkı `Content-Security-Policy` meta etiketleri ve arka planda `sender.id !== chrome.runtime.id` muhafızı eklendi.
   - Mozilla `addons-linter` ile 0 hata / 0 uyarı ile tam onaylandı.

4. **Gelişmiş Şifre Üretici & Dokunsal Arayüz İyileştirmesi:**
   - Şifre üretici modalındaki "ŞİFREYİ KULLAN" butonu, köşelerdeki boşluk ve kavis uyumsuzlukları giderilerek modal tabanına jilet gibi sıfır (`border-radius: 0 0 3px 3px`) oturtuldu.
   - Gezinme çubuğu ve buton geçişlerine 120ms dokunsal mikro-geçiş standardı (`transition: all .12s;`) tanımlandı.

5. **Exhaustive Security Verification:**
   - 21/21 masaüstü güvenlik, kriptografik KAT, WAL dayanıklılığı, LAN P2P senkronizasyon ve eklenti testi %100 başarıyla geçti.

---

## 📦 Kurulum ve Dosya Doğrulama

İndirdiğiniz kurulum dosyasının bütünlüğünü doğrulamak için terminalde çalıştırın:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 Fuin-1.0.0-beta.7-arm64.dmg
```
