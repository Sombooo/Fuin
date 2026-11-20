# Fuin 1.0.0-Beta.12 — Sürüm Notları (Release Notes)

> **"Native Android Pano Güvenliği, Uygulama İçi Güncelleyici & Acil Durum Kiti Düzeltmeleri"**  
> *Sürüm:* `1.0.0-beta.12`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 12 Neler Getiriyor?

Fuin `v1.0.0-beta.12`, hem Masaüstü hem Fuin Mobile tarafında gerçek kullanım sorunlarını çözen kritik kararlılık ve güvenlik güncellemeleri sunar. Mobil tarafta Bitwarden / KeePassDX standardında native Android pano temizleme ve `EXTRA_IS_SENSITIVE` koruması devreye alınırken; Masaüstü tarafta uygulama içi güncelleyici `.dmg` sıfırlanma hatası, Acil Durum Kiti kurtarma anahtarı senkronizasyonu, Otomatik Yedekler kaydırma çubuğu ve Tarayıcı Eklentisi Ayarlar kartı sadeleştirmesi tamamlanır.

---

## 🛡️ Başlıca Değişiklikler ve İyileştirmeler

1. **Native Android Pano Güvenliği (`FuinMobile`):**
   - `FuinClipboardModule` ve `ClipboardClearReceiver` ile kopyalanan şifreler, kart bilgileri, TOTP kodları ve kurtarma anahtarları **`EXTRA_IS_SENSITIVE`** olarak işaretlenir (Android 13+ önizleme maskeleme & Gboard geçmiş koruması).
   - Süre dolduğunda **`AlarmManager` + `clearPrimaryClip()`** aracılığıyla uygulama arka plandayken dahi sistem panosu temizlenir.
   - `OnPrimaryClipChangedListener` sayesinde kullanıcı arada başka bir metin kopyalarsa önceki temizlik zamanlayıcısı güvenle iptal edilir; diskte hiçbir zaman açık metin saklanmaz.
   - iOS / fallback yolundaki arka plan pano okuma kaynaklı erken süre silme hatası giderildi ve kurtarma anahtarı kopyalaması `copySecure` altına alındı.

2. **Güvenilir Uygulama İçi Güncelleyici (`updateManager.js` & `main.js`):**
   - İndirme tamamlandıktan sonra **"Kurulumu Başlat"** butonuna tıklandığında indirilen `.dmg` dosyasını sıfırlayan çift `click` dinleyicisi hatası (`Disk görüntüsü açılamadı / Geçersiz değişken`) giderildi.
   - İndirmeler artık geçici `.part` dosyasına akıtılır, boyut doğrulaması yapılmadan hedef dosya üzerine yazılmaz.

3. **Acil Durum Kiti Anahtar Senkronizasyonu & Yedek Geçmişi UI:**
   - Kurtarma anahtarı yenilendiğinde, doğrulandığında veya kurtarma ile şifre sıfırlandığında anahtar **Argon2id + AES-256-GCM** zarfıyla saklanarak kilit/kilit-açma döngüleri sonrasında da Acil Durum Kitine en güncel anahtarın yazılması sağlandı.
   - Otomatik Yedekler & Geri Yükleme modalındaki kaydırma çubuğu Fuin'in warm-dark renk token'larıyla uyumlu hale getirildi ve yedek sayısı etiketi netleştirildi (`"{count} şifreli yedek hazır"`).

4. **Sadeleştirilmiş Tarayıcı Eklentisi Ayar Kartı:**
   - Chrome Web Store ve Firefox uzantı kimlikleri zaten otomatik kayıtlı olduğundan Ayarlar ekranındaki gereksiz ham ID rozetleri ve manuel geliştirici girişi kaldırıldı; yalnızca **Otomatik Hazır** durumu ve kısayol bilgisi bırakıldı.

---

## 📦 Kurulum ve Bütünlük Doğrulama

İkili kurulum paketleri (`dmg`, `exe`) ve `SHA256SUMS.txt`, sürüm derlemesi (`npm run build-mac` / `npm run build-win` + `npm run checksums`) tamamlandığında GitHub Release ekleri ile birlikte doğrulanır:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 dist/Fuin-1.0.0-beta.12-arm64.dmg
```
