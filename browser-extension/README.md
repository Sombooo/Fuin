# Fuin Tarayıcı Eklentisi — Kurulum (Geliştirme Aşaması)

Bu eklenti henüz Chrome Web Store'a yüklenmedi, "paketlenmemiş öğe"
olarak yüklenmesi gerekiyor.

## 1. Eklentiyi tarayıcıya yükle

1. `chrome://extensions` (Brave/Edge'de de aynı yol) adresine git
2. Sağ üstten **Geliştirici Modu**'nu aç
3. **Paketlenmemiş öğe yükle** → bu `browser-extension/` klasörünü seç
4. Sayfada eklentinin altında görünen **ID**'yi kopyala (örn. `abcdefgh...`)

## 2. Native messaging host'u kaydet

Terminalde `native-host/` klasörüne gidip:

```bash
node install-host.js --chrome-id=BURAYA_KOPYALADIGIN_ID
```

Bu komut, tarayıcının bu eklentiyle `host.js`'i çalıştırmasına izin
veren manifest dosyalarını doğru klasörlere yazar (Chrome/Edge/Brave
otomatik kapsanır).

## 3. Test et

1. Fuin masaüstü uygulamasını aç, kilidini aç
2. Herhangi bir sitede (kayıtlı bir hesabın varsa) şifre alanının
   sağındaki **⬡** ikonuna tıkla
3. Eşleşen kayıt(lar) listelenmeli, seçince form dolmalı

## Sorun giderme

- **"Fuin çalışmıyor"**: Fuin uygulamasının açık olduğundan emin ol.
- **"Fuin kilitli"**: Uygulamayı kilit ekranından aç.
- Hâlâ çalışmıyorsa: `node install-host.js` çıktısındaki dosya
  yollarının gerçekten oluştuğunu kontrol et, tarayıcıyı tamamen
  kapatıp yeniden aç (native messaging host'lar tarayıcı başlangıcında
  önbelleğe alınır).

## Bilinen sınırlamalar (v1)

- Native host, sistemde kurulu bir Node.js'e bağımlı (`host.js`
  doğrudan çalıştırılıyor). Dağıtım öncesi bunu `pkg`/`nexe` ile
  bağımsız bir binary'e çevirmek gerekir.
- Firefox desteği kod olarak hazır (`install-host.js --firefox-id=...`)
  ama `manifest.json`'a henüz `browser_specific_settings.gecko.id`
  eklenmedi — Firefox'ta yüklemeden önce bunu ekle.
- Token tabanlı yetkilendirme, "aynı makinedeki başka bir process"
  tehdidine karşı tam koruma sağlamaz (bkz. `main.js` içindeki güvenlik
  notu). Üretime geçmeden önce bu katmanın güçlendirilmesi önerilir.
