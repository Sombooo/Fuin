# Fuin 1.0.0-Beta.8 — Sürüm Notları (Release Notes)

> **"Neler Yeni (What's New) Modalı, Dinamik Dil Senkronizasyonu & Gelişmiş UI Cilalaması"**  
> *Sürüm:* `1.0.0-beta.8`  
> *Yayın Tarihi:* Kasım 2026  
> *Mimari Standart:* Sıfır Bulut, Çevrimdışı-Öncelikli, P2P Eşitleme  

---

## 🌟 Beta 8 Neler Getiriyor?

Fuin `v1.0.0-beta.8`, kullanıcıların son sürümlerdeki güncellemeleri, özellikleri ve güvenlik iyileştirmelerini doğrudan kasa içinden çevrimdışı inceleyebileceği **"Neler Yeni?"** yama notları gezginini sunar. Ayrıca uygulama yeniden başlatılmasına gerek kalmadan anında çalışan reaktif çoklu dil (TR/EN) senkronizasyonu ve dikkat dağıtmayan, ortalanmış sakin arayüz mimarisi getirir.

---

## 🛡️ Başlıca Değişiklikler ve İyileştirmeler

1. **Çevrimdışı "Neler Yeni?" & Yama Notları Modalı:**
   - Ayarlar > Sistem bölümüne ve kasa açılışına entegre edilen sıcak organik koyu temalı sürüm gezgini.
   - Sürümler arası anında geçiş sağlayan üst sekme çubuğu, detaylı öne çıkanlar ve güvenlik etiketleri.

2. **Reaktif Çoklu Dil (i18n) Senkronizasyonu:**
   - `onLanguageChanged` kancası ile dil değiştirildiğinde (TR ⟷ EN) modallar, dinamik rozetler ve sürüm sekmeleri anında çevrilir.
   - Sistem güncellemeleri ve ayarlar başlıklarındaki tüm ham anahtarlar ve durum mesajları yerelleştirildi.

3. **Sakin ve Odaklı Modal Mimarisi (Quietly Secure):**
   - Modal altlarındaki gereksiz pazarlama sloganları ve yinelenen linkler temizlendi.
   - Aksiyon ve kapatma butonları tam odaklı, ortalanmış ve konforlu genişliğe (max 360px) kavuşturuldu.
   - Mobil modallarda iOS Home Indicator ve Android navigasyon çubuğu için platforma uyarlanan alt boşluk standardı tanımlandı.

4. **Kapsamlı Güvenlik & Regresyon Doğrulaması:**
   - 41 statik kontrol ve 22/22 masaüstü güvenlik paketi; 27 mobil kontrol ve 10/10 mobil test paketi %100 başarıyla ve sıfır regresyonla tamamlandı.

---

## 📦 Kurulum ve Dosya Doğrulama

İndirdiğiniz kurulum dosyasının bütünlüğünü doğrulamak için:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# veya tekil kontrol (macOS)
shasum -a 256 Fuin-1.0.0-beta.8-arm64.dmg
```
