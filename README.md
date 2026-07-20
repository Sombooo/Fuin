# ⬡ KEKKAI — Şifre Yöneticisi

## Kurulum

```bash
npm install
npm start
```

## Güvenlik Mimarisi

| Katman              | Teknoloji                        | Açıklama                              |
|---------------------|----------------------------------|---------------------------------------|
| Anahtar Türetme     | Argon2id (64MB RAM, 3 iter)      | Brute force'a karşı en güçlü KDF      |
| Şifreleme           | AES-256-GCM                      | Authenticated encryption              |
| RAM Zeroing         | Node.js Buffer.fill(0)           | Anahtar bellekten gerçekten silinir   |
| Timing Attack       | crypto.timingSafeEqual()         | Sabit zamanlı karşılaştırma           |
| Entropi Analizi     | zxcvbn                           | Gerçek tahmin bazlı güç analizi       |
| Sızıntı Kontrolü   | HaveIBeenPwned k-Anonymity       | Şifre internete gönderilmez           |

## Build

```bash
npm run build-mac    # macOS .dmg
npm run build-win    # Windows .exe
npm run build-linux  # Linux .AppImage
```
