# FUIN SYNC PROTOCOL V2 — FINAL SPECIFICATION

**Document Version:** 2.0.0  
**Status:** Implementation-Ready  
**Replaces:** SYNC_PROTOCOL V1

Bu doküman, FUIN Sync V2 mimarisinin byte-level deterministik ve implementasyona hazır teknik spesifikasyonudur.
V1 spesifikasyonundaki şu kritik mimari problemler bu versiyonda çözülmüştür:
- AAD içinde raw binary + pipe-separator karışımı (parser ambiguity)
- `last_sync_hash` global zinciri multi-device desteğini bozuyordu
- "deterministic nonce" çelişkisi (nonce CSPRNG ile üretilir, deterministic değildir)
- Binary payload layout'ta ciphertext length implicit bırakılmıştı
- Argon2id salt boyutu tutarsızlığı (16B spec vs 32B kod)
- Mobile yerel değişiklik uyarısı mekanizması tanımsızdı

---

## 1. KAPSAM VE YÖN SINIRI

**V2 Protokolü kesinlikle TEK YÖNLÜDÜR: Desktop → Mobile.**

```
Desktop Vault (Authoritative Source)
        │
        ├──► Mobile A
        ├──► Mobile B
        └──► Mobile C
```

- Mobile → Desktop yönünde aktarım V2 kapsamında YOKTUR.
- Bidirectional sync, conflict resolution, merge mekanizmaları V3 veya sonrasına bırakılmıştır.
- Desktop her zaman authoritative source'tur.
- Mobile'da yapılan local Add/Edit/Delete Mobile local vault'unu değiştirir, ancak Desktop'a geri sync edilmez.

---

## 2. THREAT MODEL

### 2.1 Saldırı Vektörleri

| # | Saldırı | Açıklama | Savunma Mekanizması |
|---|---------|----------|---------------------|
| T1 | Shoulder Surfing / CCTV | QR kodları kamera ile kaydedilir | Tüm payload XChaCha20-Poly1305 ile şifrelenir |
| T2 | Replay — Full Session | Kayıtlı QR seti cihaza yeniden okutulur | `generation` + `snapshotHash` zincir doğrulaması |
| T3 | Replay — Partial/Stale | Eski nesil payload tekrar gönderilir | `lastAcceptedGeneration` karşılaştırması |
| T4 | Chunk Silme | Saldırgan bir chunk'u düşürür | `TOTAL_CHUNKS` tamamlanmadan vault'a yazılmaz |
| T5 | Chunk Değiştirme | QR içindeki byte değiştirilir | AEAD Auth Tag doğrulaması tüm payload'ı reddeder |
| T6 | Chunk Yeniden Sıralama | Chunk'lar farklı sırayla okutulur | Index tabanlı assembly, sıra bağımsız çalışır |
| T7 | Yeni Chunk Ekleme | Sahte chunk eklenerek payload bozulur | AEAD Auth Tag doğrulaması patlayacaktır |
| T8 | Metadata Tahrifatı | QR header alanları (version, sessionId) değiştirilir | AAD imzalar bu alanları; değişiklik Auth Tag'i bozar |
| T9 | Farklı Session Karıştırma | Farklı oturumların chunk'ları birbirine sokulur | `sessionId` eşleşmesi zorunludur |
| T10 | Cihaz Ele Geçirme | Mobile fiziksel olarak ele geçirilir | Hardware-bound local vault encryption devreye girer |
| T11 | Yanlış Parola | Saldırgan şifre dener | Argon2id yavaşlığı + AEAD immediate fail |

### 2.2 Kapsam Dışı Tehditler

- Mobile işletim sistemi veya donanımının root'lanması bu protokolün sorumluluğu değildir.
- Kullanıcının kendi cihazında keylogger çalışması bu protokolün kapsam dışındadır.
- Sync Password'ün sosyal mühendislikle ele geçirilmesi protokol katmanında engellenemez.

---

## 3. SECURITY BOUNDARIES

İki güvenlik alanı kesin olarak ayrılmıştır ve birbirine karıştırılmamalıdır.

```
┌─────────────────────────────────────────────────────────────────┐
│                    LOCAL VAULT SECURITY                         │
│                                                                 │
│  Vault Password (Master Password)                               │
│  Vault KDF (PBKDF2-SHA512 veya Argon2id, implementasyona özel) │
│  machineId / hardware fingerprint                               │
│  OS Keychain / Secure Enclave / DPAPI / Android Keystore        │
│  Local disk encryption                                          │
└─────────────────────────────────────────────────────────────────┘
                             ≠ (TAMAMEN AYRI) ≠
┌─────────────────────────────────────────────────────────────────┐
│                  AIR-GAPPED SYNC SECURITY                       │
│                                                                 │
│  Sync Password                                                  │
│  Argon2id (m=65536, t=3, p=4, len=32)                          │
│  Sync Key (DEK)                                                 │
│  XChaCha20-Poly1305                                             │
│  sessionId / generation / snapshotHash                          │
│  QR chunk CRC32 + AEAD Auth Tag                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 3.1 Vault Password vs Sync Password

- **Vault Password:** Local vault'u açmak için kullanılır. Desktop'ın mevcut encryption altyapısıyla işlenir. Protokolün dışındadır.
- **Sync Password:** Yalnızca Air-Gapped Sync payload'ını şifrelemek ve çözmek için kullanılır. Sync Key derivation'ın tek insan-kaynaklı girdisidir.
- **Kural:** Sync Key derivation içinde Vault Password kullanılmaz. Bu kural, kullanıcının her iki şifre için aynı string'i seçmesi durumunda bile bozulmaz; mimari olarak ayrı derivation path'leri kullanılır.

### 3.2 Hardware Independence (Donanım Bağımsızlığı)

Sync encryption'a aşağıdakiler dahil EDİLEMEZ:

- machineId
- hardware fingerprint
- OS-specific encryption key
- safeStorage / DPAPI / macOS Keychain / Secure Enclave / Android Keystore material
- TPM material
- cihaz UUID'si
- diğer cihaz-spesifik secret'lar

Desktop, Vault'u kendi hardware-bound mekanizmasıyla bellekte açar. Açılmış plaintext veri yalnızca Sync Password ile türetilen donanım bağımsız Sync Key kullanılarak şifrelenir ve QR olarak aktarılır.

---

## 4. KEY DERIVATION

### 4.1 Algoritma ve Parametreler

```
Algorithm:    Argon2id
Memory (m):   65536 KiB  (64 MiB)
Iterations (t): 3
Parallelism (p): 4
Output Length: 32 bytes
Salt Length:  16 bytes
```

Bu parametreler V2 protokolünde sabittir. Cihaz performansına, OS türüne veya başka herhangi bir runtime koşuluna göre değiştirilemez.

### 4.2 Domain Separation

Sync Key, Vault Key derivation'dan domain separation ile ayrılır. Salt'a sabit bir domain prefix eklenerek aynı şifrenin iki farklı bağlamda farklı key üretmesi garanti edilir.

```
effective_salt = salt_16B || UTF8("FUIN_SYNC_V2")
Sync Key = Argon2id(
    password = UTF8(SyncPassword),
    salt     = effective_salt,       // 16 + 12 = 28 bytes toplam
    m        = 65536,
    t        = 3,
    p        = 4,
    tagLen   = 32
)
```

- `salt_16B`: CSPRNG ile üretilen 16 byte
- `"FUIN_SYNC_V2"`: 12 byte sabit ASCII string (domain tag)
- `effective_salt` toplam uzunluğu: 28 bytes

**Not:** Argon2id implementasyonları salt için minimum uzunluk gereksinimi duyabilir. 16 byte + 12 byte domain tag = 28 byte bu gereksinimi karşılar.

### 4.3 Desteklenen Cross-Platform Senaryolar

Aşağıdaki senaryoların tamamında, doğru Sync Password bilindiği sürece aynı Sync Key türetilir:

```
Desktop Windows  →  Mobile Android
Desktop macOS    →  Mobile iOS
Desktop Linux    →  Mobile Android
Desktop A        →  Mobile A
Desktop A        →  Mobile B   (farklı cihaz, aynı key)
```

---

## 5. ENCRYPTION

### 5.1 Algoritma

```
Algorithm:          XChaCha20-Poly1305
Key:                32 bytes  (Argon2id çıktısı)
Nonce:              24 bytes  (CSPRNG, her sync işlemi için benzersiz)
Authentication Tag: 16 bytes  (Poly1305 çıktısı)
```

### 5.2 Nonce Üretimi

Nonce her encryption işleminde CSPRNG ile üretilir. Nonce **deterministik değildir**. "Deterministic nonce" ifadesi V2 protokolünde kullanılmaz.

Nonce benzersizliği güvenlik gereksinimidir. Aynı Key + Nonce kombinasyonu ikinci kez kullanılmamalıdır. CSPRNG üretimi bu riski ihmal edilebilir düzeye indirir (2^192 uzayında çakışma olasılığı).

### 5.3 Encryption Output Format

XChaCha20-Poly1305 encryption çıktısı iki parçadır:

```
ciphertext:  N bytes  (plaintext ile eşit uzunlukta, N = compressed_plaintext.length)
auth_tag:    16 bytes (Poly1305 MAC)
```

Wire format'ta bu iki alan **bitişik olarak** aşağıdaki sırayla yerleştirilir:

```
[ciphertext (N bytes)][auth_tag (16 bytes)]
```

Toplam şifrelenmiş blob uzunluğu: `N + 16` bytes.

Implementasyon notu: libsodium `crypto_aead_xchacha20poly1305_ietf_encrypt` bu iki alanı tek buffer olarak döndürür. Bu durum spesifikasyonla uyumludur.

### 5.4 AAD (Additional Authenticated Data)

AAD, metadata'nın kriptografik olarak imzalanmasını sağlar. AAD üzerindeki herhangi bir değişiklik Auth Tag doğrulamasını bozar.

#### AAD Canonical Binary Format

AAD tamamen binary olarak aşağıdaki sırayla birleştirilir. String/binary karışımı YOKTUR. Pipe separator YOKTUR.

```
Field 1: protocol_version_byte   — 1 byte,  uint8, Big-Endian
                                   V2 için değer: 0x02
Field 2: session_id              — 8 bytes, raw bytes (hex string değil, ham byte)
Field 3: salt                    — 16 bytes, raw bytes (KDF'e verilen ham salt)
```

**Toplam AAD uzunluğu: 25 bytes (sabit)**

```
AAD = [0x02][session_id (8B)][salt (16B)]
       ^     ^                ^
       1B    8B               16B
```

Bu format, her platformda (Node.js, Swift, Kotlin) `Buffer.concat` veya `ByteArray.plus` kullanılarak aynen üretilmedir. UTF-8 coercion, string encoding veya separator yorumlama farkı oluşmaz.

---

## 6. SERIALIZATION VE COMPRESSION

### 6.1 Serialization

```
Format: CBOR (RFC 8949)
```

CBOR Canonical Encoding kuralları (deterministic map serialization):
- Map key'leri length-first sözlük (lexicographic) sırasına göre sıralanır.
- Integer değerler minimum byte representation kullanılır.
- Gereksiz tag'ler kullanılmaz.
- Text string'ler UTF-8 olarak encode edilir.
- Byte string'ler `bstr` (major type 2) olarak encode edilir.

Desktop ve Mobile, aynı plaintext struct için byte-level aynı CBOR çıktısı üretmek ZORUNDADIR.

### 6.2 Compression

```
Format: zstd (Zstandard)
Level:  3  (default, deterministik)
```

Compression level sabit 3'tür. Implementasyona göre değiştirilemez.

### 6.3 Processing Pipeline

```
Vault Plaintext Data (RAM)
        │
        ▼
Canonical CBOR Serialization
        │
        ▼
zstd Compression (level=3)
        │
        ▼
XChaCha20-Poly1305 Encryption
        │
        ▼
Encrypted Sync Payload
        │
        ▼
QR Chunking (Base45)
```

---

## 7. PAYLOAD FORMAT

### 7.1 CBOR Plaintext İç Yapısı

Şifrelenmeden önce canonical CBOR olarak serileştirilecek plaintext struct:

| Alan Adı | CBOR Tipi | Uzunluk / Format | Açıklama | Zorunlu |
|----------|-----------|-----------------|----------|---------|
| `protocol_version` | uint | uint8 | Sync protokol versiyonu. V2=2 | Zorunlu |
| `payload_version` | uint | uint8 | Şifreli zarf içi veri yapısı versiyonu. V2=1 | Zorunlu |
| `vault_schema_version` | uint | uint8 | Vault nesne şeması versiyonu | Zorunlu |
| `session_id` | bstr | 8 bytes | CSPRNG üretimi raw bytes | Zorunlu |
| `timestamp` | uint | uint64, Big-Endian | UTC Epoch, saniye cinsinden | Zorunlu |
| `generation` | uint | uint64 | Desktop snapshot sayacı (0'dan başlar) | Zorunlu |
| `snapshot_hash` | bstr | 32 bytes | SHA-256 hash'i (açıklama: Bölüm 8) | Zorunlu |
| `entries` | array | CBOR array | Vault entry'lerinin CBOR dizisi | Zorunlu |

### 7.2 Binary Wire Format (Outer Envelope)

Şifrelenmiş Sync Payload'ının byte-level layout'u:

```
Offset      Length      Field
────────────────────────────────────────────────────────────
0           2           header_magic     — 0x46 0x53 ("FS")
2           1           wire_version     — 0x02 (uint8, V2)
3           16          salt             — KDF salt (raw bytes)
19          24          nonce            — XChaCha20 nonce (raw bytes)
43          N           ciphertext       — zstd(CBOR(plaintext)) şifrelenmiş
43+N        16          auth_tag         — Poly1305 authentication tag
────────────────────────────────────────────────────────────
Toplam: 43 + N + 16 = N + 59 bytes
```

**Ciphertext uzunluğu (N) hesaplama:**  
`N = total_payload_length - 59`  
Veya: `N = file_size - 59` (streaming olmayan implementasyonlar için)

`auth_tag` her zaman son 16 byte'tır.

---

## 8. STATE MODEL VE SNAPSHOT HASH

### 8.1 Desktop Global State

Desktop, her yeni Sync Payload ürettiğinde `generation` değerini bir artırır.

```
Desktop State:
  current_generation:  uint64   // Mevcut snapshot sayacı
  snapshot_hash:       bytes32  // Mevcut snapshot'ın hash'i (aşağıda tanımlı)
```

### 8.2 Mobile Per-Device Local State

**KRİTİK:** `lastAcceptedSnapshotHash` her Mobile cihazda bağımsızdır. Mobile A'nın state'i Mobile B'yi etkilemez.

```
Mobile Local State (her cihazda ayrı):
  lastAcceptedGeneration:  uint64   // Son başarıyla kabul edilen generation
  lastAcceptedSnapshotHash: bytes32  // Son başarıyla kabul edilen snapshot hash
```

**İlk sync (virgin mobile):**
```
lastAcceptedGeneration  = 0
lastAcceptedSnapshotHash = 0x0000...00  (32 sıfır byte)
```

### 8.3 Snapshot Hash Tanımı

`snapshot_hash`, Desktop'ın gönderdiği payload'ın hash'idir — Mobile'ın mevcut state'inin değil.

```
snapshot_hash = SHA-256( CBOR(entries_array) )
```

- Hash edilen veri: `entries` alanının canonical CBOR byte dizisi
- Algoritma: SHA-256
- Çıktı: 32 bytes

Bu hash, Mobile'ın kabul ettiği son snapshot'ı temsil eder ve `lastAcceptedSnapshotHash` olarak saklanır.

### 8.4 Neden Hash Mobile State Değil Desktop Snapshot

V1'de hata: `last_sync_hash` Mobile cihazın state'ini temsil ediyordu. Bu nedenle Mobile B, Mobile A'nın hash'ini bilmediği için Desktop'tan gelen paketi reddediyordu.

V2'de çözüm: `snapshot_hash`, Desktop'ın gönderdiği payload'ın hash'idir. Mobile B ilk kez sync olduğunda bu hash'i hesaplar ve saklar. Mobile A'nın state'inden bağımsızdır.

---

## 9. VERSIONING

Üç versiyon kavramı birbirinden kesin olarak ayrılmıştır:

| Versiyon Alanı | Temsil Ettiği | V2 Değeri | Konumu |
|----------------|---------------|-----------|--------|
| `protocol_version` | QR chunking, AAD, wire format versiyonu | 2 | QR Header + Outer Envelope + CBOR Plaintext |
| `payload_version` | Şifreli CBOR iç struct versiyonu | 1 | CBOR Plaintext içinde |
| `vault_schema_version` | Vault entry nesnelerinin şema versiyonu | İmplementasyona özgü | CBOR Plaintext içinde |

### 9.1 Version Mismatch Davranışı

- **Bilinmeyen `protocol_version`:** QR chunk alındığı anda, decryption denenmeden reddedilir. Hata: `"Unsupported sync protocol version. Please update your app."`. Session iptal.
- **Bilinmeyen `payload_version`:** Şifre çözme başarılı olur ancak CBOR struct parse edilemezse veri yazılmaz. Hata: `"Payload format not supported."`.
- **Bilinmeyen `vault_schema_version`:** Şifre çözme ve parse başarılı olur ancak migration mümkün değilse veri yazılmaz. Hata: `"Vault schema migration required. Please update your app."`.

---

## 10. SESSION ID

Her Sync işlemi başlatıldığında kriptografik rastgele `sessionId` üretilir.

```
session_id: 8 bytes, CSPRNG
```

- Wire format ve CBOR içinde **raw bytes (bstr)** olarak taşınır.
- QR chunk header'ında **16 karakter Hex string** (lowercase) olarak encode edilir.
- İşlevi: Aynı sync oturumunun tüm chunk'larını birbirine bağlar ve farklı oturumların chunk'larının karışmasını engeller.

---

## 11. QR CHUNK FORMAT

### 11.1 Chunk Header Yapısı

```
FUIN|<VER>|<SESSID>|<IDX>/<TOT>|<CRC>|<DATA>
```

| Alan | Encoding | Uzunluk | Örnek |
|------|----------|---------|-------|
| Prefix | ASCII literal | 4 chars | `FUIN` |
| `VER` | ASCII integer | 1-3 chars | `2` |
| `SESSID` | Hex lowercase | 16 chars | `a1b2c3d4e5f6g7h8` |
| `IDX` | Decimal, zero-padded 3+ digit | ≥3 chars | `001` |
| `TOT` | Decimal, zero-padded 3+ digit | ≥3 chars | `017` |
| `CRC` | Hex uppercase | 8 chars | `F9A3B1C2` |
| `DATA` | Base45 | Variable | `...` |
| Separator | ASCII 0x7C (`\|`) | 1 char | `\|` |

**Örnek chunk string:**
```
FUIN|2|a1b2c3d4e5f6g7h8|002/017|F9A3B1C2|...base45_data...
```

### 11.2 CRC32 Hesaplama Kapsamı

CRC32, yalnızca `DATA` alanının **Base45 decode edilmiş ham byte'ları** üzerinden hesaplanır.

```
CRC32_input = Base45_decode(DATA_field)
CRC32_output = CRC32(CRC32_input)  // 4 bytes → 8 char Hex (uppercase)
```

CRC32 hesaplamaya header (prefix, version, sessid, idx/tot) dahil edilmez.

### 11.3 DATA Alanı İçeriği

Outer Envelope'un (Bölüm 7.2) belirli byte aralığı bu chunk'a bölüştürülerek Base45 encode edilir.

```
full_payload = [header_magic(2B)][wire_version(1B)][salt(16B)][nonce(24B)][ciphertext(NB)][auth_tag(16B)]
chunks       = split(full_payload, chunk_byte_size)
DATA_field_i = Base45_encode(chunks[i])
```

Chunk byte boyutu (chunk_byte_size): Tek bir QR kod bağlamında sabit belirlenir. Önerilen değer implementasyona bırakılır, ancak bir kez belirlendikten sonra aynı session içinde tutarlı olmalıdır.

### 11.4 Chunk Assembly Kuralları

- Chunk'lar `IDX` değerine göre sıralanır (`1`'den başlayan 1-indexed).
- Aynı `SESSID` + `IDX` kombinasyonu tekrar gelirse sessizce ignore edilir (duplicate).
- Farklı `SESSID` olan chunk mevcut session buffer'ına eklenmez.
- Tüm `IDX` değerleri `1..TOT` aralığında tamamlandığında assembly tamamdır.
- 60 saniye içinde assembly tamamlanmazsa session iptal edilir (timeout).

---

## 12. INTEGRITY VERIFICATION

İki integrity katmanı birbirinden kesin olarak ayrılmıştır:

### 12.1 Transport Integrity — CRC32

- **Amaç:** QR okuma, kamera blur veya baskı/ekran bozukluklarından kaynaklanan bit hataları
- **Kapsam:** Tek chunk'ın DATA alanı
- **Başarısız olursa:** O chunk drop edilir, session devam eder
- **Güvenlik garantisi vermez.** Saldırgan CRC32'yi de güncelleyebilir.

### 12.2 Cryptographic Integrity — AEAD Auth Tag

- **Amaç:** Payload/metadata tahrifatı, replay saldırısı, wrong key tespiti
- **Kapsam:** Tüm ciphertext + AAD (protocol_version + session_id + salt)
- **Başarısız olursa:** Tüm session iptal edilir, plaintext asla açığa çıkmaz
- **Güvenlik garantisi:** XChaCha20-Poly1305 authenticated encryption

---

## 13. REPLAY PROTECTION

Replay protection üç katmanlıdır. Yalnızca timestamp'e dayanmaz.

### 13.1 Session-Level (sessionId)

Her sessionId bir kez kullanılır. Mobile başarıyla tamamlanan sessionId'yi saklar. Aynı sessionId tekrar gelirse session açılmadan reddedilir.

### 13.2 Generation-Level

Gelen payload'daki `generation` değeri, Mobile'ın `lastAcceptedGeneration` değerinden **büyük** olmalıdır.

```
if payload.generation <= mobile.lastAcceptedGeneration → REJECT ("Stale snapshot")
```

**İlk sync (virgin mobile):** `lastAcceptedGeneration = 0`, gelen `generation >= 1` olduğu için kabul edilir.

**Multi-device:** Mobile B, `lastAcceptedGeneration = 0` ile başlar. Desktop generation=6 gönderdiğinde Mobile B bunu kabul eder çünkü `6 > 0`.

### 13.3 Snapshot Hash — Bütünlük Zinciri

Mobile, başarılı her sync'in ardından `lastAcceptedSnapshotHash` değerini günceller.

Sonraki sync geldiğinde: Payload'daki `snapshot_hash`, Mobile'ın `lastAcceptedSnapshotHash` değeriyle karşılaştırılmaz (bu V1'deki hatalı modeldi). Bunun yerine:

- `snapshot_hash`, Desktop'ın gönderdiği `entries` CBOR'unun SHA-256'sıdır.
- Mobile bu hash'i kabul ettikten sonra `lastAcceptedSnapshotHash` olarak saklar.
- Bir sonraki sync'te `generation > lastAcceptedGeneration` kontrolü yeterlidir.

`snapshot_hash` doğrulama mantığı:

```
received_hash = SHA-256( CBOR(payload.entries) )
if received_hash != payload.snapshot_hash → REJECT ("Snapshot integrity failure")
```

Bu kontrol, payload içindeki `entries` ile `snapshot_hash` alanının tutarlı olduğunu doğrular.

### 13.4 Timestamp

`timestamp`, saniye cinsinden UTC Epoch değeridir. Güvenlik kararlarında kullanılmaz. Yalnızca kullanıcı arayüzünde bilgi amaçlıdır ("Bu sync 2 saat önce gönderilmiş").

### 13.5 Chunk Manipülasyon Korumaları

| Senaryo | Savunma |
|---------|---------|
| Chunk silme | `TOTAL_CHUNKS` tamamlanmaz → timeout reject |
| Chunk değiştirme | AEAD Auth Tag doğrulaması tüm payload'ı reddeder |
| Chunk yeniden sıralama | `IDX` tabanlı assembly, sıra bağımsız çalışır |
| Yeni chunk ekleme | Assembly tamamlandıktan sonra AEAD fail olur |
| Chunk değiştirme + CRC güncelleme | AEAD Auth Tag'i aldatılamaz |

---

## 14. DEVICE INDEPENDENCE VE MOBILE LOCAL STATE

### 14.1 Mobile Per-Device State

Her Mobile cihaz kendi state'ini bağımsız olarak tutar. Bu state başka cihazlara aktarılmaz.

```
mobile_sync_state = {
    lastAcceptedGeneration:   uint64,   // İlk değer: 0
    lastAcceptedSnapshotHash: bytes32,  // İlk değer: 0x00...00 (32 sıfır)
    lastAcceptedSessionId:    bytes8,   // Son başarılı sessionId
    lastAcceptedTimestamp:    uint64    // Son başarılı sync zamanı (UX amaçlı)
}
```

### 14.2 Mobile Local Edit Uyarısı

Mobile cihaz local değişiklikler yapmış olabilir (Add/Edit/Delete). Desktop'tan yeni bir snapshot geldiğinde:

- Eğer Mobile local vault, `lastAcceptedSnapshotHash` ile farklılaşmışsa (local değişiklik tespit edilmişse):
- Mobile kullanıcıya açık bir uyarı göstermelidir.
- Uyarı metni net olmalıdır: **"Bu cihazda yapılan değişiklikler, yeni Desktop snapshot'ı kabul edilirse üzerine yazılacaktır. Devam edilsin mi?"**
- Kullanıcı kabul etmeden vault replace edilmez.

---

## 15. WRONG PASSWORD HANDLING

1. Yanlış Sync Password, Argon2id'nin farklı bir Sync Key türetmesine neden olur.
2. XChaCha20-Poly1305 decryption, Auth Tag mismatch ile başarısız olur.
3. Plaintext asla bellekte oluşturulmaz.
4. Hata: `"Decryption failed. Wrong Sync Password or corrupted data."`
5. Kullanıcı yeniden deneyebilir. Retry limiti (Örn: 3 denemede artan bekleme) uygulama katmanında yönetilir.
6. Protokol, şifre denemesi sayısını veya süresini takip etmez.

---

## 16. FAILURE CASES

Her senaryoda davranış deterministik olarak tanımlanmıştır.

| Durum | Operation | Session | Retry | Kullanıcı Mesajı |
|-------|-----------|---------|-------|------------------|
| Wrong password | İptal | İptal | Mümkün | "Yanlış Sync Password" |
| Corrupted QR chunk (CRC fail) | Chunk drop, devam | Devam | Auto | "QR okunamadı, tekrar tara" |
| Missing chunk (timeout) | İptal | İptal | Baştan | "Eksik QR. Lütfen tekrar başlatın" |
| Duplicate chunk | Chunk ignore, devam | Devam | — | — |
| Out-of-order chunk | Assembly'e eklenir | Devam | — | — |
| Wrong sessionId | Chunk ignore | Devam | — | — |
| Replayed session (generation ≤ lastAccepted) | İptal | İptal | Hayır | "Eski veya tekrar eden veri" |
| Modified metadata (AAD fail) | İptal | İptal | Hayır | "Şifre çözme başarısız" |
| Modified ciphertext (Auth Tag fail) | İptal | İptal | Hayır | "Şifre çözme başarısız" |
| Snapshot integrity fail (hash mismatch) | İptal | İptal | Hayır | "Veri bütünlüğü hatası" |
| Unsupported protocol_version | İptal | İptal | Hayır | "Protokol versiyonu desteklenmiyor. Uygulamayı güncelleyin" |
| Unsupported vault_schema_version | İptal | İptal | Hayır | "Vault şeması desteklenmiyor. Uygulamayı güncelleyin" |
| Invalid CBOR | İptal | İptal | Hayır | "Bozuk veri paketi" |
| Decompression failure (zstd) | İptal | İptal | Hayır | "Veri açma hatası" |
| Malformed payload | İptal | İptal | Hayır | "Geçersiz veri yapısı" |
| Incomplete transfer (uygulama kapandı) | Session temizle | İptal | Baştan | — |
| User cancellation | Memory zeroing | İptal | İsteğe bağlı | — |
| Oversized payload / OOM | İptal | İptal | Hayır | "Veri çok büyük" |
| Mobile local edit conflict | Kullanıcıya sor | Bekle | Kullanıcı kararı | "Yerel değişiklikler üzerine yazılacak" |

---

## 17. BACKWARD COMPATIBILITY

- V2 Sync Protokolü, Desktop ve Mobile'ın mevcut local Vault şifreleme altyapısını değiştirmez.
- Legacy Vault, mevcut mekanizmasıyla (PBKDF2 veya Argon2id, AES-GCM) decrypt edilir.
- Plaintext veri yalnızca transient memory'de tutulur.
- Bu plaintext, V2 Sync pipeline'ına (CBOR → zstd → XChaCha20-Poly1305 → QR) beslenir.
- V1 Sync formatı ile oluşturulmuş QR kodları, V2 client tarafından `protocol_version` mismatch ile reddedilir.

---

## 18. MIGRATION

### 18.1 Vault Format Migration

Mevcut Vault verisinin V2 üzerinden aktarılması:

```
Legacy Vault (disk)
        │
        ▼ (Vault Password ile decrypt, hardware key dahil)
Plaintext Vault Entries (RAM only)
        │
        ▼ (entries → Canonical CBOR array)
CBOR bytes (RAM only)
        │
        ▼ (zstd compression, level=3)
Compressed bytes (RAM only)
        │
        ▼ (XChaCha20-Poly1305, Sync Key + Nonce + AAD)
Encrypted Sync Payload (RAM only)
        │
        ▼ (Outer envelope header prepend)
Binary Payload (RAM only)
        │
        ▼ (chunked + Base45 encoded)
QR Codes (display)
```

**Kural:** Plaintext veri migration süreci boyunca diske yazılmaz. Tüm işlemler RAM üzerinde gerçekleşir.

### 18.2 Protocol Migration (V1 → V2)

- V2 client, V1 formatındaki QR'ları `protocol_version != 2` olduğu için reddeder.
- Desktop V2 desteği olmayan eski bir Mobile cihaz, V2 QR'ları okuyamaz. Kullanıcı uygulamayı güncellemek zorundadır.
- İki taraf da V2 destekliyorsa herhangi bir migration adımı gerekmez; yeni Sync Password ile yeni session başlatılır.

---

## 19. EXAMPLE FLOWS

### Flow A — Desktop → Mobile A İlk Sync (Başarılı)

```
Desktop:
  1. Kullanıcı "Sync to Mobile" başlatır.
  2. Vault Password ile local vault bellekte açılır.
  3. CSPRNG ile üretilir:
       session_id = [8 random bytes]            → hex: "a1b2c3d4e5f6g7h8"
       salt       = [16 random bytes]           → raw bytes
       nonce      = [24 random bytes]           → raw bytes
  4. generation = 1  (ilk sync, 0'dan 1'e çıkar)
  5. snapshot_hash = SHA-256(CBOR(entries))     → 32 bytes
  6. Kullanıcı Sync Password girer.
  7. effective_salt = salt || "FUIN_SYNC_V2"
     Sync Key = Argon2id(SyncPassword, effective_salt, m=65536, t=3, p=4, out=32)
  8. Plaintext CBOR oluşturulur (tüm alanlar dahil).
  9. zstd(level=3) ile sıkıştırılır.
  10. AAD = [0x02][session_id(8B)][salt(16B)]  → 25 bytes sabit
  11. XChaCha20-Poly1305 encrypt(plaintext=compressed, key=SyncKey, nonce=nonce, aad=AAD)
      → ciphertext (N bytes) + auth_tag (16 bytes)
  12. Outer envelope:
      [0x46,0x53][0x02][salt(16B)][nonce(24B)][ciphertext(NB)][auth_tag(16B)]
  13. Envelope chunk'lara bölünür, Base45 encode edilir.
  14. QR header: "FUIN|2|a1b2c3d4e5f6g7h8|001/005|F9A3B1C2|..."
  15. 5 QR kod ekranda animasyonla gösterilir.

Mobile A (Virgin):
  lastAcceptedGeneration  = 0
  lastAcceptedSnapshotHash = 0x00...00

  16. Kamera 5 QR'ı okur (sırasız gelebilir).
  17. sessionId = "a1b2c3d4e5f6g7h8", protocol_version = 2 → OK
  18. Duplicate chunk kontrolü: aynı IDX tekrar gelirse ignore.
  19. 5 chunk tamamlanır, CRC32 kontrolleri geçer.
  20. Outer envelope birleştirilir. salt, nonce parse edilir.
  21. Kullanıcı Sync Password girer.
  22. effective_salt = salt || "FUIN_SYNC_V2"
      Sync Key = Argon2id(SyncPassword, effective_salt, m=65536, t=3, p=4, out=32)
  23. AAD = [0x02][session_id(8B)][salt(16B)]
  24. XChaCha20-Poly1305 decrypt → Auth Tag OK → compressed bytes elde edilir.
  25. zstd decompress → CBOR bytes.
  26. CBOR parse → payload struct.
  27. Kontroller:
      protocol_version == 2                → OK
      payload.generation (1) > lastAcceptedGeneration (0) → OK
      SHA-256(CBOR(payload.entries)) == payload.snapshot_hash → OK
  28. Mobile vault, payload.entries ile replace edilir.
  29. Mobile local state güncellenir:
      lastAcceptedGeneration  = 1
      lastAcceptedSnapshotHash = payload.snapshot_hash
      lastAcceptedSessionId   = session_id bytes
      lastAcceptedTimestamp   = payload.timestamp
  30. Kullanıcıya: "Sync başarılı."
```

### Flow B — Desktop → Mobile B (Farklı Cihaz, İlk Kez)

```
Desktop: Generation 6'da. snapshot_hash = H6.
Mobile B: lastAcceptedGeneration = 0 (virgin)

Desktop:
  1. Adımlar Flow A ile aynı. generation=7, snapshot_hash=H7.

Mobile B:
  2. payload.generation (7) > lastAcceptedGeneration (0) → OK
  3. SHA-256(CBOR(entries)) == payload.snapshot_hash (H7) → OK
  4. Kabul edilir. Mobile B, Mobile A'nın state'ini bilmez, bilmek zorunda değildir.
```

### Flow C — Replay Saldırısı (Başarısız)

```
Saldırgan: Generation=5, snapshot_hash=H5 içeren QR setini video kaydetmiştir.

Mobile A: lastAcceptedGeneration = 6 (zaten daha ileri)

Saldırgan eski QR'ları okutur:
  1. Chunk'lar toplanır.
  2. Sync Key (saldırgan password'ü biliyorsa) doğru türetilir.
  3. AEAD decrypt başarılı (payload değişmemiş).
  4. payload.generation (5) > lastAcceptedGeneration (6) → FALSE → REJECT
  5. Hata: "Eski veya tekrar eden veri." Vault değişmez.
```

### Flow D — Chunk Manipülasyon Saldırısı (Başarısız)

```
Saldırgan: 3. chunk'un DATA alanını değiştirir (veya yeni bir chunk ekler).

  1. CRC32 mismatch → Chunk drop edilir.
  2. Saldırgan CRC32'yi de güncellerse → CRC32 geçer.
  3. Assembly tamamlanır ancak byte dizisi bozulmuştur.
  4. AEAD Auth Tag doğrulaması FAILS.
  5. Session iptal. Hata: "Şifre çözme başarısız."
```

---

## 20. IMPLEMENTATION INVARIANTS

Aşağıdaki kurallar implementasyon sırasında istisnasız uygulanmak ZORUNDADIR.

1. **[INV-01]** Sync Password ile Vault Password protokol mimarisinde ayrı derivation path'leri kullanır.
2. **[INV-02]** Sync Key derivation'a machineId veya herhangi bir hardware-bound secret dahil edilemez.
3. **[INV-03]** Sync Key yalnızca şu girdilerden türetilir: Sync Password + protocol-defined KDF parameters + random salt + domain tag.
4. **[INV-04]** V2 yalnızca Desktop → Mobile yönündedir.
5. **[INV-05]** KDF: Argon2id, m=65536, t=3, p=4, outLen=32. Runtime'da değiştirilemez.
6. **[INV-06]** Salt: 16 bytes CSPRNG. Effective salt: salt || "FUIN_SYNC_V2" (28 bytes toplam).
7. **[INV-07]** Cipher: XChaCha20-Poly1305. Nonce: 24 bytes CSPRNG. Auth Tag: 16 bytes.
8. **[INV-08]** Nonce "deterministic" değildir. Her encryption işlemi için yeni CSPRNG nonce üretilir.
9. **[INV-09]** AAD: [0x02][session_id(8B)][salt(16B)] — 25 bytes, tamamen binary, separator yok.
10. **[INV-10]** Serialization: Canonical CBOR (RFC 8949). MessagePack veya JSON kullanılamaz.
11. **[INV-11]** Compression: zstd level=3. zlib kullanılamaz.
12. **[INV-12]** QR encoding: Base45 (RFC 9285).
13. **[INV-13]** Her sync işleminin benzersiz sessionId'si vardır (8 bytes CSPRNG).
14. **[INV-14]** `lastAcceptedGeneration` ve `lastAcceptedSnapshotHash` her Mobile cihazda bağımsız tutulur.
15. **[INV-15]** `snapshot_hash = SHA-256(CBOR(entries))` — Mobile state'inin değil, Desktop payload'ının hash'idir.
16. **[INV-16]** Replay detection: `payload.generation > lastAcceptedGeneration` kontrolü zorunludur.
17. **[INV-17]** Replay protection yalnızca timestamp'e dayanamaz. Generation kontrolü zorunludur.
18. **[INV-18]** CRC32 güvenlik mekanizması değildir. Yalnızca transport integrity içindir.
19. **[INV-19]** Kriptografik bütünlük garantisi yalnızca AEAD Auth Tag tarafından sağlanır.
20. **[INV-20]** Auth Tag doğrulaması başarısız olursa plaintext bellekte oluşturulmaz ve asla açığa çıkmaz.
21. **[INV-21]** Mobile yerel değişiklik varsa ve yeni Desktop snapshot gelirse kullanıcı uyarı olmadan override edilemez.
22. **[INV-22]** Plaintext veri migration veya sync süreci boyunca diske yazılmaz.
23. **[INV-23]** Desktop'ın mevcut local Vault Encryption mekanizması bu protokol tarafından değiştirilmez.
24. **[INV-24]** Mobile, Desktop'ın hardware-bound Vault Key'ini kullanmak zorunda değildir ve kullanamaz.
25. **[INV-25]** protocol_version, payload_version ve vault_schema_version birbirinden farklı kavramlardır; aynı sayaç değillerdir.
26. **[INV-26]** Outer envelope'da `header_magic = [0x46, 0x53]` ve `wire_version = 0x02` zorunludur.
27. **[INV-27]** Ciphertext length implicit'tir: `total_payload_length - 59`. Auth tag her zaman son 16 byte'tır.
28. **[INV-28]** Desktop ve Mobile aynı input için byte-level aynı CBOR, zstd, AAD ve Sync Key üretmek ZORUNDADIR.
