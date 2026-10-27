# Fuin Security Model & Threat Whitepaper

**Version:** 1.0 (Beta 5 Hardened Baseline)  
**Date:** October 2026  
**Status:** Active Architectural Standard  
**Maintainer:** Fuin Security Core (`hellofuin@gmail.com`)  

---

## 1. Core Philosophy: "Quietly Secure"

Fuin is designed around an uncompromising offline-first, peer-to-peer security architecture. We reject the prevailing password manager paradigm of central multi-tenant cloud storage, mandatory accounts, and continuous background telemetry.

Secrets belong solely to the user's personal devices. Fuin has:
- **Zero central servers** (no user database, no relay proxy, no auth servers).
- **Zero telemetry & analytics** (no Sentry, no Google Analytics, no tracking pings).
- **Zero background cloud connections** (100% offline by default).

---

## 2. Adversarial Threat Model: What We Protect Against

Fuin's threat model explicitly defines adversary capabilities and technical mitigations across the four primary vectors:

```mermaid
flowchart TD
    subgraph Vectors["Adversarial Vectors"]
        A["1. Physical Storage Theft"]
        B["2. Hostile Local Network (LAN)"]
        C["3. Supply Chain / Memory Tampering"]
        D["4. Web / Phishing Context"]
    end

    subgraph Defenses["Fuin Cryptographic Defenses"]
        A -->|Argon2id 128MB + AES-256-GCM| D1["At-Rest Vault Jail"]
        B -->|Optical QR Pairing + XChaCha20-Poly1305| D2["Ephemeral LAN P2P Channel"]
        C -->|mlock + Buffer.fill(0) + Safe Memory| D3["Zeroization & Session Isolation"]
        D -->|contextIsolation + Domain Jailing| D4["Browser & IPC Isolation"]
    end
```

### 2.1 Vector 1: Stolen Storage, Device Seizure & Offline Brute-Force
- **Adversary Capability:** An attacker obtains a physical copy of `fuin.enc`, a flash backup, or the full disk from a stolen laptop or smartphone.
- **Mitigations:**
  - **Memory-Hard KDF:** The master password derives the master key via **Argon2id** (`m=131072` [128 MiB RAM], `t=4`, `p=1` on Desktop; `m=65536` [64 MiB], `t=3`, `p=1` on Mobile). This configuration imposes massive memory bandwidth requirements, rendering GPU and ASIC dictionary attacks economically infeasible.
  - **Authenticated Cipher at Rest:** All payloads are encrypted using **AES-256-GCM** with fresh 96-bit CSPRNG IVs on every write. Any single-bit modification to ciphertext or file headers triggers an immediate AEAD authentication tag mismatch; no plaintext is ever decrypted or surfaced.
  - **Tamper-Resistant Rate Limiting:** Consecutive failed unlock attempts trigger progressive exponential backoff (from 1s up to 300s). Lockout counters are persisted in an **HMAC-SHA256** authenticated state file (`fuin.lockout`), verified via constant-time equality (`crypto.timingSafeEqual`). Mutating or deleting the lockout file triggers an immediate safety lockout.

### 2.2 Vector 2: Hostile Local Network & Wi-Fi Eavesdropping (Man-in-the-Middle)
- **Adversary Capability:** An attacker controls the local Wi-Fi router, monitors coffee shop traffic, or runs an ARP/DNS spoofing attack on the LAN.
- **Mitigations:**
  - **Out-of-Band Trust (Optical QR Pairing):** Mutual trust is established exclusively out-of-band by scanning an optical QR code displayed on the desktop screen. The QR payload contains an ephemeral 256-bit CSPRNG `pairKey`, port, and device identifier.
  - **XChaCha20-Poly1305 AEAD Transport:** All network communications between paired devices are encrypted end-to-end using **XChaCha20-Poly1305** with 192-bit CSPRNG nonces.
  - **Strict Socket Jailing:** Ephemeral HTTP listeners bind strictly to local RFC1918 interfaces (or loopback). Non-private IP addresses, loopback forgery, and browser CORS cross-origin preflight requests are rejected at the TCP socket boundary.
  - **Replay & Reflection Defense:** Packets incorporate directional identifiers (`request` vs `response`), cryptographic `requestNonce` verification, a 120-second timestamp freshness window, and a persistent cross-session nonce cache.
  - **120-Second Ephemeral Lifecycle:** The local listener is opened only upon explicit user request, operates for at most 120 seconds, and shuts down immediately upon sync completion, user cancellation, or vault lock.
  - **Pairing vs. Sync Separation:** The QR code is strictly used for one-time optical device pairing. Vault synchronization is carried out peer-to-peer over the local network (home Wi-Fi or phone hotspot) without optical chunk transfers.

### 2.3 Vector 3: Memory Extraction & Application Tampering
- **Adversary Capability:** A background process attempts to dump RAM, capture windows, or harvest clipboard data.
- **Mitigations:**
  - **Memory Pinning & Zeroization:** Sensitive key buffers in the Electron main process are pinned in physical RAM using `sodium_mlock` (`secureBuffer`) to prevent swapping to disk pagefiles, and are deterministically overwritten with `Buffer.fill(0)` immediately after use.
  - **In-Memory Vault Entry Jailing:** While the vault is unlocked, credentials and TOTP secrets are encrypted in-memory under an ephemeral WebCrypto `sessionKey` and decrypted only when explicitly viewed or copied.
  - **Screen Protection:** Windows on Desktop enforce `setContentProtection(true)` to defeat background screen recorders; Mobile enforces `FLAG_SECURE` (`preventScreenCaptureAsync`).
  - **Clipboard Auto-Clear:** Copied credentials are automatically purged from the operating system clipboard after 30–45 seconds with SHA-256 digest validation to prevent overwriting user data if the clipboard changed.

### 2.4 Vector 4: Malicious Files, IPC Hijacking & Renderer Exploitation
- **Adversary Capability:** A malformed Bitwarden, 1Password, or CSV import file attempts prototype pollution, or an attacker injects malicious IPC payloads into the renderer.
- **Mitigations:**
  - **Strict Context Isolation:** Electron windows run with `contextIsolation: true`, `nodeIntegration: false`, and `sandbox: true`. The renderer communicates with the main process solely through typed, validated IPC channels in `preload.js`.
  - **Object Prototype Immunization:** Importers sanitize incoming JSON/CSV data against prototype pollution attacks, rejecting `__proto__`, `constructor`, and `prototype` keys.
  - **URL Protocol Whitelisting:** Outbound URL handlers allow only strictly validated `http:` and `https:` schemes, blocking `file:`, `javascript:`, `data:`, `ms-msdt:`, and shell injection primitives.

---

## 3. Trust Boundaries & Assumptions

Security engineering requires intellectual honesty about what is **out of scope**:

1. **Host Operating System Integrity:** Fuin assumes the host OS kernel and hardware are uncompromised. If an adversary installs a kernel rootkit, hardware keylogger, or physical debugger on the host machine, no userland software can prevent key extraction.
2. **V8 Engine Garbage Collection:** While byte buffers (`Buffer`, `Uint8Array`) are deterministically zeroized, transient JavaScript string representations created during UI rendering remain subject to V8 / Hermes garbage collection lifecycles until collected.
3. **Master Password Entropy:** Fuin cannot protect passwords if the user chooses a weak master password susceptible to dictionary lookup. Fuin provides built-in `zxcvbn` estimation to guide users toward high-entropy passphrases.

---

## 4. Cryptographic Specification Table

| Dimension | Desktop Specification | Mobile Specification |
|:---|:---|:---|
| **Cipher at Rest** | AES-256-GCM (NIST SP 800-38D) | AES-256-GCM (NIST SP 800-38D) |
| **KDF Algorithm** | Argon2id (RFC 9106) | Argon2id (RFC 9106) |
| **KDF Memory (`m`)** | 131,072 KiB (128 MiB) | 65,536 KiB (64 MiB) |
| **KDF Time (`t`)** | 4 iterations | 3 iterations |
| **KDF Parallelism (`p`)** | 1 lane | 1 lane |
| **Salt Length** | 256 bits (32 bytes CSPRNG) | 256 bits (32 bytes CSPRNG) |
| **IV / Nonce Length** | 96 bits (12 bytes CSPRNG) | 96 bits (12 bytes CSPRNG) |
| **AEAD Tag Length** | 128 bits (16 bytes) | 128 bits (16 bytes) |
| **P2P Transport Cipher** | XChaCha20-Poly1305 (RFC 8439 / draft) | XChaCha20-Poly1305 (RFC 8439 / draft) |
| **Transport Nonce** | 192 bits (24 bytes CSPRNG) | 192 bits (24 bytes CSPRNG) |
| **Pairing Key Length** | 256 bits (32 bytes CSPRNG) | 256 bits (32 bytes CSPRNG) |
| **Dual-Key Derivation** | HKDF-SHA256 (`VaultKey`, `SyncKey`) | HKDF-SHA256 (`VaultKey`, `SyncKey`) |
| **Storage Durability** | Atomic write + fsync + commit journal | Sandboxed storage + hardware SecureStore |

---

## 5. Zero-Network Verification Guide ("Don't Trust Us, Verify")

We encourage every user, systems administrator, and security auditor to verify Fuin's offline integrity independently.

### Step 1: Launch Your Preferred Network Monitor
Open any standard network inspection tool:
- **macOS:** [Little Snitch](https://www.obdev.at/products/littlesnitch/) or [Proxyman](https://proxyman.io/)
- **Linux:** `sudo tcpdump -i any -n "not port 53 and not arp"`
- **Windows:** [Wireshark](https://www.wireshark.org/) or [GlassWire](https://www.glasswire.com/)

### Step 2: Normal Usage Observation
1. Launch Fuin Desktop.
2. Unlock your vault, create new entries, search, and copy passwords.
3. **Result:** Observe exactly **0 outbound network packets**. Fuin makes zero calls to any remote server or IP address.

### Step 3: Local P2P Sync Observation
1. Connect your computer and mobile phone to the same Wi-Fi router (or activate your phone's Personal Hotspot).
2. On Desktop, click **Eşitle (Sync)**.
3. On Mobile, tap **Eşitle (Sync)**.
4. **Result:**
   - Observe strictly local RFC1918 traffic (e.g. `192.168.1.X` to `192.168.1.Y`) over the ephemeral port.
   - All payload packets are ciphertext (`XChaCha20-Poly1305`).
   - The ephemeral port closes automatically within 120 seconds or as soon as sync completes.
   - Zero packets ever touch the public internet.

---

## 6. Responsible Disclosure & Security Audits

Fuin adheres to the [RFC 9116](https://datatracker.ietf.org/doc/html/rfc9116) reporting specification:
- **Security Contact:** `mailto:hellofuin@gmail.com`
- **Security Policy:** [/.well-known/security.txt](file:///.well-known/security.txt)
- **Vulnerability Reporting:** [GitHub Security Advisories](https://github.com/Sombooo/Fuin/security/advisories)
- **Response Commitment:** All valid security advisories receive an initial response within 48 hours. Fixes are prioritized and released with full cryptographic disclosure.
