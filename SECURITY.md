# SECURITY ARCHITECTURE

Fuin is engineered around a strict **zero-knowledge, offline-first, peer-to-peer** security model. No user accounts, central servers, or cloud relays exist in the architecture.

## 1. Local Vault Cryptography
- **Key Derivation Function (KDF):**
  - **Desktop:** Master passwords are stretched using **Argon2id** (`memoryCost = 131072` [128 MiB], `timeCost = 4`, `parallelism = 1`, 32-byte CSPRNG salt). Insecure KDF downgrades are strictly refused.
  - **Mobile:** Calibrated for mobile memory ceilings using **Argon2id** (`memory = 65536` [64 MiB], `iterations = 3`, `parallelism = 1`).
- **Authenticated Encryption at Rest:**
  - Vault payloads (`fuin.enc`), recovery descriptors (`fuin.recovery`), and master key envelopes (`fuin.master.enc`) are encrypted with **AES-256-GCM** using fresh 96-bit CSPRNG IVs and 256-bit salts on every write.
  - Files are persisted via atomic write-and-fsync transactions (`0o600` permissions) with crash-safe `.commit` / `.rollback` recovery journals.
- **Brute-Force Resistance:**
  - Failed unlock attempts trigger exponential backoff delays (`1s` up to `300s`), persisted in an HMAC-SHA256 authenticated lockout state (`fuin.lockout`) verified via constant-time comparison (`crypto.timingSafeEqual`).
  - On Mobile, 15 consecutive failed unlock attempts trigger automatic local vault erasure.

## 2. Memory & Session Hygiene
- **Encrypted In-Memory Vault Entries:** While the desktop vault is unlocked, credential passwords and TOTP secrets are not held as plaintext strings in the entry list; they are encrypted in memory under an ephemeral WebCrypto **AES-GCM** `sessionKey` and decrypted only on demand.
- **Locked Buffers & Zeroization:** Sensitive key buffers in the Electron main process are pinned with `sodium_mlock` (`secureBuffer`) to prevent OS swap-file leakage and wiped with `Buffer.fill(0)` immediately after cryptographic operations.
- **Screen & Clipboard Protection:**
  - Desktop windows enforce `setContentProtection(true)` and Mobile screens enforce `preventScreenCaptureAsync()`.
  - Copied credentials are automatically cleared from the OS clipboard after a 30–45 second TTL using SHA-256 digest verification.

## 3. Hybrid P2P Synchronization Security
### A. Local LAN Sync (P2P)
- **Out-of-Band Pairing:** A 256-bit CSPRNG `pairKey` is exchanged optically via QR code. Pairing proofs (`/pair`) and acknowledgments (`pair-ack`) are authenticated with **XChaCha20-Poly1305**.
- **Transport Hardening:**
  - Bound to a 120-second ephemeral HTTP listener that immediately terminates upon sync completion or vault lock.
  - Enforces strict **RFC1918 / Loopback** socket filtering, rejecting public internet IPs and browser CORS preflights.
  - Protects against reflection, MitM, and cross-session replay attacks via directional tags (`direction: 'request' | 'response'`), cryptographic `requestNonce` binding, a 120-second freshness window, and a cross-session nonce replay cache.
- **Conflict-Free Deterministic Merge:** Concurrent edits are resolved deterministically with a `+5 minute` clock-skew ceiling, preserving superseded credentials in `history` and propagating tombstone deletions (`deletedAt`).

### B. Air-Gap QR Sync (V2)
- Operates with zero network interfaces enabled. Vault snapshots are serialized in canonical CBOR, compressed with ZSTD, encrypted with **XChaCha20-Poly1305** (keyed via **Argon2id** + **HKDF-SHA256**), and transmitted over animated Base45 QR frames with CRC-32 frame verification and a strictly monotonic `generation` counter.

## 4. Browser Extension & Phishing Defenses
- **No Silent Autofill:** Credentials are never injected automatically on page load. Every autofill request requires explicit user approval in the Desktop app modal showing the target domain.
- **Domain Isolation:** Enforces HTTPS-only targets, top-frame verification (`sender.frameId === 0`), in-flight tab navigation cancellation, and strict exact-matching on multi-tenant public suffixes (`github.io`, `vercel.app`, `pages.dev`, `netlify.app`, etc.).

## 5. Known Runtime Boundaries
- **JavaScript Engine String Immutability:** While byte buffers (`Buffer` / `Uint8Array`) are deterministically zeroized, transient JavaScript strings created during UI rendering remain subject to V8 / Hermes garbage collection cycles.

## Responsible Disclosure
If you discover a security vulnerability, please open a confidential security advisory on GitHub or contact the maintainers before public disclosure.
