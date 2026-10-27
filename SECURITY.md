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

## 3. Cross-Device P2P Synchronization Security
Fuin syncs vault data directly between devices without cloud intermediaries, central accounts, or third-party relay servers.

### A. One-Time Optical Pairing (QR Exchange)
- **Zero-Network Trust Establishment:** Mobile and Desktop devices establish mutual trust out-of-band by scanning a single optical QR code generated on the desktop screen.
- **Cryptographic Ephemeral Handshake:**
  - The pairing QR code encodes a 256-bit CSPRNG `pairKey`, an ephemeral port, local RFC1918 IP candidates, and the desktop `deviceId`.
  - The mobile device initiates an authenticated handshake (`/pair`) encrypted with **XChaCha20-Poly1305** using a single-use CSPRNG nonce.
  - Plaintext keys are never sent over the wire. Once the desktop validates and records the mobile device (`pair-ack`), pairing is finalized, and either device can revoke the pairing at any time with a single click.

### B. Encrypted Local P2P Synchronization (LAN / Hotspot)
- **Network Scope:** Operates strictly on private local networks (RFC1918 Wi-Fi subnets or phone Personal Hotspots).
- **Transport Hardening:**
  - Bound to an ephemeral HTTP server active only for a 120-second window during synchronization.
  - Automatically shuts down immediately upon sync completion, explicit cancellation, or vault lock.
  - Enforces strict socket-level filtering: public internet IP addresses, loopback forgery, and browser CORS cross-origin requests are rejected upfront.
  - **Replay & Reflection Defense:** Directional binding (`direction: 'request' | 'response'`), cryptographic `requestNonce` verification, a 120-second freshness window, and a persistent cross-session nonce cache prevent packet injection and replay attacks.
- **Conflict-Free Deterministic Merge:** Two-way edits are merged deterministically using entry-level timestamps with a `+5 minute` clock-skew ceiling. Superseded entries are preserved in entry history, and tombstone deletions (`deletedAt`) are propagated safely across devices.

## 4. Browser Extension & Phishing Defenses
- **No Silent Autofill:** Credentials are never injected automatically on page load. Every autofill request requires explicit user approval in the Desktop app modal showing the target domain.
- **Domain Isolation:** Enforces HTTPS-only targets, top-frame verification (`sender.frameId === 0`), in-flight tab navigation cancellation, and strict exact-matching on multi-tenant public suffixes (`github.io`, `vercel.app`, `pages.dev`, `netlify.app`, etc.).

## 5. Known Runtime Boundaries
- **JavaScript Engine String Immutability:** While byte buffers (`Buffer` / `Uint8Array`) are deterministically zeroized, transient JavaScript strings created during UI rendering remain subject to V8 / Hermes garbage collection cycles.

## 6. Vulnerability Reporting & Responsible Disclosure
We welcome security researchers and independent auditors to inspect Fuin's open-source architecture. Fuin maintains an RFC 9116 compliant security policy:

- **Security Contact:** [hellofuin@gmail.com](mailto:hellofuin@gmail.com)
- **RFC 9116 Policy:** [/.well-known/security.txt](file:///.well-known/security.txt)
- **Confidential Advisories:** Please report vulnerabilities via [GitHub Security Advisories](https://github.com/Sombooo/Fuin/security/advisories) or email before public disclosure.
- **Response SLA:** We acknowledge all valid security reports within 48 hours and prioritize patch releases. Confirmed researchers are acknowledged in release notes.
