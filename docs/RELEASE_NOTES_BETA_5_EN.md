### Fuin Desktop v1.0.0-beta.5 (Hardened Security Baseline)

The most stable, hardened, and verified beta release of Fuin Desktop. 100% offline-first password management with zero telemetry, direct P2P local sync, and memory-safe cryptography.

#### 📦 Download Artifacts

| Platform | File | Architecture |
|:---|:---|:---|
| **macOS** | [`Fuin-1.0.0-beta.5-arm64.dmg`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.5/Fuin-1.0.0-beta.5-arm64.dmg) | Apple Silicon (M1/M2/M3/M4) |
| **Windows** | [`Fuin Setup 1.0.0-beta.5.exe`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.5/Fuin.Setup.1.0.0-beta.5.exe) | Windows 10 / 11 (64-bit) |
| **Integrity** | [`SHA256SUMS.txt`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.5/SHA256SUMS.txt) | Checksum Verification |

#### 🛡️ Key Security & Architecture Highlights

- **P2P Sync & Optical Pairing Separation:** Mutual trust is established once via out-of-band optical QR code pairing; encrypted vault synchronization is performed strictly peer-to-peer over your private local network (Wi-Fi or hotspot) with **XChaCha20-Poly1305**. Zero cloud relays, zero external telemetry.
- **Production Screen Protection:** Windows enforce `setContentProtection(true)` to prevent background spyware or accidental screen share leakage.
- **Exhaustive Security Verification:** 20 test suites with 290+ automated tests passing with 0 failures, including prototype pollution immunity, IPC URL protocol jailing, and HMAC-authenticated brute-force lockout defenses.
- **RFC 9116 Compliant:** Published `/.well-known/security.txt` and comprehensive Threat Model documentation ([docs/SECURITY_MODEL.md](https://github.com/Sombooo/Fuin/blob/main/docs/SECURITY_MODEL.md)).
- **Zero Vulnerabilities:** All dependencies audited and patched against upstream CVEs (`npm audit: 0 vulnerabilities`).

#### 🔒 Verification

```bash
# Verify checksums on macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or manually on macOS:
shasum -a 256 Fuin-1.0.0-beta.5-arm64.dmg
```

---
*Security reports:* [hellofuin@gmail.com](mailto:hellofuin@gmail.com) · *Repository:* [github.com/Sombooo/Fuin](https://github.com/Sombooo/Fuin)
