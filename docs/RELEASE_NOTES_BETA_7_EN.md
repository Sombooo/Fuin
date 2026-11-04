### Fuin Desktop v1.0.0-beta.7 (AGPLv3 License, In-App Update Management & Hardened Security)

Official GNU AGPLv3 licensing paired with user-controlled in-app update checks and direct installer downloading, browser extension v1.0.1 RAM zeroization and CSP hardening, tactile micro-transition UI polish, and 21/21 passing adversarial security suites. 100% offline-first with zero cloud and zero telemetry.

#### 📦 Download Artifacts

| Platform | File | Architecture |
|---|---|---|
| **macOS** | [`Fuin-1.0.0-beta.7-arm64.dmg`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.7/Fuin-1.0.0-beta.7-arm64.dmg) | Apple Silicon (M1/M2/M3/M4) |
| **Windows** | [`Fuin Setup 1.0.0-beta.7.exe`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.7/Fuin.Setup.1.0.0-beta.7.exe) | Windows 10 / 11 (64-bit) |
| **Integrity** | [`SHA256SUMS.txt`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.7/SHA256SUMS.txt) | Checksum Verification |

#### 🛡️ Key Security & Feature Highlights

- **Official GNU AGPLv3 License:** Upgraded project licensing to the full official Affero General Public License Version 3 to ensure permanent open-source freedom and zero-knowledge privacy for all users.
- **In-App Update Management:** Added Settings toggle for "Check Updates on Startup" so users have complete control over read-only GitHub release pings, alongside direct one-click DMG/EXE downloading and installer launching from within the app.
- **Browser Extension v1.0.1 Hardening:** Zeroed memory and input buffers on save prompt dismissal and submit, enforced strict per-page CSP headers, added top-frame HTTPS validation and `sender.id` integrity guards. Verified with Mozilla `addons-linter` (0 errors).
- **Tactile Micro-Transitions & Generator UI Polish:** Aligned the Advanced Password Generator action button flush with the modal's bottom corners (`border-radius: 0 0 3px 3px`, zero layout shift), and codified snappy 120ms transitions across all navigation and interactive controls.
- **21/21 Automated Security Suites Passing:** Cryptographic KATs, Argon2id KDF, WAL durability, and air-gapped LAN P2P pairing suites all pass cleanly with zero regressions.

#### 🔒 Verification

```bash
# Verify checksums on macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or manually on macOS:
shasum -a 256 Fuin-1.0.0-beta.7-arm64.dmg
```

---

Security reports: hellofuin@gmail.com · Repository: github.com/Sombooo/Fuin
