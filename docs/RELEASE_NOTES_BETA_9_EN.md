# Fuin 1.0.0-Beta.9 — Release Notes

> **"SHA-256 Backup History, Recovery Key Self-Test & Emergency Kit Redesign"**  
> *Version:* `1.0.0-beta.9`  
> *Release Date:* November 2026  
> *Architectural Standard:* Zero Cloud, Offline-First, P2P Sync  

---

## 🌟 What's New in Beta 9?

Fuin `v1.0.0-beta.9` elevates serverless, 100% offline disaster recovery. It introduces **SHA-256 Integrity-Verified Backup History** with point-in-time snapshot restore, portable encrypted `.fuin` vault backups, an offline **Recovery Key Self-Test** verifier, and a redesigned **Emergency Kit** crafted in Fuin's Warm Dark and Warm Paper design system.

---

## 🛡️ Key Changes & Enhancements

1. **SHA-256 Backup History & Point-in-Time Restore:**
   - Automatic and manual vault snapshots are tracked with SHA-256 digests and automatic deduplication.
   - Inspect verified snapshots and restore any point-in-time backup directly from Settings > Automatic Backups.

2. **Recovery Key Self-Test & Encrypted `.fuin` Vault Backup:**
   - Verify that your Recovery Key matches your vault offline without resetting your master password.
   - Export and import portable Argon2id + AES-256-GCM encrypted `.fuin` backup archives.

3. **Warm Dark & Warm Paper Emergency Kit Redesign:**
   - Redesigned Emergency Kit HTML featuring Fuin's `#1a1816` Warm Dark and `#f5f0e8` Warm Paper themes, official flat-top hexagon logo, interactive theme switch, A4 print stylesheet, and strict offline Content-Security-Policy.

4. **Deep Security Hardening (`SEC-01`..`SEC-05`):**
   - Enforced unlocked-vault checks and `fs.lstatSync` symlink rejection across backup, recovery, and file import IPCs.
   - Replaced plaintext password concatenation in browser extension dismissal caches with per-session keyed digests (`hashDismissedKey`) and active memory sweeping.
   - Added complete closure and modal DOM scrubbing upon vault lock (`lock()`).

---

## 📦 Downloads & Verification

| Platform | File | Architecture |
| :--- | :--- | :--- |
| **macOS** | [`Fuin-1.0.0-beta.9-arm64.dmg`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.9/Fuin-1.0.0-beta.9-arm64.dmg) | Apple Silicon (M1/M2/M3/M4) |
| **Windows** | [`Fuin Setup 1.0.0-beta.9.exe`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.9/Fuin.Setup.1.0.0-beta.9.exe) | Windows 10 / 11 (64-bit) |
| **Integrity** | [`SHA256SUMS.txt`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.9/SHA256SUMS.txt) | Checksum Verification |

Verify binary integrity:
```bash
shasum -a 256 Fuin-1.0.0-beta.9-arm64.dmg
```
