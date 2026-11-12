# Fuin 1.0.0-Beta.10 — Release Notes

> **"Credit Card & Secure Note Vault, Auto-Formatting, and Enterprise Security Audit"**  
> *Version:* `1.0.0-beta.10`  
> *Release Date:* November 2026  
> *Architecture Standard:* Zero Cloud, Local-First, Offline P2P Sync  

---

## 🌟 What's New in Beta 10?

Fuin `v1.0.0-beta.10` expands the vault capability by introducing dedicated **Credit Card** and **Encrypted Secure Note** entry types. Card numbers are dynamically auto-formatted into 4-digit groups (`0000 0000 0000 0000`), MM/YY expiry dates and CVV codes are masked, and card brands (Visa, Mastercard, Troy, Amex) are identified client-side. It also delivers live dynamic TR/EN language reactivity inside open modals, 2FA interface spacing refinements, and comprehensive enterprise security audit verification.

---

## 🛡️ Key Features & Improvements

1. **Credit Card Vault & Smart Auto-Formatting:**
   - Real-time 4-digit grouping for card numbers, MM/YY expiry formatting, and 3-4 digit CVV masking.
   - Client-side card brand detection for Visa, Mastercard, Troy, and Amex.
   - One-click secure clipboard copy actions (`copy-card-num`, `copy-cvv`) with automatic 30s clipboard purge.

2. **AES-256-GCM Encrypted Secure Notes:**
   - Dedicated zero-knowledge vault storage for private recovery codes, server keys, or confidential notes with one-click copy.

3. **Dynamic Multi-Language Parity (i18n) & UI Polish:**
   - Live TR/EN language switching while entry creation/editing modals are active.
   - Neutral and professional `"İsim Soyisim"` (TR) / `"First & Last Name"` (EN) placeholders.
   - Refined 2FA flexbox spacing (`gap: 12px`) preventing visual collision with modal dividers.
   - Full-width layout for the Settings Security Info card and borderless styling for lock screen biometric buttons.

4. **Enterprise-Grade Security Audit & Repository Hygiene:**
   - AST regex credential scanning across all repositories confirming 0 secret leaks.
   - Complete cleanup of OS artifacts (`.DS_Store`) and exclusion of ~10 MB promo video assets from electron-builder distribution packages.
   - 29 Desktop test suites and 10 Mobile test suites verifying zero regressions.

---

## 📦 Installation & Verification

| Platform | File | Architecture | SHA-256 |
|---|---|---|---|
| **macOS** | `Fuin-1.0.0-beta.10-arm64.dmg` | Apple Silicon (M1/M2/M3/M4) | `093e85889900620119291a5fb4dc2e0d57c6881296ab0101919e81bc4e4d7365` |
| **Windows** | `Fuin Setup 1.0.0-beta.10.exe` | Windows 10 / 11 (64-bit) | `1c9c8b1f09a4ec3f8007d7144c9daea69a800849fb0f6ede00c6f7805a70ffed` |
| **Integrity** | `SHA256SUMS.txt` | Checksum Verification | — |

To verify the cryptographic integrity of downloaded installation packages:

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or individual check (macOS)
shasum -a 256 Fuin-1.0.0-beta.10-arm64.dmg
```
