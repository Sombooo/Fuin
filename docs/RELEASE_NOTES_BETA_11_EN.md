# Fuin 1.0.0-Beta.11 — Release Notes

> **"2FA QR Scanner, Extension Protocol Handshake & Card/Note Copy, and Portable Backup Parity"**  
> *Version:* `1.0.0-beta.11`  
> *Release Date:* November 2026  
> *Architecture Standard:* Zero Cloud, Local-First, Offline P2P Sync  

---

## 🌟 What's New in Beta 11?

Fuin `v1.0.0-beta.11` delivers key usability, portability, and security upgrades across Desktop, Browser Extension, and Fuin Mobile. It introduces mandatory protocol version handshakes (`PROTOCOL_VERSION = 1`) between the Native Host and the extension alongside zero-knowledge **Credit Card** & **Secure Note** copying directly from the extension popup. On mobile, it adds a full-screen **2FA `otpauth://` QR scanner**, live **30s TOTP countdown codes**, single-step biometric unlock, cross-platform `.fuin` backup compatibility, and clear **AP Isolation (Personal Hotspot)** guidance during LAN P2P sync.

---

## 🛡️ Key Features & Improvements

1. **Native Host ↔ Browser Extension Protocol Handshake & Card/Note Copy:**
   - Enforces a `PROTOCOL_VERSION = 1` handshake across the extension and native host bridge to detect version mismatches safely.
   - Adds **Logins**, **Cards**, and **Notes** segmented tabs inside the extension popup with full TR/EN localization (`popup.html` / `popup.js`).
   - Copies card numbers, CVVs, and secure notes via Fuin Desktop's **30-second auto-clearing clipboard** without transferring raw card/note secrets over Native Messaging; blocks silent copy on `reprompt`-protected items.

2. **Universal 2FA QR (`otpauth://`) & Portable `.fuin` / CSV / JSON Import Parity:**
   - Standardizes `otpauth://` URI parsing (`totpEngine.js`) and 6-digit TOTP verification across Desktop and Mobile.
   - Expands Chrome, Bitwarden, 1Password, and LastPass CSV/JSON importers to cover Credit Cards and Secure Notes seamlessly.
   - Supports Argon2id and PBKDF2-SHA512 encrypted `.fuin` vault backup portability between Desktop and Mobile.

3. **Fuin Mobile 2FA QR Scanner, Live TOTP & Single-Step Biometric Unlock:**
   - Fixes full-screen Android CameraView layout rendering and aiming reticle alignment.
   - Displays live auto-refreshing 30s TOTP verification codes directly on mobile vault cards.
   - Streamlines mobile unlock to a single biometric authentication prompt.

4. **LAN Sync AP Isolation (Personal Hotspot) Guidance:**
   - Adds non-intrusive TR/EN tips in the Desktop LAN Sync modal, sync timeout toast, and Mobile pairing/unreachable alerts guiding users on AP-isolated corporate or dorm Wi-Fi to connect via Personal Hotspot.

---

## 📦 Installation & Integrity Verification

Installer binaries (`dmg`, `exe`) and `SHA256SUMS.txt` are verified alongside the GitHub Release build artifacts (`npm run build-mac` / `npm run build-win` + `npm run checksums`):

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or individual check (macOS)
shasum -a 256 dist/Fuin-1.0.0-beta.11-arm64.dmg
```
