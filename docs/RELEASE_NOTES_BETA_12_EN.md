# Fuin 1.0.0-Beta.12 — Release Notes

> **"Native Android Clipboard Security, In-App Updater Reliability & Emergency Kit Fixes"**  
> *Version:* `1.0.0-beta.12`  
> *Release Date:* November 2026  
> *Architecture Standard:* Zero Cloud, Local-First, Offline P2P Sync  

---

## 🌟 What's New in Beta 12?

Fuin `v1.0.0-beta.12` delivers targeted reliability, security, and UI polish across both Fuin Desktop and Fuin Mobile. Mobile gains native Android `EXTRA_IS_SENSITIVE` masking alongside reliable background clipboard wiping (`AlarmManager` + `clearPrimaryClip()`), while Desktop resolves the in-app updater DMG truncation bug, persists newly regenerated recovery keys for Emergency Kit exports across lock cycles, refines Backup History scrollbars, and streamlines the Browser Extension Settings card.

---

## 🛡️ Key Features & Improvements

1. **Native Android Clipboard Security (`FuinMobile`):**
   - Tags copied passwords, cards, TOTP codes, and recovery keys with **`EXTRA_IS_SENSITIVE`** on Android 13+ for OS preview masking and Gboard history privacy.
   - Schedules reliable OS-level auto-clearing via **`AlarmManager` + `BroadcastReceiver` + `clearPrimaryClip()`** even while Fuin Mobile is backgrounded.
   - Monitors external clip replacements with `OnPrimaryClipChangedListener` so user copies never get overwritten by an older timer; persists zero plaintext on disk.
   - Routes recovery key copying through `copySecure()` and fixes Android 10+/iOS fallback expiry dropping when checked from the background.

2. **Reliable In-App Updater (`updateManager.js` & `main.js`):**
   - Eliminates the duplicate `click` listener bug that truncated freshly downloaded `.dmg` installers back to 0 bytes when clicking Install (`Disk image couldn't be opened / Invalid argument`).
   - Streams update downloads to an isolated `.part` temporary file and performs atomic rename after verifying downloaded byte length.

3. **Emergency Kit Key Sync & Backup History Polish:**
   - Encrypts an Argon2id + AES-256-GCM envelope on recovery key generation/verification and cross-checks it against on-disk `fuin.recovery` so Emergency Kit exports always reflect the latest active recovery key even after relocking.
   - Styles Backup History & Password History scrollbars with Fuin's warm-dark design tokens and clarifies the backup summary pill wording.

4. **Streamlined Browser Extension Settings Card:**
   - With official Chrome Web Store and Firefox extension bridges built in automatically, removes raw extension ID badges and cluttered manual developer fields from the Settings UI.

---

## 📦 Installation & Integrity Verification

Installer binaries (`dmg`, `exe`) and `SHA256SUMS.txt` are verified alongside the GitHub Release build artifacts (`npm run build-mac` / `npm run build-win` + `npm run checksums`):

```bash
# macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or individual check (macOS)
shasum -a 256 dist/Fuin-1.0.0-beta.12-arm64.dmg
```
