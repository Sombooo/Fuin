# Fuin 1.0.0-Beta.8 — Release Notes

> **"What's New Modal, Reactive Dynamic i18n Sync & UI Refinement"**  
> *Version:* `1.0.0-beta.8`  
> *Release Date:* November 2026  
> *Architectural Standard:* Zero Cloud, Offline-First, P2P Sync  

---

## 🌟 What's New in Beta 8?

Fuin `v1.0.0-beta.8` introduces an offline-first **"What's New?"** changelog modal and release navigator directly within your secure vault. It also delivers instant multi-language (TR / EN) reactivity without restarting the app, and refined, distraction-free centered action layouts across Desktop and Mobile.

---

## 🛡️ Key Changes & Enhancements

1. **Offline "What's New?" & Release Navigator:**
   - Integrated warm organic dark modal accessible from Settings > System and on initial unlock.
   - Sticky version switcher tabs, category badge pills, and comprehensive release highlight breakdowns.

2. **Instant Dynamic Multi-Language (i18n) Reactivity:**
   - Dynamic `onLanguageChanged` listener ensuring tabs, cards, and modal components translate immediately upon toggling language.
   - Complete 1:1 key parity between English and Turkish dictionaries.

3. **Quietly Secure & Focused Action Layouts:**
   - Eliminated redundant product slogans and duplicate link lists from utility modals.
   - Centered, comfortably wide (max 360px) primary action buttons.
   - Platform-adaptive bottom padding on mobile footers (`Platform.OS === 'ios' ? 28 : 20`).

4. **Exhaustive Security Verification:**
   - 41 static checks and 22/22 desktop security suites passed cleanly.
   - 27 static checks and 10/10 mobile security suites passed cleanly.

---

## 📦 Downloads & Verification

| Platform | File | Architecture |
| :--- | :--- | :--- |
| **macOS** | [`Fuin-1.0.0-beta.8-arm64.dmg`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.8/Fuin-1.0.0-beta.8-arm64.dmg) | Apple Silicon (M1/M2/M3/M4) |
| **Windows** | [`Fuin Setup 1.0.0-beta.8.exe`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.8/Fuin.Setup.1.0.0-beta.8.exe) | Windows 10 / 11 (64-bit) |
| **Integrity** | [`SHA256SUMS.txt`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.8/SHA256SUMS.txt) | Checksum Verification |

Verify binary integrity:
```bash
shasum -a 256 Fuin-1.0.0-beta.8-arm64.dmg
```
