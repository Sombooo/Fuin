### Fuin Desktop v1.0.0-beta.6 (Seamless Autofill & Hardened API/IPC Security)

Seamless browser autofill & post-navigation credential capture paired with hardened Native Messaging IPC, strict external API boundaries, and 21/21 passing adversarial security suites. 100% offline-first with zero cloud and zero telemetry.

#### 📦 Download Artifacts

| Platform | File | Architecture |
|:---|:---|:---|
| **macOS** | [`Fuin-1.0.0-beta.6-arm64.dmg`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.6/Fuin-1.0.0-beta.6-arm64.dmg) | Apple Silicon (M1/M2/M3/M4) |
| **Windows** | [`Fuin Setup 1.0.0-beta.6.exe`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.6/Fuin.Setup.1.0.0-beta.6.exe) | Windows 10 / 11 (64-bit) |
| **Integrity** | [`SHA256SUMS.txt`](https://github.com/Sombooo/Fuin/releases/download/v1.0.0-beta.6/SHA256SUMS.txt) | Checksum Verification |

#### 🛡️ Key Security & Feature Highlights

- **Seamless Browser Autofill & Save Capture:** Split-login and SPA credential detection (`chess.com`, multi-step auth flows), closed Shadow DOM post-navigation save/update prompts, `Cmd+Shift+L` / `Ctrl+Shift+L` shortcut autofill, 30s auto-clearing clipboard copy from the extension popup, and in-app Chrome extension ID registration.
- **Hardened Native Messaging & Extension Isolation:** Per-user HMAC-derived Windows Named Pipe anti-squatting (`fuin-win32-pipe-v1`), POSIX `0o600` + UID ownership checks, 1 MB stdio/socket frame caps, `sender.frameId === 0` iframe phishing rejection, and expanded multi-tenant suffix isolation (`github.io`, `vercel.app`, `pages.dev`, `netlify.app`, etc.).
- **Strict External API & Vault Reprompt Guards:** `AbortController` timeouts, `redirect: 'error'`, response size caps, and strict `https://github.com/Sombooo/Fuin/` origin validation on update and HIBP k-Anonymity checks; Master Password Reprompt enforced on 2FA/TOTP view (`showTOTP`), self-contained HTML escaping in Emergency Kit exports, and 30s auto-clearing secure copy in the password generator.
- **Exhaustive Security Verification:** 21/21 automated security, cryptographic KAT, WAL durability, LAN P2P sync, and extension suites passing with 0 failures.

#### 🔒 Verification

```bash
# Verify checksums on macOS / Linux
sha256sum -c SHA256SUMS.txt

# Or manually on macOS:
shasum -a 256 Fuin-1.0.0-beta.6-arm64.dmg
```

---
*Security reports:* [hellofuin@gmail.com](mailto:hellofuin@gmail.com) · *Repository:* [github.com/Sombooo/Fuin](https://github.com/Sombooo/Fuin)
