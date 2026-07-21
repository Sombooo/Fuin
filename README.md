<div align="center">
  
# ⬡ Fuin
**Quietly secure.**

A minimalist, air-gapped, and ultra-secure local password manager. Built for privacy.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform: macOS | Windows | Linux](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgray.svg)](#)

</div>

<br />

Fuin is a next-generation password manager that runs entirely **offline**. It never connects to a server, never syncs your vault to a hidden cloud, and never asks for a subscription. Your data stays completely on your local machine, protected by military-grade encryption.

## 🛡️ Security Architecture

Fuin is designed with a paranoid approach to security, ensuring that even if your machine is compromised, your vault remains uncrackable.

| Layer | Technology | Description |
|---|---|---|
| **Key Derivation** | `Argon2id` | The strongest KDF against brute-force and GPU attacks. (64MB memory cost, 3 iterations) |
| **Encryption** | `AES-256-GCM` | Authenticated encryption that guarantees both privacy and data integrity. |
| **Memory Zeroing** | `Buffer.fill(0)` | Master keys are wiped entirely from your RAM the millisecond they are used. |
| **Timing Attacks** | `crypto.timingSafeEqual()` | Constant-time comparisons to prevent side-channel leaks. |
| **Entropy Analysis** | `zxcvbn` | Advanced password strength estimation built-in. |
| **Data Privacy** | `Air-Gapped` | No background telemetry, no cloud syncing. 100% offline. |

## 🚀 Installation & Usage

You can download the pre-compiled, ready-to-use installation files for your operating system from the [Releases](../../releases) tab.

> [!NOTE]
> **For macOS Users:** Since Fuin is a free and independent open-source project, the installer is not signed with a $99/year Apple Developer certificate. When you open the `.dmg`, macOS Gatekeeper might show an "unidentified developer" warning. This is completely normal for open-source apps. Simply **Right-Click** the Fuin app icon and select **Open** to bypass this warning safely. You only need to do this once.

### Building from Source

If you prefer to compile Fuin yourself:

```bash
# Clone the repository
git clone https://github.com/Sombooo/Fuin.git
cd Fuin

# Install dependencies
npm install

# Run in development mode
npm start

# Build for your platform
npm run build-mac    # macOS (.dmg)
npm run build-win    # Windows (.exe)
npm run build-linux  # Linux (.AppImage)
```

## 🧩 Browser Extension
Fuin comes with a companion browser extension for Chrome, Brave, and Firefox-based browsers. You can seamlessly autofill your credentials into websites directly from your local Fuin vault.
* Download the extension package from the `browser-extension` folder or install it via the Chrome Web Store / Firefox Add-ons (Links coming soon).

## 🗺️ Roadmap: Mobile App (Coming Late August)
The core cryptographic engine and the desktop version of Fuin are fully complete and stable. We are currently actively developing the **iOS and Android** versions!
Expect the mobile companion app to drop by the **end of August 2026**, bringing the exact same military-grade, offline-first security to your pocket.

## ☕ Support the Development

Fuin is an independent, open-source project. If you enjoy the absolute privacy and security it provides, consider supporting the continuous development of the desktop and upcoming mobile apps!

[![Support via Lemon Squeezy](https://img.shields.io/badge/Support_Fuin-Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](#)
*(Note: Replace the "#" in the link above with your actual Lemon Squeezy checkout URL once you set it up).*

---
<div align="center">
  <i>"Built for privacy. Designed for security."</i><br>
  Copyright © 2026 Fuin Dev.
</div>
