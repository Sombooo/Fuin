<div align="center">
  
# ⬡ Fuin
**Quietly secure.**

A minimalist, air-gapped, and ultra-secure local password manager. Built for privacy.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Platform: macOS | Windows | Linux](https://img.shields.io/badge/Platform-macOS%20%7C%20Windows%20%7C%20Linux-lightgray.svg)](#)

</div>

<br />

> [!NOTE]
> **Vibe Coding Project:** Fuin is built with AI-assisted "vibe coding". While it implements strict offline-first security principles, please explore, audit, and use it at your own discretion.

## What is Fuin?

Fuin is a local-first password manager designed to be simple, reliable, and completely private. 

Most modern password managers store your sensitive data on third-party cloud servers. Fuin takes a completely different path: **your vault never leaves your device**. There are no accounts to create, no servers listening in the background, and no telemetry tracking your habits.

- **100% Offline Vault:** Your data is encrypted and saved directly on your computer's disk.
- **Air-Gapped Sync:** Synchronize your vault to your mobile phone using animated QR codes—without ever connecting through the internet or local network.
- **Zero Cloud Dependence:** No subscription plans, no remote database breaches, and no account lockouts.

---

## 🧩 Browser Extension

Fuin includes a lightweight browser extension that lets you autofill your logins directly from your local vault into websites.

### Firefox
> **Coming Very Soon:** The official Firefox add-on has been submitted to **Firefox Add-ons (AMO)** and is currently under review. Once approved, you'll be able to install it with a single click.

### Chrome, Brave & Edge (Manual Setup)
Until the extension arrives on the Chrome Web Store, you can easily load it locally in developer mode:

1. Clone or download this repository.
2. Open your browser's extension manager:
   - **Chrome / Brave:** Navigate to `chrome://extensions`
   - **Edge:** Navigate to `edge://extensions`
3. Enable **Developer Mode** (toggle in the top-right corner).
4. Click **Load unpacked** (Paketlenmemiş öğe yükle).
5. Select the [`browser-extension`](./browser-extension) folder from the Fuin directory.
6. The Fuin icon will appear in your toolbar, ready to communicate with your desktop app.

---

## ⚙️ How It Works (Under the Hood)

We believe in honest, proven security without using marketing buzzwords like "military-grade." Here is exactly how Fuin protects your data:

- **Key Derivation (Argon2id):** When you set a master password, Fuin turns it into an encryption key using **Argon2id** (RFC 9106). This algorithm is memory-hard, making brute-force guessing attacks with GPUs or specialized hardware prohibitively expensive.
- **Vault Encryption (AES-256-GCM):** Your vault file is locked with authenticated **AES-256-GCM**, ensuring both total privacy and tamper detection. If a single byte of your vault file is modified, it cannot be decrypted.
- **Memory Safety:** Passwords are kept encrypted in memory and are only temporarily decrypted the moment you view or copy them. Cryptographic keys and sensitive byte buffers are zeroed (`Buffer.fill(0)`) immediately after use.
- **Safe Clipboard:** Copied passwords are automatically wiped from your operating system clipboard after 30 seconds.
- **Private Native Bridge:** Communication between your browser and desktop app happens locally over standard OS-level pipes using timing-safe token authentication.

---

## ☕ Support the Development

Fuin is an independent, open-source project. If you enjoy the absolute privacy and security it provides, consider supporting the continuous development of the desktop and upcoming mobile apps!

[![Support via Lemon Squeezy](https://img.shields.io/badge/Support_Fuin-Buy_Me_A_Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://fuindev.lemonsqueezy.com/checkout/buy/c898c753-098b-4c0b-a721-77332db06bdc)
