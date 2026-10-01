# Fuin Browser Extension / Tarayıcı Eklentisi

Companion browser extension for the [Fuin](https://github.com/Sombooo/Fuin) local-first password manager. Allows you to securely autofill your logins into web forms directly from your local desktop vault.

---

## 🦊 Firefox Installation

> **Status: Submitted to Firefox Add-ons (AMO) — Coming Very Soon!**  
> The extension has been submitted for review. Once approved, you will be able to install it with a single click from the official store without any manual setup.
> 
> In the meantime, you can load it temporarily via `about:debugging` -> **This Firefox** -> **Load Temporary Add-on...** -> select `manifest.json`.

---

## 🌐 Chrome, Brave & Edge Setup (Developer Mode)

Until the extension is published on the Chrome Web Store, you can run it locally in a few quick steps:

### 1. Load the Extension into Your Browser
1. Navigate to your browser's extensions page:
   - **Chrome / Brave:** `chrome://extensions`
   - **Edge:** `edge://extensions`
2. Enable **Developer Mode** (toggle in the top-right corner).
3. Click **Load unpacked** (Paketlenmemiş öğe yükle).
4. Select this `browser-extension/` directory.
5. Copy the generated 32-character **ID** shown on the extension card (e.g., `abcdefghijklmnop...`).

### 2. Register the Native Messaging Host
To allow the extension to talk to the Fuin desktop app, register the native messaging host on your system:

Open your terminal, navigate to the `native-host/` directory, and run:

```bash
node install-host.js --chrome-id=YOUR_COPIED_EXTENSION_ID
```

*(This command automatically installs the native messaging manifest for Chrome, Brave, and Edge on macOS, Linux, or Windows).*

### 3. Usage & Testing
1. Launch the Fuin desktop app and unlock your vault.
2. Open any website where you have saved credentials.
3. Click the **⬡** Fuin icon next to the login field.
4. Select your account to automatically autofill the form.

---

## 🛠️ Troubleshooting

- **"Fuin is not running":** Ensure the Fuin desktop app is launched.
- **"Fuin is locked":** Unlock your vault in the desktop application.
- **Connection Issues:** Re-run `node install-host.js --chrome-id=...` and restart your browser completely (browsers cache native host manifests on startup).

---

## 🔒 Security Architecture

- **Zero Cloud Exposure:** The extension never communicates with remote servers. All credential lookups occur strictly over local OS pipes (`stdio` socket bridge).
- **DOM Isolation:** Injected dropdown menus use closed Shadow DOM to prevent hostile page scripts from inspecting or scraping credentials.
- **User Gesture Verification:** Reveal requests require explicit user clicks (`isTrusted`) and approval from the desktop app.
- **Fixed Gecko ID:** Registered for Firefox as `fuin-app@sombo.dev`.
