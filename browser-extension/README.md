# Fuin Browser Extension / Tarayıcı Eklentisi

Companion browser extension for the [Fuin](https://github.com/Sombooo/Fuin) offline-first password manager. Connects locally to your unlocked Fuin Desktop app over OS native messaging so you can fill logins or copy cards/notes without storing anything in the cloud.

---

## 🌐 Installation (Chrome, Firefox, Brave & Edge)

> **Status: Ready on Firefox Add-ons & Chrome Web Store**  
> Both the **Firefox** and **Chrome / Chromium** extensions are ready. You can install them from the official browser stores—or if you prefer inspecting and running directly from source, you can load this [`browser-extension/`](./) folder manually.

### Running Manually from Source (Optional / Developer Mode)

#### Firefox (`about:debugging`)
1. Open `about:debugging` -> **This Firefox** -> **Load Temporary Add-on...**
2. Select [`manifest.json`](./manifest.json) inside this directory (`fuin-app@sombo.dev`).

#### Chrome, Brave & Edge
1. Open `chrome://extensions` (or `edge://extensions`).
2. Enable **Developer Mode**.
3. Click **Load unpacked** and select this [`browser-extension/`](./) directory.
4. Copy the 32-character extension **ID** shown on the card, then register the native messaging host from `native-host/`:

```bash
node install-host.js --chrome-id=YOUR_COPIED_EXTENSION_ID
```

*(Note: Official store installs use Fuin Desktop's built-in bridge IDs automatically; restart your browser once if native messaging was just installed).*

---

## 🔒 How It Works Underneath

- **Local Only:** No external requests or telemetry. Credentials stay inside the Fuin Desktop vault until requested.
- **Local Socket & Symlink Isolation:** `native-host/host.js` talks to Desktop over owner-only UNIX sockets (`0o600` / `0o700` dir, `lstatSync` symlink checks) or private Windows named pipes with per-message HMAC authentication.
- **DOM & Domain Isolation:** Menus render inside closed Shadow DOM, click/autofill actions verify trusted user input (`isTrusted`), cross-origin subframes are blocked, and multi-tenant hosts (e.g., `github.io`, `wordpress.com`, `vercel.app`) match by exact subdomain.
- **No Silent Autofill:** Passwords are only populated when you trigger a fill from the icon, shortcut (`Ctrl+Shift+L` / `Cmd+Shift+L`), or popup.
