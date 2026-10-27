# PRIVACY POLICY & DISCLOSURES

Fuin is built on a strict **local-first, zero-knowledge** privacy model.

## 1. What We Do Not Collect
- **No Cloud Storage:** Your vault is never uploaded to or stored on any remote server.
- **No User Accounts:** Fuin requires no registration, email address, phone number, or personal identifier.
- **No Telemetry or Analytics:** Neither Fuin Desktop nor Fuin Mobile includes any analytics SDKs, crash reporters, or usage trackers.

## 2. Local Data Storage
All passwords, TOTP seeds, categories, and notes are encrypted with **AES-256-GCM** and stored exclusively on your local device filesystem (`0o600` owner-only permissions on Desktop; sandboxed app storage and hardware-backed `SecureStore` on Mobile).

## 3. Cross-Device Synchronization
Your data only moves between your own devices when you explicitly initiate a sync session:
- **Local LAN P2P Sync:** Transfers XChaCha20-Poly1305 encrypted vault packets directly between your Desktop and Mobile devices over your private local network (RFC1918 Wi-Fi or phone hotspot) using a temporary 120-second listener. Initial trust is established once via an optical QR code pairing exchange. No third-party servers, relays, or cloud intermediaries are ever involved.

## 4. Optional External Network Requests
Fuin operates completely offline by default. External HTTPS requests occur only in two user-controlled scenarios:
1. **Password Breach Check (HIBP k-Anonymity):** When you manually run a breach scan in the Health tab, Fuin sends only the first **5 characters** of each password's SHA-1 hash to `https://api.pwnedpasswords.com/range/` with `Add-Padding: true` and `cache: 'no-store'`. Your actual passwords or full hashes never leave your device.
2. **Release Update Check:** Fuin checks the public GitHub Releases API (`https://api.github.com/repos/Sombooo/Fuin/releases/latest`) over HTTPS to notify you when a new version is available.

## 5. Browser Extension Permissions
The Fuin Browser Extension requests only the minimum privileges required to operate:
- `activeTab`: To identify login fields and populate credentials only when triggered by the user.
- `nativeMessaging`: To communicate locally with the Fuin Desktop app over an OS-level pipe.
- `host_permissions ("https://*/*")`: Restricts autofill operation strictly to HTTPS origins.
