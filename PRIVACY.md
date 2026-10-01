# PRIVACY POLICY & DISCLOSURES

Fuin takes a strict local-first and offline-first approach to your data.

## What we DO NOT do:
- **No Cloud Infrastructure:** We do not host your vault on our servers.
- **No Accounts:** You do not need to register an account to use Fuin.
- **No Telemetry:** We do not collect product analytics, crash logs, or telemetry.

## What information is stored locally:
Your passwords, OTP seeds, and secure notes are encrypted and stored purely on your local filesystem (Desktop and Mobile). 

## Data Transfers (Air-Gap Sync V2):
- Files and vault entries remain local unless you explicitly initiate an Air-Gap Sync transfer.
- The transfer is strictly Desktop → Mobile via animated QR codes.
- No network connection (Wi-Fi, Bluetooth, or LAN) is used for the transfer.
- Your vault data NEVER leaves your physical proximity.

## Browser Extension Permissions
The Fuin Browser Extension requests the following permissions:
- `activeTab`: To fill passwords into the current page upon user action.
- `nativeMessaging`: To communicate securely with the Fuin Desktop application locally over a socket.
- `host_permissions: "https://*/*"`: Password filling is explicitly restricted to secure HTTPS websites.

No information is ever sent to external APIs by the extension.
