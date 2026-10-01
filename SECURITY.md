# SECURITY ARCHITECTURE

Fuin is designed with an offline-first, local-first architecture. 

## Implemented Guarantees
- **Vault Encryption:** Local vault is protected with authenticated encryption.
- **Sync V2 Cryptography:** Desktop-to-Mobile transfers utilize an independent cryptographic envelope (Argon2id, XChaCha20-Poly1305).
- **Argon2id Parameters:** m=65536, t=3, p=4. (No fallback to PBKDF2).
- **Sync vs Vault Separation:** The Air-Gap Sync password is mathematically isolated from the Master Vault password.
- **Replay / Generation Protection:** Sync V2 payloads carry a strictly incrementing generation integer to reject stale/replayed QR payloads.
- **QR Transport Integrity:** CRC-32 and strict Base45 formatting prevent malformed data from reaching the decryption layer.
- **Local Edit Protection:** Mobile users are explicitly prompted if incoming Desktop Sync data conflicts with local vault edits.

## Implementation Limitations
- **Plaintext Lifetime:** JavaScript V8 garbage collection limits the ability to deterministically zeroize string memory. We use `Buffer.fill(0)` for byte arrays (keys, intermediate ciphertexts), but parsed JSON/CBOR objects rely on the engine's GC cycles.
- **Platform Limitations:** Operating system capabilities may allow screenshots on certain mobile platforms despite our best-effort `ScreenCapture` prevention. Biometric unlocking (e.g. TouchID/FaceID) falls back to the device PIN/passcode depending on the OS configuration.

## Not Tested
- We have mathematically simulated real-device cryptographic interoperability (Desktop `argon2` -> React Native `react-native-argon2`), but we have **NOT** yet verified the execution on actual physical hardware limits (CPU/RAM).

## Responsible Disclosure
If you find a security flaw, please contact the maintainers directly before public disclosure.
