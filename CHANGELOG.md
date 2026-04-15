## 2.0.1

- Fix web compatibility (audio)

## 2.0.0

- Support for PoW v2 challenge format
- Migrated to `altcha_lib` for proof-of-work solving (supports PBKDF2, SHA, Scrypt, Argon2id)
- Native PBKDF2 C++ solver with SHA-NI / ARM SHA-2 acceleration on supported platforms