## 2.0.5

- Fix "No Material widget found" error on Flutter 3.47+ by giving the widget its own Material ancestor [#8]

## 2.0.4

- Fix build with Swift Package Manager [#7]

## 2.0.3

- Fix Windows CMakeLists in debug [#6]

## 2.0.2

- Fix formatting and web compatibility

## 2.0.1

- Fix web compatibility (audio)

## 2.0.0

- Support for PoW v2 challenge format
- Migrated to `altcha_lib` for proof-of-work solving (supports PBKDF2, SHA, Scrypt, Argon2id)
- Native PBKDF2 C++ solver with SHA-NI / ARM SHA-2 acceleration on supported platforms