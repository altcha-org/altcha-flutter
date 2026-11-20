## 2.4.0

- Feature: HIS collector payload v2 (`v: 2`), compatible with the ALTCHA JS widget 3.6.0: adds `click` samples (`[x, y, t, hold, offsetX, offsetY, pointerType, moves]`), `key` samples (`[t, hold]`, hardware keyboard only, no key values), `untrusted` (always 0) and `webdriver`; stylus movement is now sampled as `pointer`
- Feature: when the code challenge carries `his: true`, the data collected since the challenge request is sent as `his` with the server verification request (ALTCHA Sentinel with `his.codeChallenge` blocked code-challenge verification without it)
- Fix: HIS `maxTouchPoints` reports real touchscreens instead of 0 (touch input was flagged as touch emulation): the browser's `navigator.maxTouchPoints` on web, `GetSystemMetrics(SM_MAXIMUMTOUCHES)` on Windows, and on Linux 10 for a multi-touch screen (1 for single-touch) found in `/proc/bus/input/devices`
- Fix: HIS scroll and interaction samples use a monotonic clock instead of the wall clock
- Breaking: `HisCollector.recordScroll` takes only the scroll offset; `HisCollector.attach()`/`detach()` also register/remove a `HardwareKeyboard` handler; the sample lists are read-only getters

## 2.3.0

- Fix Android build with AGP 9 built-in Kotlin: migrate to built-in Kotlin (drop `kotlin-android`, use `kotlin.compilerOptions`) and compile against Android SDK 36 [#9]
- Update the minimum supported SDK version to Flutter 3.44/Dart 3.12

## 2.2.0

- Send `Accept: application/json` with challenge, HIS and server verification requests
- Fix server verification request ignoring the custom `httpClient`

## 2.1.0

- Upgrade `altcha_lib` to 1.0.0
- Fix slow native PBKDF2 solver in iOS/macOS Debug builds (~6x): always compile the solver with `-O3` (CocoaPods and Swift Package Manager), matching Android/Linux

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