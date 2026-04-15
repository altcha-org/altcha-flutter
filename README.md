# altcha_widget

A native Flutter widget for [ALTCHA](https://altcha.org) — a privacy-first, self-hosted CAPTCHA alternative based on proof-of-work. No tracking, no third-party calls, compliant with GDPR and global data privacy regulations.

## Features

- Proof-of-work challenge solving (PoW v2 format)
- Multi-algorithm support: PBKDF2/SHA-, SHA-, Scrypt, Argon2id
- Native PBKDF2 acceleration: ARM SHA-2 (Android, iOS, macOS, Linux/Windows ARM64), Intel SHA-NI (Linux/Windows x86-64)
- Parallel solving via Dart isolates (configurable concurrency)
- Pluggable `deriveKey` callback for custom algorithm implementations (e.g. Argon2id via `sodium`)
- Optional server-side verification (ALTCHA Sentinel)
- Code challenge support (image + audio)
- Human Interaction Signature (HIS) collection
- Built-in localization: English, German, Spanish, French, Italian, Portuguese
- Custom translation overrides
- Theme-aware (light / dark via `Theme`)


## Screenshots

<div>
  <img
    src="https://raw.githubusercontent.com/altcha-org/altcha-flutter/refs/heads/main/assets/images/screen-widget.png"
    alt="ALTCHA Widget."
    width="200">
  <img
    src="https://raw.githubusercontent.com/altcha-org/altcha-flutter/refs/heads/main/assets/images/screen-code.png"
    alt="ALTCHA Widget with Code Challenge."
    width="200">
</div>

## Platform support

The widget is optimized for the PBKDF2/SHA-256 algorithm. Scrypt and Argon2id are implemented in pure Dart (`pointycastle`) and are expected to be significantly slower than a native library. Use the `sodium` package for performant Argon2id — see [Custom deriveKey](#custom-derivekey).

| Platform | SHA-256      | PBKDF2                                    | SCRYPT | ARGON2ID |
| -------- | ------------ | ----------------------------------------- | ------ | -------- |
| Android  | native       | native C++ (ARM SHA-2)                    | Dart   | Dart     |
| iOS      | native       | native C++ (ARM SHA-2)                    | Dart   | Dart     |
| macOS    | native       | native C++ (ARM SHA-2 / x86 scalar)       | Dart   | Dart     |
| Linux    | Dart         | native C++ (SHA-NI / ARM SHA-2 / scalar)  | Dart   | Dart     |
| Windows  | Dart         | native C++ (SHA-NI / ARM SHA-2 / scalar)  | Dart   | Dart     |
| Web      | SubtleCrypto | SubtleCrypto                              | —      | —        |

## Benchmarks

The native C++ PBKDF2 implementation performs approximately 2x better than the browser's WebCrypto on the same hardware. Results below were measured with `PBKDF2/SHA-256` (`cost=5000, counter=5000`); the multiplier is relative to the WebCrypto baseline on the same device.

| Platform | 1 Worker     | 4 Workers    |
| -------- | ------------ | ------------ |
| Android  | 2.1s (~1.5x) | 0.8s (~2.5x) |
| iOS      | 1.8s (~2x)   | 0.7s (~1.6x) |
| macOS    | 1.8s (~0.8x) | 0.4s (~3.1x) |

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  altcha_widget: ^2.0.0
```

> **Note:** `altcha_widget` depends on `just_audio` for audio code challenges. Platform-specific setup may be required — see the [just_audio README](https://pub.dev/packages/just_audio#readme) for details.

## Basic usage

Wrap your app with the localization delegate and drop `AltchaWidget` into your form:

```dart
import 'package:altcha_widget/altcha_widget.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

MaterialApp(
  localizationsDelegates: [
    const AltchaLocalizationsDelegate(),
    GlobalMaterialLocalizations.delegate,
    GlobalWidgetsLocalizations.delegate,
    GlobalCupertinoLocalizations.delegate,
  ],
  supportedLocales: const [Locale('en')],
  home: MyPage(),
);
```

```dart
AltchaWidget(
  challenge: 'https://your-server.example/challenge',
  onVerified: (String payload) {
    // payload is a base64-encoded JSON string.
    // Include it as the `altcha` field when submitting your form.
    print('Verified: $payload');
  },
  onFailed: (Object error) {
    print('Verification failed: $error');
  },
)
```

## ALTCHA Sentinel

When used with ALTCHA Sentinel, the widget automatically submits the solved PoW payload to Sentinel for server-side verification:

```dart
AltchaWidget(
  challenge: 'https://sentinel.example.com/v1/challenge?apiKey=...',
  onServerVerification: (AltchaServerVerification result) {
    if (result.verified) {
      print('Score: ${result.score}');
    }
  },
  onVerified: (String payload) {
    // Called after successful server verification.
  },
)
```

## Programmatic control

Use a `GlobalKey<AltchaWidgetState>` to trigger or reset verification from code:

```dart
final _altchaKey = GlobalKey<AltchaWidgetState>();

// Trigger verification
_altchaKey.currentState?.verify();

// Reset back to idle
_altchaKey.currentState?.reset();

AltchaWidget(key: _altchaKey, challenge: '...')
```

## Pre-fetched challenge

If you already have a challenge JSON, pass the map directly:

```dart
AltchaWidget(
  challenge: {
    'parameters': {
      'algorithm': 'PBKDF2/SHA-256',
      'cost': 1000,
      'keyLength': 32,
      'keyPrefix': '00',
      'nonce': '...',
      'salt': '...',
    },
    'signature': '...',
  },
  onVerified: (payload) { ... },
)
```

## Headless solving

Use `solveChallenge` to solve a challenge without the UI widget — useful for background verification, custom UI flows, or server-to-server use cases.

```dart
import 'package:altcha_widget/altcha_widget.dart';
import 'package:http/http.dart' as http;

// 1. Fetch a challenge
final response = await http.get(Uri.parse('https://your-server.example/challenge'));
final challenge = AltchaChallenge.fromJson(jsonDecode(response.body));

// 2. Solve it (uses native C++ for PBKDF2, Dart isolates for other algorithms)
final solution = await solveChallenge(
  challenge: challenge.challenge,
  concurrency: 4,    // parallel workers (default 4)
  timeoutMs: 90000,  // timeout in ms (default 90 s)
);

if (solution != null) {
  // 3. Build the payload and submit to your server
  final payload = base64.encode(utf8.encode(jsonEncode({
    'challenge': challenge.challenge.toJson(),
    'solution': solution.toJson(),
  })));
  // Include `payload` as the `altcha` field in your form or API request.
}
```

Pass a custom `deriveKey` for non-PBKDF2 algorithms such as Argon2id (see [Custom deriveKey](#custom-derivekey)):

```dart
final solution = await solveChallenge(
  challenge: challenge.challenge,
  deriveKey: sodiumDeriveKey,
);
```

## Human Interaction Signature (HIS)

Some ALTCHA Sentinel configurations require a Human Interaction Signature before issuing a challenge. When the server requests HIS data, the widget automatically collects pointer, touch, and scroll events, submits them to the server, and uses the response as the actual challenge.

HIS collection is disabled by default. Enable it with `humanInteractionSignature: true`.

### Early collection

For the best signal quality, start the collector before the ALTCHA widget appears on screen. Create a `HisCollector`, call `attach()` at app start, and pass it to the widget:

```dart
import 'package:altcha_widget/altcha_widget.dart';

// Start collecting at app launch (e.g. in main() or your root widget's initState).
final collector = HisCollector()..attach();

// Later, in your widget tree:
AltchaWidget(
  challenge: 'https://your-server.example/challenge',
  humanInteractionSignature: true,
  collector: collector,
  onVerified: (payload) { ... },
)

// When the app exits (optional — OS will clean up):
collector.detach();
```

When a `collector` is provided, the widget uses it as-is and does not register its own pointer route. When omitted and `humanInteractionSignature` is `true`, the widget creates an internal collector that is active only while the widget is on screen.

### Origin

To allow server-side origin restriction, set `origin` to your app's bundle identifier or package name. The widget sends it as both the `Origin` and `Referer` headers:

```dart
AltchaWidget(
  challenge: 'https://your-server.example/challenge',
  origin: 'com.example.myapp',
  // Sends: Origin: https://com.example.myapp
  //        Referer: https://com.example.myapp/
  onVerified: (payload) { ... },
)
```

A full `https://` URL is also accepted and used as-is.

## Parameters

| Parameter                   | Type                                      | Default | Description                                                                                       |
| --------------------------- | ----------------------------------------- | ------- | ------------------------------------------------------------------------------------------------- |
| `challenge`                 | `Object?`                                 | —       | URL string to fetch the challenge from, or a pre-fetched `Map<String, dynamic>` JSON object.      |
| `collector`                 | `HisCollector?`                           | —       | External HIS collector started before the widget is shown. See [Human Interaction Signature](#human-interaction-signature-his). |
| `concurrency`               | `int`                                     | `4`     | Number of isolates for parallel solving (native only). Set to `1` to solve on a single isolate.   |
| `debug`                     | `bool`                                    | `false` | Print verbose logs to the console.                                                                |
| `deriveKey`                 | `DeriveKeyFunction?`                      | —       | Custom key-derivation function. See [Custom deriveKey](#custom-derivekey).                        |
| `hideFooter`                | `bool?`                                   | —       | Hide the "Protected by ALTCHA" footer.                                                            |
| `hideLogo`                  | `bool?`                                   | —       | Hide the ALTCHA logo.                                                                             |
| `httpClient`                | `http.Client`                             | default | Custom HTTP client (useful for testing or proxies).                                               |
| `httpHeaders`               | `Map<String, String>?`                    | `{}`    | Extra headers added to all HTTP requests. Takes priority over auto-generated headers.             |
| `humanInteractionSignature` | `bool`                                    | `false` | Enable HIS event collection and submission.                                                       |
| `minDuration`               | `int`                                     | `500`   | Minimum milliseconds the "verifying" state is shown, so the progress indicator is always visible. |
| `origin`                    | `String?`                                 | —       | App bundle ID or package name sent as `Origin` and `Referer` headers on native platforms.         |
| `onFailed`                  | `ValueChanged<Object>?`                   | —       | Called with the exception on failure.                                                             |
| `onServerVerification`      | `ValueChanged<AltchaServerVerification>?` | —       | Called with the server verification result.                                                       |
| `onVerified`                | `ValueChanged<String>?`                   | —       | Called with the base64 payload on success.                                                        |

## Localization

The widget ships with built-in translations for **en, de, es, fr, it, pt**. Register the delegate in your `MaterialApp`:

```dart
const AltchaLocalizationsDelegate()
```

### Custom translations / overrides

Override specific keys or add a new language:

```dart
AltchaLocalizationsDelegate(
  customTranslations: {
    'en': {
      'label': 'Prove you\'re human',
    },
    'ja': {
      'label': '私はロボットではありません',
      // ... other keys
    },
  },
)
```

### Translation keys

| Key                    | Default (en)                          |
| ---------------------- | ------------------------------------- |
| `cancel`               | Cancel                                |
| `enterCode`            | Enter code                            |
| `error`                | Verification failed. Try again later. |
| `expired`              | Verification expired. Try again.      |
| `footer`               | Protected by ALTCHA                   |
| `incompleteCode`       | Incomplete code. Try again.           |
| `label`                | I'm not a robot                       |
| `playAudio`            | Play Audio                            |
| `reload`               | Reload                                |
| `required`             | Required                              |
| `stopAudio`            | Stop Audio                            |
| `verify`               | Verify                                |
| `verificationRequired` | Verification required!                |
| `verified`             | Verified                              |
| `verifying`            | Verifying...                          |

## Custom deriveKey

The `deriveKey` parameter lets you replace the built-in Dart key-derivation implementation with any library-backed function. The primary use case is **Argon2id**, where the built-in pure-Dart implementation is approximately 3.5x slower than a native library such as `sodium`.

The function signature matches `DeriveKeyFunction` from `altcha_lib`:

```dart
typedef DeriveKeyFunction = Future<DeriveKeyResult> Function(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
);
```

When `deriveKey` is set, the widget runs the function in a background isolate via `Isolate.run()`, which supports closures. Any heavy resource (e.g. a `sodium` instance) should be **initialised inside the function itself**, not captured from the calling isolate, to ensure it is available in the spawned context.

### Example: Argon2id via `sodium`

```yaml
# pubspec.yaml
dependencies:
  altcha_widget: ^2.0.0
  sodium: ^4.0.2
```

```dart
import 'dart:typed_data';
import 'package:altcha_widget/altcha_widget.dart';
import 'package:sodium/sodium.dart';

Future<DeriveKeyResult> sodiumDeriveKey(
  ChallengeParameters params,
  List<int> salt,
  List<int> password,
) async {
  // Initialise sodium inside the isolate.
  final sodium = await SodiumInit.init();
  final key = sodium.crypto.pwhash.call(
    outLen: params.keyLength,
    password: Int8List.fromList(password),
    salt: Uint8List.fromList(salt),
    opsLimit: params.cost,
    memLimit: (params.memoryCost ?? 65536) * 1024,
    algorithm: CryptoPwhashAlgorithm.argon2id13,
  );
  return DeriveKeyResult(derivedKey: key.extractBytes());
}

AltchaWidget(
  challenge: 'https://your-server.example/challenge',
  deriveKey: sodiumDeriveKey,
  onVerified: (payload) { ... },
)
```

> **Tip:** `deriveKey` is called for all non-PBKDF2 algorithms. If your server may issue multiple algorithm types, check `params.algorithm` and delegate to `adaptiveDeriveKey` for the ones you do not handle:
>
> ```dart
> import 'package:altcha_widget/altcha_widget.dart';
>
> Future<DeriveKeyResult> myDeriveKey(
>   ChallengeParameters params,
>   List<int> salt,
>   List<int> password,
> ) async {
>   if (params.algorithm.toUpperCase() == 'ARGON2ID') {
>     return sodiumDeriveKey(params, salt, password);
>   }
>   return adaptiveDeriveKey(params, salt, password);
> }
> ```

## Payload format

The `onVerified` callback receives a base64-encoded JSON payload:

```json
{
  "challenge": {
    "parameters": {
      "algorithm": "PBKDF2/SHA-256",
      "cost": 5000,
      "keyLength": 32,
      "keyPrefix": "00ab...",
      "nonce": "...",
      "salt": "..."
    },
    "signature": "..."
  },
  "solution": {
    "counter": 4231,
    "derivedKey": "00ab...",
    "time": 1.23
  }
}
```

Pass this value as the `altcha` field in your form submission. Verify it server-side using [`altcha_lib`](https://pub.dev/packages/altcha_lib) or any other ALTCHA server library.

## Native PBKDF2 implementation (Android, iOS, macOS, Linux, Windows)

All native platforms use a shared C++ PBKDF2 implementation rather than the platform crypto APIs. The primary motivation differs by platform:

### Why not the platform crypto API?

**Android — Java Cryptography Architecture (JCA)**

`AndroidOpenSSL` (Conscrypt) does not register `SecretKeyFactory` for PBKDF2 at all. The Android security team scoped Conscrypt to TLS, ciphers, MACs, and message digests, delegating password-based key derivation to BouncyCastle. The underlying BoringSSL library does internally call `PKCS5_PBKDF2_HMAC` with correct raw-byte semantics for operations such as PKCS#8 key decryption, but that code path is never exposed through the JCA interface.

`BC` (BouncyCastle) registers `PBKDF2WithHmacSHA256` but converts the password `char[]` to bytes using UTF-8 encoding. Characters in the range `0x80–0xFF` expand to two-byte sequences (e.g. `0x80` → `0xC2 0x80`), which diverges from the raw-byte HMAC semantics used by the Dart and JavaScript implementations. The corrective `PBKDF2WithHmacSHA256And8bit` variant is not present in Android's stripped BouncyCastle distribution.

**iOS / macOS — CommonCrypto**

CommonCrypto's `CCKeyDerivationPBKDF` is semantically correct, but reinitialises the full HMAC state (ipad and opad SHA compressions) on every PBKDF2 internal iteration. The C++ implementation precomputes the ipad and opad states once per call and clones them for each iteration, halving the number of SHA-256 compressions from ~4 to ~2 per iteration.

**Linux / Windows**

No platform PBKDF2 API is available that is both semantically correct and accessible from Flutter plugins without heavy system dependencies. The portable C++ solver is used directly.

### What the C++ library does

The implementation uses HMAC ipad/opad precomputation and hardware SHA-2 acceleration where available:

- **Android**: `vsha256*` ARM intrinsics, enabled at runtime via `getauxval(AT_HWCAP) & HWCAP_SHA2`. Falls back to scalar C++ on x86 (emulator) and older ARM32 devices.
- **iOS**: ARM SHA-2 always active — all supported devices (iOS 12+, A9+) have the extension. Detected at compile time via `__ARM_FEATURE_SHA2`.
- **macOS**: ARM SHA-2 on Apple Silicon; scalar C++ on Intel, selected at compile time per architecture slice.
- **Linux / Windows (x86-64)**: Intel SHA Extensions (`SHA-NI`) detected at runtime via CPUID leaf 7 EBX bit 29. Uses `_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`, and `_mm_sha256msg2_epu32` intrinsics when available (AMD Zen+ 2018+, Intel Ice Lake 2019+). Falls back to scalar C++ on older CPUs. On GCC/Clang the SHA-NI function carries `__attribute__((target("sha,sse4.1,ssse3")))` so no project-wide `-msha` flag is needed.
- **Linux / Windows (ARM64)**: same `__ARM_FEATURE_SHA2` compile-time path used on iOS and macOS Apple Silicon. Enabled automatically when the toolchain targets ARMv8 with crypto extensions.

The entire counter search loop runs inside native code with no per-iteration JVM (Android) or ObjC/Swift (iOS/macOS) overhead.

## License

MIT
