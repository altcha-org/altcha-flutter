// Platform-conditional export.
//   - dart.library.io  → native (iOS, macOS, Android) via method channel
//   - dart.library.html → web via window.crypto.subtle
//   - fallback → stub that throws (Linux/Windows desktop — pure Dart fallback
//     is applied by the caller via try-catch on MissingPluginException)
export 'pbkdf2_stub.dart'
    if (dart.library.io) 'pbkdf2_io.dart'
    if (dart.library.js_interop) 'pbkdf2_web.dart';
