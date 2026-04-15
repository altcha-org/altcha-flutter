import 'package:flutter/services.dart';

// A const channel avoids allocating a new object on every call and is safe
// to construct inside background isolates that have already called
// BackgroundIsolateBinaryMessenger.ensureInitialized().
const MethodChannel _channel = MethodChannel('altcha_widget/pbkdf2');

/// Derives a PBKDF2 key using the native platform implementation.
///
/// Supported on iOS, macOS, and Android.  The channel call is routed to the
/// platform handler, which uses CommonCrypto on Apple platforms and
/// javax.crypto.Mac on Android — both run in native speed.
///
/// To call this from a background [Isolate], first call:
///   BackgroundIsolateBinaryMessenger.ensureInitialized(token)
Future<Uint8List> platformPbkdf2({
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int keyLength,
  required String hash,
}) async {
  final result = await _channel.invokeMethod<Uint8List>('pbkdf2', {
    'password': password,
    'salt': salt,
    'iterations': iterations,
    'keyLength': keyLength,
    'hash': hash,
  });
  return result!;
}

// SHA hashing is fast in pure Dart on native; no platform channel needed.
// Throw so channelDeriveKey falls through to adaptiveDeriveKey.
Future<Uint8List> platformSha({
  required Uint8List salt,
  required Uint8List password,
  required String hash,
  required int iterations,
  required int keyLength,
}) {
  throw MissingPluginException();
}
