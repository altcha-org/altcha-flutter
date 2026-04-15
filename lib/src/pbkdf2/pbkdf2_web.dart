import 'dart:js_interop';
import 'dart:typed_data';

import 'package:web/web.dart' as web;

/// Computes an iterated SHA hash chain using the browser's SubtleCrypto API.
///
/// Mirrors the pure-Dart SHA deriveKey in altcha_lib:
///   iteration 0 → SHA(concat(salt, password))
///   iteration i → SHA(previous digest)
///
/// Each [await] on subtle.digest() yields to the browser event loop, keeping
/// the render thread unblocked.
Future<Uint8List> platformSha({
  required Uint8List salt,
  required Uint8List password,
  required String hash,
  required int iterations,
  required int keyLength,
}) async {
  final subtle = web.window.crypto.subtle;

  // First iteration: hash(salt || password)
  final initBuf = Uint8List(salt.length + password.length);
  initBuf.setAll(0, salt);
  initBuf.setAll(salt.length, password);

  var current = initBuf;
  for (var i = 0; i < iterations; i++) {
    final bits =
        await subtle.digest(hash.toJS, current.buffer.toJS).toDart;
    current = (bits as JSArrayBuffer).toDart.asUint8List();
  }
  return current.sublist(0, keyLength);
}

/// Derives a PBKDF2 key using the browser's SubtleCrypto API.
///
/// Runs on the main thread; no isolate concerns since Flutter Web is
/// single-threaded.
Future<Uint8List> platformPbkdf2({
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int keyLength,
  required String hash,
}) async {
  final subtle = web.window.crypto.subtle;

  // Ensure typed data owns its own backing buffer (no sub-view offset issues).
  final passwordBuf = Uint8List.fromList(password).buffer.toJS;
  final saltBuf = Uint8List.fromList(salt).buffer.toJS;

  // JSArrayBuffer is a subtype of JSObject, satisfying the keyData parameter.
  final keyMaterial = await subtle
      .importKey(
        'raw',
        passwordBuf,
        {'name': 'PBKDF2'}.jsify()!,
        false,
        <JSString>['deriveBits'.toJS].toJS,
      )
      .toDart;

  final bits = await subtle
      .deriveBits(
        {
          'name': 'PBKDF2',
          'salt': saltBuf,
          'iterations': iterations,
          'hash': hash,
        }.jsify()!,
        keyMaterial,
        keyLength * 8,
      )
      .toDart;

  // JSArrayBuffer.toDart → ByteBuffer → Uint8List
  return bits.toDart.asUint8List().sublist(0, keyLength);
}
