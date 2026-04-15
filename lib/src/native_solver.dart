import 'dart:typed_data';

import 'package:altcha_lib/altcha_lib.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/services.dart' show MethodChannel;

import 'algorithms.dart';
import 'native.dart';

Uint8List _hexToBytes(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return bytes;
}

String _bytesToHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Solves [challenge] using the fastest available implementation on each platform.
///
/// **PBKDF2** (native): the bundled C++/ObjC/Java solver runs [concurrency]
/// parallel workers entirely off the Dart thread via the `altcha_widget/pbkdf2`
/// method channel.
///
/// **All other algorithms** (SHA-256, Scrypt, Argon2id, …):
/// - If [deriveKey] is provided it is called inside a background [Isolate] via
///   [Isolate.run]. Use this to plug in a hardware-accelerated implementation,
///   e.g. `sodium` for Argon2id. Initialise any heavy resources *inside* the
///   function — not outside — so they are available in the spawned isolate.
/// - Otherwise [solveChallengeIsolates] is used with [concurrency] isolates and
///   the built-in [adaptiveDeriveKey].
///
/// **Web**: all algorithms are solved via [solveChallenge] with [channelDeriveKey]
/// (SubtleCrypto for PBKDF2/SHA, pure-Dart for others). [deriveKey] is ignored
/// on web.
///
/// Returns `null` if no solution is found within [timeoutMs] milliseconds.
Future<Solution?> solveChallenge({
  required Challenge challenge,
  DeriveKeyFunction? deriveKey,
  int concurrency = 4,
  int timeoutMs = 90000,
}) async {
  if (kIsWeb) {
    return solveChallenge(challenge: challenge, deriveKey: channelDeriveKey);
  }

  final isPbkdf2 = challenge.parameters.algorithm.toUpperCase().startsWith(
    'PBKDF2',
  );

  if (isPbkdf2) {
    final params = challenge.parameters;
    final hash = params.algorithm.contains('/')
        ? params.algorithm.split('/')[1].toUpperCase()
        : 'SHA-256';

    final raw = await const MethodChannel('altcha_widget/pbkdf2')
        .invokeMethod<Map<dynamic, dynamic>>('solve', {
          'nonce': _hexToBytes(params.nonce),
          'salt': _hexToBytes(params.salt),
          'cost': params.cost,
          'keyLength': params.keyLength,
          'keyPrefix': params.keyPrefix,
          'hash': hash,
          'concurrency': concurrency,
          'timeoutMs': timeoutMs,
        });

    if (raw == null) return null;
    return Solution(
      counter: raw['counter'] as int,
      derivedKey: _bytesToHex(raw['derivedKey'] as Uint8List),
    );
  }

  if (deriveKey != null) {
    return isolateRun(
      () => solveChallenge(challenge: challenge, deriveKey: deriveKey),
    );
  }

  return solveChallengeIsolates(
    challenge: challenge,
    deriveKey: adaptiveDeriveKey,
    concurrency: concurrency,
  );
}
