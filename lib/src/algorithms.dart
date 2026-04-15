import 'dart:typed_data';

import 'package:altcha_lib/algorithms.dart';
import 'package:flutter/services.dart' show MissingPluginException;

import 'pbkdf2/pbkdf2.dart';

export 'package:altcha_lib/algorithms.dart' show adaptiveDeriveKey;

String _extractHash(String algorithm) {
  final parts = algorithm.split('/');
  return parts.length > 1 ? parts[1].toUpperCase() : 'SHA-256';
}

/// Platform-native deriveKey for PBKDF2 challenges.
///
/// Uses the native channel (CommonCrypto on iOS/macOS, javax.crypto on Android,
/// SubtleCrypto on web) for PBKDF2, and falls back to [adaptiveDeriveKey] for
/// all other algorithms or when the native channel is unavailable.
///
/// This is a top-level function so it can be sent across isolate boundaries.
/// Background isolates must call:
///   BackgroundIsolateBinaryMessenger.ensureInitialized(token)
/// before invoking this function.
Future<DeriveKeyResult> channelDeriveKey(
  ChallengeParameters parameters,
  List<int> salt,
  List<int> password,
) async {
  final algo = parameters.algorithm.toUpperCase();
  if (algo.startsWith('PBKDF2')) {
    try {
      final derivedKey = await platformPbkdf2(
        password: Uint8List.fromList(password),
        salt: Uint8List.fromList(salt),
        iterations: parameters.cost,
        keyLength: parameters.keyLength,
        hash: _extractHash(parameters.algorithm),
      );
      return DeriveKeyResult(derivedKey: derivedKey);
    } on MissingPluginException {
      // Plugin not available on this platform (e.g. Linux/Windows desktop) —
      // fall through to pure-Dart implementation below.
    }
  } else if (algo.startsWith('SHA-')) {
    try {
      // On web: uses SubtleCrypto digest — async, yields to the event loop
      // between iterations so the render thread stays unblocked.
      // On native: throws MissingPluginException → falls through to
      // adaptiveDeriveKey (pure Dart SHA is fast enough on native).
      final derivedKey = await platformSha(
        salt: Uint8List.fromList(salt),
        password: Uint8List.fromList(password),
        hash: algo,
        iterations: parameters.cost < 1 ? 1 : parameters.cost,
        keyLength: parameters.keyLength,
      );
      return DeriveKeyResult(derivedKey: derivedKey);
    } on MissingPluginException {
      // fall through to pure-Dart implementation below.
    }
  }
  return adaptiveDeriveKey(parameters, salt, password);
}
