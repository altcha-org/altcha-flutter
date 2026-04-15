import 'dart:typed_data';

Future<Uint8List> platformPbkdf2({
  required Uint8List password,
  required Uint8List salt,
  required int iterations,
  required int keyLength,
  required String hash,
}) {
  throw UnsupportedError('platformPbkdf2 is not supported on this platform.');
}

Future<Uint8List> platformSha({
  required Uint8List salt,
  required Uint8List password,
  required String hash,
  required int iterations,
  required int keyLength,
}) {
  throw UnsupportedError('platformSha is not supported on this platform.');
}
