import 'dart:js_interop';
import 'dart:typed_data';

import 'package:web/web.dart' as web;

class PlatformAudioPlayer {
  web.HTMLAudioElement? _audio;
  String? _blobUrl;
  void Function(bool isLoading, bool isPlaying)? _onStateChanged;

  void init(void Function(bool isLoading, bool isPlaying) onStateChanged) {
    _onStateChanged = onStateChanged;
  }

  Future<void> play(Uint8List bytes, String extension) async {
    await stop();

    final mimeType = _mimeFromExtension(extension);
    final blob = web.Blob(
      [Uint8List.fromList(bytes).buffer.toJS].toJS,
      web.BlobPropertyBag(type: mimeType),
    );
    _blobUrl = web.URL.createObjectURL(blob);

    final audio = web.HTMLAudioElement();
    _audio = audio;

    audio.addEventListener(
      'playing',
      ((web.Event _) => _onStateChanged?.call(false, true)).toJS,
    );
    audio.addEventListener(
      'ended',
      ((web.Event _) {
        _onStateChanged?.call(false, false);
        _revokeBlobUrl();
      }).toJS,
    );
    audio.addEventListener(
      'error',
      ((web.Event _) {
        _onStateChanged?.call(false, false);
        _revokeBlobUrl();
      }).toJS,
    );

    audio.src = _blobUrl!;
    _onStateChanged?.call(true, false);

    try {
      await audio.play().toDart;
    } catch (_) {
      _onStateChanged?.call(false, false);
      rethrow;
    }
  }

  Future<void> stop() async {
    _audio?.pause();
    _audio = null;
    _revokeBlobUrl();
    _onStateChanged?.call(false, false);
  }

  void dispose() {
    _audio?.pause();
    _audio = null;
    _revokeBlobUrl();
  }

  void _revokeBlobUrl() {
    if (_blobUrl != null) {
      web.URL.revokeObjectURL(_blobUrl!);
      _blobUrl = null;
    }
  }

  String _mimeFromExtension(String ext) {
    return switch (ext.toLowerCase()) {
      '.mp3' => 'audio/mpeg',
      '.ogg' => 'audio/ogg',
      '.m4a' => 'audio/mp4',
      _ => 'audio/wav',
    };
  }
}
