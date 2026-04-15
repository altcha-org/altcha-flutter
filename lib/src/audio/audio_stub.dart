import 'dart:typed_data';

class PlatformAudioPlayer {
  void init(void Function(bool isLoading, bool isPlaying) onStateChanged) {}

  Future<void> play(Uint8List bytes, String extension) async {
    throw UnsupportedError('Audio playback not supported on this platform.');
  }

  Future<void> stop() async {}

  void dispose() {}
}
