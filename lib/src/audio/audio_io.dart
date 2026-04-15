import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:just_audio/just_audio.dart';
import 'package:path_provider/path_provider.dart';

class PlatformAudioPlayer {
  final AudioPlayer _player = AudioPlayer();
  File? _tempFile;
  StreamSubscription<PlayerState>? _sub;

  void init(void Function(bool isLoading, bool isPlaying) onStateChanged) {
    _sub = _player.playerStateStream.listen((state) {
      final ps = state.processingState;
      if (ps == ProcessingState.loading || ps == ProcessingState.buffering) {
        onStateChanged(true, false);
      } else if (!state.playing) {
        onStateChanged(false, false);
      } else if (ps == ProcessingState.ready && state.playing) {
        onStateChanged(false, true);
      } else if (ps == ProcessingState.completed) {
        onStateChanged(false, false);
      }
    });
  }

  Future<void> play(Uint8List bytes, String extension) async {
    final tempDir = await getTemporaryDirectory();
    await Directory(tempDir.path).create(recursive: true);
    final file = File('${tempDir.path}/altcha_audio_cache$extension');
    await file.writeAsBytes(bytes, flush: true);
    _tempFile = file;
    await _player.setFilePath(file.path);
    await _player.play();
  }

  Future<void> stop() async {
    await _player.stop();
  }

  void dispose() {
    _sub?.cancel();
    _player.dispose();
    _tempFile?.delete();
  }
}
