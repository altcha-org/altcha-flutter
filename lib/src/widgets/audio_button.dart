import 'dart:async';
import 'dart:io';
import 'dart:typed_data';
import 'package:altcha_widget/src/localizations.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:just_audio/just_audio.dart';
import 'package:path_provider/path_provider.dart';

class AltchaAudioButtonWidget extends StatefulWidget {
  final void Function(String message)? log;
  final Uri url;
  final http.Client? httpClient;
  final Map<String, String>? httpHeaders;

  const AltchaAudioButtonWidget({
    super.key,
    required this.url,
    this.log,
    this.httpClient,
    this.httpHeaders,
  });

  @override
  State<AltchaAudioButtonWidget> createState() =>
      _AltchaAudioButtonWidgetState();
}

class _AltchaAudioButtonWidgetState extends State<AltchaAudioButtonWidget> {
  final AudioPlayer _player = AudioPlayer();

  bool _isLoading = false;
  bool _isPlaying = false;

  Uint8List? _cachedBytes;
  String? _cachedUrl;
  File? _tempAudioFile;

  StreamSubscription<PlayerState>? _playerStateSubscription;

  @override
  void initState() {
    super.initState();

    _playerStateSubscription = _player.playerStateStream.listen((playerState) {
      if (!mounted) return;

      final processingState = playerState.processingState;
      final playing = playerState.playing;

      if (processingState == ProcessingState.loading ||
          processingState == ProcessingState.buffering) {
        setState(() {
          _isLoading = true;
          _isPlaying = false;
        });
      } else if (!playing) {
        setState(() {
          _isPlaying = false;
          _isLoading = false;
        });
      } else if (processingState == ProcessingState.ready && playing) {
        setState(() {
          _isPlaying = true;
          _isLoading = false;
        });
      } else if (processingState == ProcessingState.completed) {
        setState(() {
          _isPlaying = false;
          _isLoading = false;
        });
      }
    });
  }

  String _getExtensionFromUrl(Uri url) {
    final path = url.path;
    final dotIndex = path.lastIndexOf('.');
    if (dotIndex != -1 && dotIndex < path.length - 1) {
      return path.substring(dotIndex);
    }
    return '.wav';
  }

  Future<File> _writeBytesToTempFile(Uint8List bytes, String extension) async {
    final tempDir = await getTemporaryDirectory();
    // Ensure the directory exists — on macOS sandbox the returned path may not
    // yet have been created by the OS.
    await Directory(tempDir.path).create(recursive: true);
    final file = File('${tempDir.path}/altcha_audio_cache$extension');
    await file.writeAsBytes(bytes, flush: true);
    return file;
  }

  Future<void> _playAudio() async {
    setState(() => _isLoading = true);

    try {
      final languageCode = Localizations.localeOf(context).languageCode;

      final uriWithLanguage = widget.url.replace(
        queryParameters: {
          ...widget.url.queryParameters,
          'language': languageCode,
        },
      );

      final urlString = uriWithLanguage.toString();

      if (_cachedBytes == null || _cachedUrl != urlString) {
        final client = widget.httpClient ?? http.Client();
        final response = await client.get(
          uriWithLanguage,
          headers: widget.httpHeaders,
        );
        if (response.statusCode != 200) {
          throw Exception('Failed to load audio: ${response.statusCode}');
        }
        _cachedBytes = response.bodyBytes;
        _cachedUrl = urlString;

        final extension = _getExtensionFromUrl(uriWithLanguage);
        _tempAudioFile = await _writeBytesToTempFile(_cachedBytes!, extension);
      }

      if (_tempAudioFile == null) {
        throw Exception('Failed to prepare audio file');
      }

      await _player.setFilePath(_tempAudioFile!.path);
      await _player.play();
    } catch (e) {
      widget.log?.call('audio error: $e');
      if (mounted) {
        setState(() {
          _isLoading = false;
          _isPlaying = false;
        });
      }
    }
  }

  Future<void> _stopAudio() async {
    await _player.stop();
    if (mounted) {
      setState(() => _isPlaying = false);
    }
  }

  @override
  void dispose() {
    _playerStateSubscription?.cancel();
    _player.dispose();
    _tempAudioFile?.delete();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final localizations = AltchaLocalizations.of(context);

    return IconButton(
      iconSize: 24,
      tooltip: _isPlaying
          ? localizations.text('stopAudio')
          : localizations.text('playAudio'),
      onPressed: _isLoading
          ? null
          : _isPlaying
              ? _stopAudio
              : _playAudio,
      icon: _isLoading
          ? const SizedBox(
              width: 24,
              height: 24,
              child: CircularProgressIndicator(strokeWidth: 2),
            )
          : Icon(_isPlaying ? Icons.stop : Icons.volume_up),
    );
  }
}
