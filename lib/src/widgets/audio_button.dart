import 'dart:typed_data';

import 'package:altcha_widget/src/localizations.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

import '../audio/audio.dart';

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
  final PlatformAudioPlayer _player = PlatformAudioPlayer();

  bool _isLoading = false;
  bool _isPlaying = false;

  Uint8List? _cachedBytes;
  String? _cachedUrl;

  @override
  void initState() {
    super.initState();
    _player.init((isLoading, isPlaying) {
      if (!mounted) return;
      setState(() {
        _isLoading = isLoading;
        _isPlaying = isPlaying;
      });
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
      }

      final extension = _getExtensionFromUrl(uriWithLanguage);
      await _player.play(_cachedBytes!, extension);
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
    _player.dispose();
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
