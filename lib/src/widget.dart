import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'package:altcha_lib/altcha_lib.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MethodChannel;
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_timezone/flutter_timezone.dart';
import 'package:http/http.dart' as http;

import 'algorithms.dart';
import 'exceptions.dart';
import 'his_collector.dart';
import 'localizations.dart';
import 'models/challenge.dart';
import 'models/server_verification.dart';
import 'widgets/code_challenge.dart';

// ---------------------------------------------------------------------------
// Isolate worker — top-level so it can be sent across isolate boundaries.
// ---------------------------------------------------------------------------

/// Pure-Dart solver for non-PBKDF2 algorithms (SHA, Scrypt, Argon2id).
Future<Map<String, dynamic>?> _computeSolve(Map<String, dynamic> json) async {
  final challenge = Challenge.fromJson(json);
  final solution = await solveChallenge(
    challenge: challenge,
    deriveKey: adaptiveDeriveKey,
  );
  return solution?.toJson();
}

// ---------------------------------------------------------------------------
// Hex helpers used by the native PBKDF2 solver.
// ---------------------------------------------------------------------------

Uint8List _hexToBytes(String hex) {
  final bytes = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    bytes[i ~/ 2] = int.parse(hex.substring(i, i + 2), radix: 16);
  }
  return bytes;
}

String _bytesToHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

class AltchaWidget extends StatefulWidget {
  /// The challenge source — either a URL [String] to fetch from, or a
  /// pre-fetched [Map<String, dynamic>] JSON object.
  final Object? challenge;

  /// Number of isolates to use for parallel solving on native platforms.
  /// Defaults to 4. Set to 1 to disable parallel solving.
  final int concurrency;

  /// Enable verbose debug logging.
  final bool debug;

  /// Minimum duration the verification UI should remain in the "verifying"
  /// state, in milliseconds.  Ensures the progress indicator is visible long
  /// enough to give the user meaningful feedback even when solving is fast.
  /// Defaults to 500 ms.
  final int minDuration;

  /// Custom key-derivation function.
  ///
  /// When provided, this function is used instead of the built-in
  /// [adaptiveDeriveKey] for all non-PBKDF2 algorithms (Argon2id, Scrypt,
  /// SHA-256).  Use this to plug in a hardware-accelerated or library-backed
  /// implementation, e.g. one using the `sodium` package for Argon2id.
  ///
  /// The function runs inside a background [Isolate] via [Isolate.run], so it
  /// must be closure-compatible (i.e. it may capture state, but any objects it
  /// captures must be reachable in the spawned isolate — initialise heavy
  /// resources such as `sodium` inside the function itself, not outside).
  final DeriveKeyFunction? deriveKey;

  /// Hide the footer text.
  final bool? hideFooter;

  /// Hide the ALTCHA logo.
  final bool? hideLogo;

  /// Custom HTTP client.
  final http.Client httpClient;

  /// Additional HTTP headers for challenge and verification requests.
  final Map<String, String>? httpHeaders;

  /// Application origin sent as the `Origin` header on native platforms.
  ///
  /// Should be your app's bundle ID or package name (e.g. `com.example.myapp`).
  /// It is formatted as `https://com.example.myapp` so the server can restrict
  /// requests by origin.  On web the browser sets the `Origin` header
  /// automatically, so this value is ignored there.
  final String? origin;

  /// Enable the Human Interaction Signature (HIS) collector.
  ///
  /// When true (the default), pointer, touch, and scroll events are collected
  /// and submitted to the server when it requests HIS data.  Set to false to
  /// opt out of HIS collection entirely.
  final bool humanInteractionSignature;

  /// Optional externally-managed [HisCollector] instance.
  ///
  /// When provided, the widget uses this collector instead of creating its own.
  /// Use this to start collection early (e.g. at app launch) so the server
  /// receives a richer interaction history rather than only events that occurred
  /// while the ALTCHA widget was on screen.
  ///
  /// The caller is responsible for registering and removing the global pointer
  /// route on the external collector (via [HisCollector.attach] /
  /// [HisCollector.detach]).  The widget will not register its own route when
  /// an external collector is supplied.
  final HisCollector? collector;

  /// Called when an error occurs during verification.
  final ValueChanged<Object>? onFailed;

  /// Called with the server verification result when the server returns
  /// verification data.
  final ValueChanged<AltchaServerVerification>? onServerVerification;

  /// Called with the base64-encoded payload after successful verification.
  final ValueChanged<String>? onVerified;

  AltchaWidget({
    super.key,
    this.challenge,
    this.collector,
    this.concurrency = 4,
    this.debug = false,
    this.humanInteractionSignature = false,
    this.minDuration = 500,
    this.deriveKey,
    this.hideFooter,
    this.hideLogo,
    this.onFailed,
    this.onServerVerification,
    this.onVerified,
    this.origin,
    http.Client? httpClient,
    Map<String, String>? httpHeaders,
  }) : httpClient = httpClient ?? http.Client(),
       httpHeaders = httpHeaders ?? const {};

  @override
  AltchaWidgetState createState() => AltchaWidgetState();
}

class AltchaWidgetState extends State<AltchaWidget> {
  bool _isCodeRequired = false;
  bool _isLoading = false;
  bool _isSolved = false;
  bool _sentinelTimeZone = false;
  String _errorMessage = '';
  String _verifyUrl = '';

  late final HisCollector _hisCollector;

  // True when this widget owns the collector and must manage its route.
  bool _ownsCollector = false;

  @override
  void initState() {
    super.initState();
    if (widget.collector != null) {
      _hisCollector = widget.collector!;
    } else {
      _hisCollector = HisCollector();
      _ownsCollector = true;
      if (widget.humanInteractionSignature) {
        _hisCollector.attach();
      }
    }
  }

  @override
  void dispose() {
    if (_ownsCollector && widget.humanInteractionSignature) {
      _hisCollector.detach();
    }
    super.dispose();
  }


  /// Returns the challenge URL string when [widget.challenge] is a [String].
  String? get _challengeUrl =>
      widget.challenge is String ? widget.challenge as String : null;

  Uri? _constructUrl(String? input, String? origin) {
    if (input == null || input.isEmpty) {
      return null;
    }
    if (origin == null || origin.isEmpty) {
      return Uri.tryParse(input);
    }

    final originUri = Uri.parse(origin);
    final inputUri = Uri.parse(input);

    if (inputUri.hasScheme) {
      return inputUri;
    }

    final mergedQueryParameters = {
      ...originUri.queryParameters,
      ...inputUri.queryParameters,
    };
    final newPath =
        inputUri.path.isNotEmpty ? inputUri.path : originUri.path;

    return Uri(
      scheme: originUri.scheme,
      host: originUri.host,
      port: originUri.hasPort ? originUri.port : null,
      path: newPath,
      queryParameters:
          mergedQueryParameters.isNotEmpty ? mergedQueryParameters : null,
    );
  }

  Future<AltchaChallenge> _fetchChallenge() async {
    try {
      if (widget.challenge == null) {
        throw Exception('challenge must be set to a URL string or a JSON map.');
      }
      if (widget.challenge is Map<String, dynamic>) {
        final json = widget.challenge as Map<String, dynamic>;
        _log('challenge json: $json');
        return AltchaChallenge.fromJson(json);
      }
      final url = widget.challenge as String;
      _log('challenge url: $url');
      final uri = Uri.parse(url);
      final response = await widget.httpClient.get(uri, headers: {
        ..._buildExtraHeaders(),
        ...?widget.httpHeaders,
      });
      _log('challenge response (${response.statusCode}): ${response.body}');
      if (response.statusCode != 200) {
        throw ServerException(response.statusCode, 'Failed to load challenge');
      }
      final Map<String, dynamic> data = jsonDecode(response.body);

      _applyConfiguration(response.headers, data);

      // If the server requests HIS data first, submit it and use the response
      // as the actual challenge JSON.
      final hisRequest = AltchaHisRequest.tryFromJson(data);
      if (hisRequest != null) {
        if (!widget.humanInteractionSignature) {
          throw Exception(
            'Server requested HIS data but humanInteractionSignature is disabled.',
          );
        }
        final hisUrl = _constructUrl(hisRequest.url, url) ?? Uri.parse(hisRequest.url);
        return await _submitHisAndFetchChallenge(hisUrl);
      }

      return AltchaChallenge.fromJson(data);
    } on SocketException {
      throw NetworkException('Network error.');
    } on FormatException {
      throw DataParsingException('Malformed JSON.');
    }
  }

  /// Parses `x-altcha-config` header and `configuration` body field and
  /// applies them to widget state.  Call after every server response that may
  /// carry configuration (challenge fetch and HIS submission).
  void _applyConfiguration(Map<String, String> headers, Map<String, dynamic> body) {
    // x-altcha-config header (legacy / lower priority)
    final altchaConfigHeader = headers['x-altcha-config'];
    if (altchaConfigHeader != null && altchaConfigHeader.isNotEmpty) {
      final altchaConfig = jsonDecode(altchaConfigHeader) as Map<String, dynamic>;
      if (altchaConfig['verifyurl'] != null) {
        _verifyUrl = altchaConfig['verifyurl'] as String;
      }
      if (altchaConfig['sentinel'] != null) {
        final sentinel = altchaConfig['sentinel'] as Map<String, dynamic>;
        _sentinelTimeZone = sentinel['timeZone'] == true;
      }
    }

    // configuration field in the response body (higher priority — overrides header)
    final configuration = body['configuration'] as Map<String, dynamic>?;
    if (configuration != null) {
      if (configuration['verifyUrl'] is String) {
        _verifyUrl = configuration['verifyUrl'] as String;
      }
      if (configuration['serverVerificationTimeZone'] is bool) {
        _sentinelTimeZone = configuration['serverVerificationTimeZone'] as bool;
      }
    }
  }

  /// POSTs the collected HIS data to [hisUrl] and parses the response body as
  /// the actual challenge.
  Future<AltchaChallenge> _submitHisAndFetchChallenge(Uri hisUrl) async {
    _log('submitting HIS to: $hisUrl');
    final body = jsonEncode({'his': _hisCollector.export()});
    final headers = {
      'Content-Type': 'application/json',
      ..._buildExtraHeaders(),
      ...?widget.httpHeaders,
    };
    _log('HIS data: $body');
    final response = await widget.httpClient.post(hisUrl, body: body, headers: headers);
    _log('HIS response (${response.statusCode}): ${response.body}');
    if (response.statusCode != 200) {
      throw ServerException(response.statusCode, 'HIS submission failed');
    }
    final Map<String, dynamic> data = jsonDecode(response.body);
    _applyConfiguration(response.headers, data);
    return AltchaChallenge.fromJson(data);
  }

  String? _getVerifyUrl() {
    if (_verifyUrl.isNotEmpty) {
      return _verifyUrl;
    }
    return null;
  }

  Future<String?> _getTimezone() async {
    try {
      final info = await FlutterTimezone.getLocalTimezone();
      return info.identifier;
    } catch (e) {
      _log('Could not get timezone: $e');
    }
    return null;
  }

  /// Extracts the first numeric version sequence from a platform version string.
  /// e.g. "Version 15.4 (Build 24E248)" → "15.4", "Android 14 (API 34)" → "14"
  String _extractVersion(String raw) {
    final match = RegExp(r'\d+(?:\.\d+)*').firstMatch(raw);
    return match?.group(0) ?? raw;
  }

  /// Builds a User-Agent string compatible with ua-parser-js conventions.
  String _buildUserAgent() {
    const app = 'altcha-flutter/2.0.0';
    final v = _extractVersion(Platform.operatingSystemVersion);
    if (Platform.isAndroid) {
      // ua-parser-js detects Android via "Linux; Android X.X" pattern.
      return 'Mozilla/5.0 (Linux; Android $v; Flutter) $app';
    } else if (Platform.isIOS) {
      // ua-parser-js detects iPhone OS via underscored version.
      return 'Mozilla/5.0 (iPhone; CPU iPhone OS ${v.replaceAll('.', '_')} like Mac OS X) $app';
    } else if (Platform.isMacOS) {
      return 'Mozilla/5.0 (Macintosh; Intel Mac OS X ${v.replaceAll('.', '_')}) $app';
    } else if (Platform.isWindows) {
      return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) $app';
    } else {
      return 'Mozilla/5.0 (X11; Linux x86_64) $app';
    }
  }

  /// Builds platform-specific HTTP headers for challenge and verification
  /// requests.  Returns an empty map on web — the browser controls User-Agent,
  /// Accept-Language, and Client Hint headers for XHR/fetch requests.
  Map<String, String> _buildExtraHeaders() {
    if (kIsWeb) return {};

    final headers = <String, String>{};

    headers['User-Agent'] = _buildUserAgent();

    // Accept-Language — ordered list of system locales with q-values
    final locales = PlatformDispatcher.instance.locales;
    if (locales.isNotEmpty) {
      final parts = <String>[];
      for (var i = 0; i < locales.length; i++) {
        final tag = locales[i].toLanguageTag();
        if (i == 0) {
          parts.add(tag);
        } else {
          final q = (1.0 - i * 0.1).clamp(0.1, 0.9);
          parts.add('$tag;q=${q.toStringAsFixed(1)}');
        }
      }
      headers['Accept-Language'] = parts.join(', ');
    }

    // sec-ch-ua-mobile — only sent on mobile platforms
    if (Platform.isAndroid || Platform.isIOS) {
      headers['sec-ch-ua-mobile'] = '?1';
    }

    // Origin + Referer — lets the server restrict requests by app identifier
    if (widget.origin != null && widget.origin!.isNotEmpty) {
      final raw = widget.origin!;
      final origin =
          raw.startsWith('https://') ? raw : 'https://$raw';
      headers['Origin'] = origin;
      headers['Referer'] = '$origin/';
    }

    return headers;
  }

  void _log(String message) {
    if (widget.debug || kDebugMode) {
      debugPrint('[ALTCHA] $message');
    }
  }

  Future<String?> _requestCodeVerification(
    String image,
    Uri? audioUrl,
    int? codeLength,
  ) async {
    final result = await showModalBottomSheet<String>(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) => AltchaCodeChallengeWidget(
        audioUrl: audioUrl,
        codeLength: codeLength,
        imageBase64: image,
        log: _log,
        httpClient: widget.httpClient,
        httpHeaders: {
          ..._buildExtraHeaders(),
          ...?widget.httpHeaders,
        },
        onSubmit: (code) {
          Navigator.of(context).pop(code);
        },
        onCancel: () {
          Navigator.of(context).pop();
        },
        onReload: () {
          Navigator.of(context).pop();
          Future(() {
            verify();
          });
        },
      ),
    );
    return result;
  }

  /// Solves a PBKDF2 challenge using the native platform implementation.
  ///
  /// A single method channel call carries all challenge parameters to the
  /// native side.  The native handler runs the full solver loop on a GCD
  /// thread pool (iOS/macOS) or Java ExecutorService (Android), returning
  /// only when the solution is found or the timeout expires.  This eliminates
  /// the per-iteration channel overhead that made the previous isolate-per-call
  /// approach slow (~50 ms × N calls on macOS).
  Future<Solution?> _solveNativePbkdf2(Challenge challenge) async {
    final params = challenge.parameters;
    final hash = params.algorithm.contains('/')
        ? params.algorithm.split('/')[1].toUpperCase()
        : 'SHA-256';

    _log('solver: native solve (concurrency=${widget.concurrency})');
    final start = DateTime.now();
    final raw = await const MethodChannel('altcha_widget/pbkdf2').invokeMethod<Map<dynamic, dynamic>>(
      'solve',
      {
        'nonce': _hexToBytes(params.nonce),
        'salt': _hexToBytes(params.salt),
        'cost': params.cost,
        'keyLength': params.keyLength,
        'keyPrefix': params.keyPrefix,
        'hash': hash,
        'concurrency': widget.concurrency,
        'timeoutMs': 90000,
      },
    );

    if (raw == null) return null;

    final counter = raw['counter'] as int;
    final derivedKey = _bytesToHex(raw['derivedKey'] as Uint8List);
    final elapsed = DateTime.now().difference(start).inMilliseconds.toDouble();
    return Solution(counter: counter, derivedKey: derivedKey, time: elapsed);
  }

  Future<String?> _solveAndBuildPayload(AltchaChallenge altchaChallenge) async {
    final challenge = altchaChallenge.challenge;
    final isPbkdf2 = challenge.parameters.algorithm.toUpperCase().startsWith('PBKDF2');
    Solution? solution;

    if (!kIsWeb && isPbkdf2) {
      // PBKDF2 on native: one channel call, native threading does the work.
      solution = await _solveNativePbkdf2(challenge);
      if (solution != null) {
        _log('solver: native solve done (counter=${solution.counter}, time=${solution.time}ms)');
      } else {
        _log('solver: native solve timed out');
      }
    } else if (!kIsWeb) {
      // Non-PBKDF2 on native: pure-Dart solver via altcha_lib isolates.
      final customDeriveKey = widget.deriveKey;
      if (customDeriveKey != null) {
        // User-provided deriveKey (e.g. sodium-based Argon2id): run in a single
        // background isolate via Isolate.run(), which supports closures.
        _log('solver: Isolate.run() with custom deriveKey');
        solution = await Isolate.run(() => solveChallenge(
          challenge: challenge,
          deriveKey: customDeriveKey,
        ));
        if (solution != null) {
          _log('solver: custom deriveKey done (counter=${solution.counter}, time=${solution.time}ms)');
        } else {
          _log('solver: custom deriveKey timed out');
        }
      } else if (widget.concurrency > 1) {
        _log('solver: solveChallengeIsolates (concurrency=${widget.concurrency})');
        bool isolatesThrew = false;
        try {
          solution = await solveChallengeIsolates(
            challenge: challenge,
            deriveKey: adaptiveDeriveKey,
            concurrency: widget.concurrency,
          );
          if (solution != null) {
            _log('solver: solveChallengeIsolates done (counter=${solution.counter}, time=${solution.time}ms)');
          } else {
            _log('solver: solveChallengeIsolates timed out — not falling back');
          }
        } catch (e) {
          isolatesThrew = true;
          _log('solver: solveChallengeIsolates threw ($e) — falling back to compute()');
        }

        // Only fall back to compute() on isolate setup failure, not timeout.
        if (solution == null && isolatesThrew) {
          _log('solver: compute()');
          final result = await compute(_computeSolve, challenge.toJson());
          if (result != null) {
            solution = Solution.fromJson(result);
            _log('solver: compute() done (counter=${solution.counter}, time=${solution.time}s)');
          }
        }
      } else {
        // concurrency == 1: single background isolate.
        _log('solver: compute() (concurrency=1)');
        final result = await compute(_computeSolve, challenge.toJson());
        if (result != null) {
          solution = Solution.fromJson(result);
          _log('solver: compute() done (counter=${solution.counter}, time=${solution.time}s)');
        }
      }
    } else {
      // Web: single-threaded with periodic yields.
      // channelDeriveKey routes PBKDF2 and SHA to SubtleCrypto (async, non-blocking);
      // Scrypt/Argon2id fall through to pure-Dart adaptiveDeriveKey.
      _log('solver: solveChallenge (main thread, web)');
      solution = await solveChallenge(
        challenge: challenge,
        deriveKey: channelDeriveKey,
      );
      if (solution != null) {
        _log('solver: solveChallenge done (counter=${solution.counter}, time=${solution.time}s)');
      }
    }

    if (solution == null) {
      setState(() {
        _errorMessage = 'Verification failed. Please try again.';
      });
      return null;
    }

    final payloadObject = {
      'challenge': challenge.toJson(),
      'solution': solution.toJson(),
    };
    final payload = base64.encode(utf8.encode(json.encode(payloadObject)));
    if (widget.onVerified != null) {
      widget.onVerified!(payload);
    }
    return payload;
  }

  Future<AltchaServerVerification> _requestServerVerification(
    String verifyUrl,
    String payload,
    String? code,
  ) async {
    if (verifyUrl.isEmpty) {
      throw Exception('verifyUrl must be a valid URL.');
    }
    try {
      final uri = _constructUrl(verifyUrl, _challengeUrl)!;
      _log('server verification url: ${uri.toString()}');
      final body = jsonEncode({
        'code': code,
        'payload': payload,
        'timeZone':
            _sentinelTimeZone ? (await _getTimezone()) : null,
      });
      final headers = {
        'Content-Type': 'application/json',
        ..._buildExtraHeaders(),
        ...?widget.httpHeaders,
      };
      final response = await http.post(uri, body: body, headers: headers);
      _log(
        'server verification response (${response.statusCode}): ${response.body}',
      );
      if (response.statusCode == 200) {
        final Map<String, dynamic> data = jsonDecode(response.body);
        final serverVerification = AltchaServerVerification.fromJson(data);
        if (widget.onServerVerification != null) {
          widget.onServerVerification!(serverVerification);
        }
        if (widget.onVerified != null && serverVerification.verified) {
          widget.onVerified!(serverVerification.payload);
        }
        return serverVerification;
      } else {
        throw Exception(
          'Server verification failed with status ${response.statusCode}.',
        );
      }
    } on SocketException {
      throw NetworkException('Network error.');
    } on FormatException {
      throw DataParsingException('Malformed JSON.');
    }
  }

  Future<void> verify() async {
    reset();
    setState(() => _isLoading = true);
    try {
      final startTime = DateTime.now();
      final altchaChallenge = await _fetchChallenge();
      final verifyUrl = _getVerifyUrl();
      final payload = await _solveAndBuildPayload(altchaChallenge);
      if (payload == null) {
        throw Exception('Failed to compute solution.');
      }
      if (altchaChallenge.codeChallenge?.image != null &&
          altchaChallenge.codeChallenge!.image.isNotEmpty) {
        if (verifyUrl == null || verifyUrl.isEmpty) {
          throw Exception('Received codeChallenge but verifyUrl is not set.');
        }
        setState(() => _isCodeRequired = true);
        final code = await _requestCodeVerification(
          altchaChallenge.codeChallenge!.image,
          _constructUrl(
              altchaChallenge.codeChallenge!.audio,
              _challengeUrl ?? (_verifyUrl.isNotEmpty ? _verifyUrl : null)),
          altchaChallenge.codeChallenge!.length,
        );
        setState(() => _isCodeRequired = false);
        if (code == null) {
          // User cancelled — reset to initial unverified state silently.
          setState(() {
            _isSolved = false;
            _errorMessage = '';
          });
          return;
        }
        final serverVerification =
            await _requestServerVerification(verifyUrl, payload, code);
        if (!serverVerification.verified) {
          throw Exception('Server verification failed.');
        }
      } else if (verifyUrl != null && verifyUrl.isNotEmpty) {
        await _requestServerVerification(verifyUrl, payload, null);
      }
      final elapsed = DateTime.now().difference(startTime).inMilliseconds;
      if (elapsed < widget.minDuration) {
        await Future.delayed(Duration(milliseconds: widget.minDuration - elapsed));
      }
      setState(() => _isSolved = true);
    } catch (e, stack) {
      _log('error: $e $stack');
      widget.onFailed?.call(e);
      setState(() {
        _errorMessage = AltchaLocalizations.of(context).text('error');
      });
    } finally {
      setState(() => _isLoading = false);
    }
  }

  void reset() {
    setState(() {
      _isCodeRequired = false;
      _isLoading = false;
      _isSolved = false;
      _sentinelTimeZone = false;
      _errorMessage = '';
      _verifyUrl = '';
    });
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final localizations = AltchaLocalizations.of(context);

    return NotificationListener<ScrollUpdateNotification>(
      onNotification: (n) {
        _hisCollector.recordScroll(
          n.metrics.pixels,
          DateTime.now().millisecondsSinceEpoch,
        );
        return false;
      },
      child: Container(
          decoration: BoxDecoration(
            border: Border.all(color: colorScheme.outline, width: 1.0),
            borderRadius: BorderRadius.circular(4.0),
            color: colorScheme.surface,
          ),
          padding: const EdgeInsets.all(12.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  _buildStatus(localizations, colorScheme),
                  const Spacer(),
                  if (widget.hideLogo != true)
                    SvgPicture.string(
                      _kAltchaLogoSvg,
                      width: 24,
                      height: 24,
                      colorFilter: ColorFilter.mode(
                        colorScheme.onSurfaceVariant.withValues(alpha: 255 * 0.7),
                        BlendMode.srcIn,
                      ),
                    ),
                ],
              ),
              if (_errorMessage.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 8.0),
                  child: Text(
                    _errorMessage,
                    style: TextStyle(color: colorScheme.error),
                  ),
                ),
              if (widget.hideFooter != true)
                Padding(
                  padding: const EdgeInsets.only(top: 16.0),
                  child: Align(
                    alignment: Alignment.centerRight,
                    child: Text(
                      localizations.text('footer'),
                      style: TextStyle(
                        color: colorScheme.onSurfaceVariant
                            .withValues(alpha: 255 * 0.7),
                        fontSize: 12.0,
                      ),
                    ),
                  ),
                ),
            ],
          ),
        ),
    );
  }

  Widget _buildStatus(
      AltchaLocalizations localizations, ColorScheme colorScheme) {
    if (_isCodeRequired) {
      return Row(
        children: [
          const SizedBox(
            width: 24,
            height: 24,
            child: Icon(Icons.warning, size: 24),
          ),
          const SizedBox(width: 8.0),
          Text(
            localizations.text('verificationRequired'),
            style: const TextStyle(fontSize: 16.0),
          ),
        ],
      );
    }
    if (_isLoading) {
      return Row(
        children: [
          const SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(strokeWidth: 2.0),
          ),
          const SizedBox(width: 8.0),
          Text(
            localizations.text('verifying'),
            style: const TextStyle(fontSize: 16.0),
          ),
        ],
      );
    }
    if (_isSolved) {
      return Row(
        children: [
          SizedBox(
            width: 24,
            height: 24,
            child: Icon(
              Icons.check_box,
              color: colorScheme.primary,
              size: 24,
            ),
          ),
          const SizedBox(width: 8.0),
          Text(
            localizations.text('verified'),
            style: const TextStyle(fontSize: 16.0),
          ),
        ],
      );
    }
    return GestureDetector(
      onTap: () {
        _hisCollector.recordInteraction();
        verify();
      },
      behavior: HitTestBehavior.opaque,
      child: Row(
        children: [
          SizedBox(
            width: 24,
            height: 24,
            child: Checkbox(
              value: false,
              onChanged: (_) {
                _hisCollector.recordInteraction();
                verify();
              },
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(4.0),
              ),
            ),
          ),
          const SizedBox(width: 8.0),
          Text(
            localizations.text('label'),
            style: const TextStyle(fontSize: 16.0),
          ),
        ],
      ),
    );
  }
}

const String _kAltchaLogoSvg = '''
<svg width="22" height="22" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M2.33955 16.4279C5.88954 20.6586 12.1971 21.2105 16.4279 17.6604C18.4699 15.947 19.6548 13.5911 19.9352 11.1365L17.9886 10.4279C17.8738 12.5624 16.909 14.6459 15.1423 16.1284C11.7577 18.9684 6.71167 18.5269 3.87164 15.1423C1.03163 11.7577 1.4731 6.71166 4.8577 3.87164C8.24231 1.03162 13.2883 1.4731 16.1284 4.8577C16.9767 5.86872 17.5322 7.02798 17.804 8.2324L19.9522 9.01429C19.7622 7.07737 19.0059 5.17558 17.6604 3.57212C14.1104 -0.658624 7.80283 -1.21043 3.57212 2.33956C-0.658625 5.88958 -1.21046 12.1971 2.33955 16.4279Z" fill="currentColor"/>
  <path d="M3.57212 2.33956C1.65755 3.94607 0.496389 6.11731 0.12782 8.40523L2.04639 9.13961C2.26047 7.15832 3.21057 5.25375 4.8577 3.87164C8.24231 1.03162 13.2883 1.4731 16.1284 4.8577L13.8302 6.78606L19.9633 9.13364C19.7929 7.15555 19.0335 5.20847 17.6604 3.57212C14.1104 -0.658624 7.80283 -1.21043 3.57212 2.33956Z" fill="currentColor"/>
  <path d="M7 10H5C5 12.7614 7.23858 15 10 15C12.7614 15 15 12.7614 15 10H13C13 11.6569 11.6569 13 10 13C8.3431 13 7 11.6569 7 10Z" fill="currentColor"/>
</svg>
''';
