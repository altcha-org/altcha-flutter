import 'dart:io';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:altcha_widget/models/solution.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:flutter_svg/flutter_svg.dart';
import 'package:flutter_timezone/flutter_timezone.dart';
import 'widgets/code_challenge.dart';
import 'models/challenge.dart';
import 'models/server_verification.dart';
import 'exceptions.dart';
import 'localizations.dart';

class AltchaWidget extends StatefulWidget {
  final Map<String, dynamic>? challengeJson;
  final String? challengeUrl;
  final bool debug;
  final int? delay;
  final bool? hideFooter;
  final bool? hideLogo;
  final http.Client httpClient;
  final Map<String, String>? httpHeaders;
  final ValueChanged<Object>? onFailed;
  final ValueChanged<AltchaServerVerification>? onServerVerification;
  final ValueChanged<String>? onVerified;
  final String? verifyUrl;

  AltchaWidget({
    super.key,
    this.challengeJson,
    this.challengeUrl,
    this.debug = false,
    this.delay,
    this.hideFooter,
    this.hideLogo,
    this.onFailed,
    this.onServerVerification,
    this.onVerified,
    this.verifyUrl,
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

    final newPath = inputUri.path.isNotEmpty ? inputUri.path : originUri.path;

    return Uri(
      scheme: originUri.scheme,
      host: originUri.host,
      port: originUri.hasPort ? originUri.port : null,
      path: newPath,
      queryParameters: mergedQueryParameters.isNotEmpty
          ? mergedQueryParameters
          : null,
    );
  }

  Future<AltchaChallenge> _fetchChallenge() async {
    try {
      if (widget.challengeUrl == null && widget.challengeJson == null) {
        throw Exception('One of challengeUrl or challengeJson must be set.');
      }
      if (widget.challengeJson != null) {
        _log('challenge json: ${widget.challengeJson}');
        return AltchaChallenge.fromJson(widget.challengeJson!);
      }
      _log('challenge url: ${widget.challengeUrl}');
      final uri = Uri.parse(widget.challengeUrl!);
      final response = await widget.httpClient.get(uri, headers: widget.httpHeaders);
      _log('challenge response (${response.statusCode}): ${response.body}');
      if (response.statusCode != 200) {
        throw ServerException(response.statusCode, 'Failed to load challenge');
      }
      final Map<String, dynamic> data = jsonDecode(response.body);
      final altchaConfigHeader = response.headers['x-altcha-config'];
      if (altchaConfigHeader != null && altchaConfigHeader.isNotEmpty) {
        final altchaConfig = jsonDecode(altchaConfigHeader);
        if (altchaConfig['verifyurl'] != null) {
          _verifyUrl = altchaConfig['verifyurl'];
        }
        if (altchaConfig['sentinel'] != null) {
          _sentinelTimeZone = altchaConfig['sentinel']['timeZone'] == true;
        }
      }
      return AltchaChallenge.fromJson(data);
    } on SocketException {
      throw NetworkException('Network error.');
    } on FormatException {
      throw DataParsingException('Malformed JSON.');
    } catch (e) {
      // Other unexpected errors
      rethrow;
    }
  }

  String? _getVerifyUrl() {
    if (_verifyUrl.isNotEmpty) {
      return _verifyUrl;
    }
    return widget.verifyUrl;
  }

  Future<TimezoneInfo?> _getTimezone() async {
    try {
      return FlutterTimezone.getLocalTimezone();
    } catch (e) {
      _log('Could not get time zone: $e');
    }
    return null;
  }

  Future<String> _hashChallenge(String salt, int num, String algorithm) async {
    final bytes = utf8.encode(salt + num.toString());
    Digest digest;
    switch (algorithm.toUpperCase()) {
      case 'SHA-256':
        digest = sha256.convert(bytes);
        break;
      case 'SHA-384':
        digest = sha384.convert(bytes);
        break;
      case 'SHA-512':
        digest = sha512.convert(bytes);
        break;
      default:
        throw UnsupportedError('Unsupported hashing algorithm: $algorithm');
    }
    return digest.toString();
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
        onSubmit: (code) {
          // Close the sheet and return the code
          Navigator.of(context).pop(code);
        },
        onReload: () {
          // Close the sheet and trigger reload
          Navigator.of(context).pop();
          Future(() {
            verify();
          });
        },
      ),
    );

    return result;
  }

  Future<String?> _requestVerification(AltchaChallenge challenge) async {
    final solution = await _solveChallenge(
      challenge.algorithm,
      challenge.challenge,
      challenge.salt,
      challenge.maxNumber,
    );
    if (solution == null) {
      setState(() {
        _errorMessage = 'Verification failed. Please try again.';
      });
      return null;
    } else {
      final payloadObject = {
        'algorithm': challenge.algorithm,
        'challenge': challenge.challenge,
        'number': solution.number,
        'salt': challenge.salt,
        'signature': challenge.signature,
        'took': solution.took,
      };
      final payload = base64.encode(utf8.encode(json.encode(payloadObject)));
      if (widget.onVerified != null) {
        widget.onVerified!(payload);
      }
      return payload;
    }
  }

  Future<AltchaServerVerification> _requestServerVerification(
    String verifyUrl,
    payload,
    String? code,
  ) async {
    if (verifyUrl.isEmpty) {
      throw Exception('verifyUrl must be valid URL.');
    }
    try {
      final uri = _constructUrl(verifyUrl, widget.challengeUrl)!;
      _log('server verification url: ${uri.toString()}');
      final body = jsonEncode({
        'code': code,
        'payload': payload,
        'timeZone': _sentinelTimeZone
            ? (await _getTimezone())?.identifier
            : null,
      });
      final headers = {'Content-Type': 'application/json'};
      final response = await http.post(uri, body: body, headers: headers);
      _log(
        'server verification response: ${response.statusCode}: ${response.body}',
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
          'Sentinel verification failed with status ${response.statusCode}.',
        );
      }
    } on SocketException {
      throw NetworkException('Network error.');
    } on FormatException {
      throw DataParsingException('Malformed JSON.');
    } catch (e) {
      // Other unexpected errors
      rethrow;
    }
  }

  Future<AltchaSolution?> _solveChallenge(
    String algorithm,
    String challenge,
    String salt,
    int? max,
  ) async {
    final Stopwatch stopwatch = Stopwatch()..start();
    max ??= 1_000_000;
    for (int n = 0; n <= max; n++) {
      final String hashedValue = await _hashChallenge(salt, n, algorithm);
      if (hashedValue == challenge) {
        stopwatch.stop();
        return AltchaSolution(number: n, took: stopwatch.elapsedMilliseconds);
      }
    }
    return null;
  }

  Future<void> verify() async {
    reset();
    setState(() {
      _isLoading = true;
    });
    try {
      if (widget.delay != null) {
        await Future.delayed(Duration(milliseconds: widget.delay!));
      }
      final challenge = await _fetchChallenge();
      final verifyUrl = _getVerifyUrl();
      final payload = await _requestVerification(challenge);
      if (payload == null) {
        throw Exception('Failed to compute solution.');
      }
      if (challenge.codeChallenge?.image != null &&
          challenge.codeChallenge!.image.isNotEmpty) {
        if (verifyUrl == null || verifyUrl.isEmpty) {
          throw Exception('Received codeChallenge but verifyUrl is not set.');
        }
        setState(() {
          _isCodeRequired = true;
        });
        final code = await _requestCodeVerification(
          challenge.codeChallenge!.image,
          _constructUrl(challenge.codeChallenge!.audio, widget.challengeUrl),
          challenge.codeChallenge!.length,
        );
        setState(() {
          _isCodeRequired = false;
        });
        if (code == null) {
          throw Exception('Verification code was not entered.');
        }
        final serverVerification = await _requestServerVerification(
          verifyUrl,
          payload,
          code,
        );
        if (serverVerification.verified != true) {
          throw Exception('Server verification failed.');
        }
      } else if (verifyUrl != null && verifyUrl.isNotEmpty) {
        await _requestServerVerification(verifyUrl, payload, null);
      }
      setState(() {
        _isSolved = true;
      });
    } catch (e, stack) {
      _log('error: $e $stack');
      if (widget.onFailed != null) {
        widget.onFailed!(e);
      }
      setState(() {
        _errorMessage = AltchaLocalizations.of(context).text('error');
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void reset() {
    setState(() {
      _isCodeRequired = false;
      _isLoading = false;
      _isSolved = false;
      _errorMessage = '';
    });
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final localizations = AltchaLocalizations.of(context);

    return Container(
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
              if (_isCodeRequired)
                Row(
                  children: [
                    SizedBox(
                      width: 24,
                      height: 24,
                      child: Icon(Icons.warning, size: 24),
                    ),
                    SizedBox(width: 8.0),
                    Text(
                      localizations.text('verificationRequired'),
                      style: TextStyle(fontSize: 16.0),
                    ),
                  ],
                )
              else if (_isLoading)
                Row(
                  children: [
                    SizedBox(
                      width: 24,
                      height: 24,
                      child: CircularProgressIndicator(strokeWidth: 2.0),
                    ),
                    SizedBox(width: 8.0),
                    Text(
                      localizations.text('verifying'),
                      style: TextStyle(fontSize: 16.0),
                    ),
                  ],
                )
              else if (_isCodeRequired)
                Row(
                  children: [
                    SizedBox(
                      width: 24,
                      height: 24,
                      child: Icon(Icons.warning, size: 24),
                    ),
                    SizedBox(width: 8.0),
                    Text(
                      localizations.text('verificationRequired'),
                      style: TextStyle(fontSize: 16.0),
                    ),
                  ],
                )
              else if (_isSolved)
                Row(
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
                    SizedBox(width: 8.0),
                    Text(
                      localizations.text('verified'),
                      style: TextStyle(fontSize: 16.0),
                    ),
                  ],
                )
              else
                Row(
                  children: [
                    GestureDetector(
                      onTap: () {
                        verify();
                      },
                      behavior: HitTestBehavior.opaque,
                      child: Row(
                        children: [
                          SizedBox(
                            width: 24,
                            height: 24,
                            child: Checkbox(
                              value: _isSolved,
                              onChanged: (value) => verify(),
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
                    ),
                  ],
                ),
              const Spacer(),
              if (widget.hideLogo != true)
                SvgPicture.string(
                  altchaLogoSvg,
                  width: 24,
                  height: 24,
                  colorFilter: ColorFilter.mode(
                    Theme.of(
                      context,
                    ).colorScheme.onSurfaceVariant.withValues(alpha: 255 * 0.7),
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
              padding: EdgeInsets.only(top: 16.0),
              child: Align(
                alignment: Alignment.centerRight,
                child: Text(
                  localizations.text('footer'),
                  style: TextStyle(
                    color: Theme.of(
                      context,
                    ).colorScheme.onSurfaceVariant.withValues(alpha: 255 * 0.7),
                    fontSize: 12.0,
                  ),
                ),
              ),
            ),
        ],
      ),
    );
  }
}

const String altchaLogoSvg = '''
<svg width="22" height="22" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg">
  <path d="M2.33955 16.4279C5.88954 20.6586 12.1971 21.2105 16.4279 17.6604C18.4699 15.947 19.6548 13.5911 19.9352 11.1365L17.9886 10.4279C17.8738 12.5624 16.909 14.6459 15.1423 16.1284C11.7577 18.9684 6.71167 18.5269 3.87164 15.1423C1.03163 11.7577 1.4731 6.71166 4.8577 3.87164C8.24231 1.03162 13.2883 1.4731 16.1284 4.8577C16.9767 5.86872 17.5322 7.02798 17.804 8.2324L19.9522 9.01429C19.7622 7.07737 19.0059 5.17558 17.6604 3.57212C14.1104 -0.658624 7.80283 -1.21043 3.57212 2.33956C-0.658625 5.88958 -1.21046 12.1971 2.33955 16.4279Z" fill="currentColor"/>
  <path d="M3.57212 2.33956C1.65755 3.94607 0.496389 6.11731 0.12782 8.40523L2.04639 9.13961C2.26047 7.15832 3.21057 5.25375 4.8577 3.87164C8.24231 1.03162 13.2883 1.4731 16.1284 4.8577L13.8302 6.78606L19.9633 9.13364C19.7929 7.15555 19.0335 5.20847 17.6604 3.57212C14.1104 -0.658624 7.80283 -1.21043 3.57212 2.33956Z" fill="currentColor"/>
  <path d="M7 10H5C5 12.7614 7.23858 15 10 15C12.7614 15 15 12.7614 15 10H13C13 11.6569 11.6569 13 10 13C8.3431 13 7 11.6569 7 10Z" fill="currentColor"/>
</svg>
''';
