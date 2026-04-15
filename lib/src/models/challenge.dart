import 'package:altcha_lib/altcha_lib.dart';

class AltchaCodeChallenge {
  final String image;
  final int? length;
  final String? audio;

  AltchaCodeChallenge({required this.image, this.audio, this.length});

  factory AltchaCodeChallenge.fromJson(Map<String, dynamic> json) {
    return AltchaCodeChallenge(
      audio: json['audio'] as String?,
      image: json['image'] as String,
      length: json['length'] as int?,
    );
  }
}

/// Wraps the [Challenge] from altcha_lib and adds optional [codeChallenge]
/// returned by the server alongside the PoW challenge.
class AltchaChallenge {
  final Challenge challenge;
  final AltchaCodeChallenge? codeChallenge;

  AltchaChallenge({required this.challenge, this.codeChallenge});

  factory AltchaChallenge.fromJson(Map<String, dynamic> json) {
    return AltchaChallenge(
      challenge: Challenge.fromJson(json),
      codeChallenge: json['codeChallenge'] != null
          ? AltchaCodeChallenge.fromJson(
              json['codeChallenge'] as Map<String, dynamic>,
            )
          : null,
    );
  }
}

/// Represents a server response that requests Human Interaction Signature
/// (HIS) data before issuing the actual challenge.
///
/// When the challenge endpoint returns `{ "his": { "url": "..." } }` the
/// widget must POST collected HIS data to [url] and use the response body
/// as the actual challenge JSON.
class AltchaHisRequest {
  final String url;

  const AltchaHisRequest({required this.url});

  static AltchaHisRequest? tryFromJson(Map<String, dynamic> json) {
    final his = json['his'];
    if (his is Map<String, dynamic>) {
      final url = his['url'] as String?;
      if (url != null && url.isNotEmpty) {
        return AltchaHisRequest(url: url);
      }
    }
    return null;
  }
}
