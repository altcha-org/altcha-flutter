class AltchaServerVerification {
  final String algorithm;
  final String apiKey;
  final String id;
  final String payload;
  final num score;
  final String signature;
  final String verificationData;
  final bool verified;

  AltchaServerVerification({
    required this.algorithm,
    required this.apiKey,
    required this.id,
    required this.payload,
    required this.score,
    required this.signature,
    required this.verificationData,
    required this.verified,
  });

  Map<String, dynamic> toJson() {
    return {
      'algorithm': algorithm,
      'apiKey': apiKey,
      'id': id,
      'payload': payload,
      'score': score,
      'signature': signature,
      'verificationData': verificationData,
      'verified': verified,
    };
  }

  @override
  String toString() => toJson().toString();

  factory AltchaServerVerification.fromJson(Map<String, dynamic> json) {
    return AltchaServerVerification(
      algorithm: json['algorithm'] as String? ?? '',
      apiKey: json['apiKey'] as String? ?? '',
      id: json['id'] as String? ?? '',
      payload: json['payload'] as String? ?? '',
      score: json['score'] as num? ?? 0,
      signature: json['signature'] as String? ?? '',
      verificationData: json['verificationData'] as String? ?? '',
      verified: json['verified'] as bool? ?? false,
    );
  }
}
