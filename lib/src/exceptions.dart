class NetworkException implements Exception {
  final String message;
  NetworkException([this.message = 'Network error occurred']);
  @override
  String toString() => message;
}

class ServerException implements Exception {
  final int statusCode;
  final String message;
  ServerException(this.statusCode, [this.message = 'Server error occurred']);
  @override
  String toString() => 'ServerException($statusCode): $message';
}

class DataParsingException implements Exception {
  final String message;
  DataParsingException([this.message = 'Failed to parse data']);
  @override
  String toString() => message;
}
