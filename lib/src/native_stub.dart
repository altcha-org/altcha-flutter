String get platformOsVersion => '';
bool get platformIsAndroid => false;
bool get platformIsIOS => false;
bool get platformIsMacOS => false;
bool get platformIsWindows => false;

Future<T?> isolateRun<T>(Future<T?> Function() fn) => fn();
