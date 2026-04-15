import 'dart:io';
import 'dart:isolate';

String get platformOsVersion => Platform.operatingSystemVersion;
bool get platformIsAndroid => Platform.isAndroid;
bool get platformIsIOS => Platform.isIOS;
bool get platformIsMacOS => Platform.isMacOS;
bool get platformIsWindows => Platform.isWindows;

Future<T?> isolateRun<T>(Future<T?> Function() fn) => Isolate.run<T?>(fn);
