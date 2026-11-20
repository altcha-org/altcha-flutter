import 'dart:ffi';
import 'dart:io';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';

/// `navigator.maxTouchPoints` equivalent: the touch points of the device's
/// touchscreen, 0 without one.
///
/// Evaluated on every call, so a touchscreen attached later is picked up.
int get hisMaxTouchPoints {
  if (Platform.isAndroid || Platform.isIOS) {
    return 5; // typical for modern mobile devices
  }
  if (Platform.isWindows) {
    return _windowsMaxTouches();
  }
  if (Platform.isLinux) {
    try {
      return linuxMaxTouchPoints(
        File('/proc/bus/input/devices').readAsStringSync(),
      );
    } on FileSystemException {
      return 0;
    }
  }
  return 0;
}

/// `navigator.webdriver` equivalent; native apps have none.
bool get hisWebdriver => false;

/// `GetSystemMetrics(SM_MAXIMUMTOUCHES)`, the value Chromium reports as
/// `navigator.maxTouchPoints` on Windows.
final int Function(int) _getSystemMetrics = DynamicLibrary.open(
  'user32.dll',
).lookupFunction<Int32 Function(Int32), int Function(int)>('GetSystemMetrics');

const int _smMaximumTouches = 95;

int _windowsMaxTouches() => _getSystemMetrics(_smMaximumTouches);

/// `INPUT_PROP_DIRECT`: the device's coordinates map onto a screen.
const int _inputPropDirect = 0x01;
const int _absX = 0x00;
const int _absMtPositionX = 0x35;

/// Touch points from the contents of `/proc/bus/input/devices`: 10 for a
/// multi-touch screen, 1 for a single-touch screen, 0 without one.
///
/// A touchscreen is a direct-input device (unlike a touchpad) reporting
/// absolute positions.  Its exact slot count needs an `EVIOCGABS` ioctl on
/// `/dev/input/event*`, which regular users can't open; 10 is what
/// touchscreens commonly report (and what browsers then expose).
@visibleForTesting
int linuxMaxTouchPoints(String devices) {
  var max = 0;
  for (final device in devices.split(RegExp(r'\n\s*\n'))) {
    if (!_bit(_bitmap(device, 'PROP'), _inputPropDirect)) {
      continue;
    }
    final abs = _bitmap(device, 'ABS');
    if (_bit(abs, _absMtPositionX)) {
      max = math.max(max, 10);
    } else if (_bit(abs, _absX)) {
      max = math.max(max, 1);
    }
  }
  return max;
}

/// The `B: <name>=` bitmap of a device: space-separated hex `long`s, most
/// significant first, leading zeros omitted.
BigInt _bitmap(String device, String name) {
  final match = RegExp(
    '^B: $name=([0-9a-fA-F ]*)\$',
    multiLine: true,
  ).firstMatch(device);
  if (match == null) {
    return BigInt.zero;
  }
  final digits = sizeOf<Long>() * 2;
  final hex = match
      .group(1)!
      .trim()
      .split(' ')
      .where((w) => w.isNotEmpty)
      .map((w) => w.padLeft(digits, '0'))
      .join();
  return hex.isEmpty ? BigInt.zero : BigInt.parse(hex, radix: 16);
}

bool _bit(BigInt bitmap, int bit) => (bitmap >> bit).isOdd;
