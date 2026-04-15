import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/gestures.dart';

// ---------------------------------------------------------------------------
// Sample tuples — mirror the JS types directly.
// FocusSample  : [elapsed, tabIndex, tagCode, hasInteraction]
// PointerSample: [x, y, t]
// ScrollSample : [y, t]
// TouchSample  : [x, y, t, pressure, radiusX, radiusY]
// ---------------------------------------------------------------------------

/// Collects Human Interaction Signature (HIS) data while the widget is shown.
///
/// Mirrors the JS `Collector` class in altcha/src/his.ts.  Captures pointer
/// movements (mouse hover + drag), touch movements, scroll events, and
/// focus/interaction samples at [sampleIntervalMs] ms throttle, capped to
/// [maxSamples] entries per buffer.
class HisCollector {
  final int maxSamples;
  final int sampleIntervalMs;

  final List<List<int>> focus = [];
  final List<List<int>> pointer = [];
  final List<List<int>> scroll = [];
  final List<List<num>> touch = [];

  final int _startMs;

  // Last-recorded timestamps per channel (milliseconds, same epoch as
  // PointerEvent.timeStamp so throttle comparisons are valid).
  int _lastPointerMs = 0;
  int _lastTouchMs = 0;
  int _lastScrollMs = 0;

  // Most-recent pending sample — updated on every event, committed only when
  // the throttle interval has elapsed (matches JS pendingPointer / pendingTouch).
  List<int>? _pendingPointer;
  List<num>? _pendingTouch;

  HisCollector({this.maxSamples = 60, this.sampleIntervalMs = 50})
      : _startMs = DateTime.now().millisecondsSinceEpoch;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Register a global pointer route so this collector receives all pointer
  /// events across the entire app.  Call once at app start for early collection.
  void attach() {
    GestureBinding.instance.pointerRouter.addGlobalRoute(_onPointerEvent);
  }

  /// Remove the global pointer route registered by [attach].
  void detach() {
    GestureBinding.instance.pointerRouter.removeGlobalRoute(_onPointerEvent);
  }

  void _onPointerEvent(PointerEvent event) {
    if (event is PointerHoverEvent && event.kind == PointerDeviceKind.mouse) {
      recordPointer(event);
    } else if (event is PointerMoveEvent) {
      if (event.kind == PointerDeviceKind.mouse) {
        recordPointer(event);
      } else if (event.kind == PointerDeviceKind.touch) {
        recordTouch(event);
      }
    }
  }

  // ── Public recording API ──────────────────────────────────────────────────

  /// Record a mouse pointer movement.
  ///
  /// Accepts both [PointerMoveEvent] (button pressed) and [PointerHoverEvent]
  /// (no button pressed) — both correspond to JS `pointermove` with
  /// `pointerType !== 'touch'`.
  void recordPointer(PointerEvent event) {
    final t = event.timeStamp.inMilliseconds;
    _pendingPointer = [
      event.position.dx.round(),
      event.position.dy.round(),
      t,
    ];
    if (t - _lastPointerMs >= sampleIntervalMs) {
      pointer.add(_pendingPointer!);
      _lastPointerMs = t;
      _pendingPointer = null;
      _evict(pointer);
    }
  }

  /// Record a touch movement event.
  ///
  /// Corresponds to JS `touchmove`.
  void recordTouch(PointerMoveEvent event) {
    final t = event.timeStamp.inMilliseconds;
    _pendingTouch = [
      event.position.dx.round(),
      event.position.dy.round(),
      t,
      0, // (event.pressure * 1000).round() / 1000,
      event.radiusMajor.round(),
      event.radiusMinor.round(),
    ];
    if (t - _lastTouchMs >= sampleIntervalMs) {
      touch.add(_pendingTouch!);
      _lastTouchMs = t;
      _pendingTouch = null;
      _evict(touch);
    }
  }

  /// Record a scroll update.  [pixels] is the current scroll offset.
  ///
  /// Corresponds to JS `scroll` event using `window.scrollY`.
  void recordScroll(double pixels, int timestampMs) {
    if (timestampMs - _lastScrollMs < sampleIntervalMs) return;
    scroll.add([pixels.round(), timestampMs]);
    _lastScrollMs = timestampMs;
    _evict(scroll);
  }

  /// Record a user interaction (tap / key press) on the widget.
  ///
  /// Analogous to the JS `onFocus` + `onInteraction` pair.  In Flutter there
  /// is no global `focusin` event, so a sample is recorded whenever the user
  /// taps the ALTCHA widget itself.
  void recordInteraction() {
    final elapsed = DateTime.now().millisecondsSinceEpoch - _startMs;
    focus.add([elapsed, 0, 0, 1]);
    _evict(focus);
  }

  // ── Export ────────────────────────────────────────────────────────────────

  /// Returns the collected data in the same JSON-serialisable shape as the JS
  /// `Collector.export()` method.
  Map<String, dynamic> export() {
    return {
      'focus': focus,
      'maxTouchPoints': _maxTouchPoints(),
      'pointer': pointer,
      'scroll': scroll,
      'time': DateTime.now().millisecondsSinceEpoch,
      'touch': touch,
    };
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  void _evict<T>(List<T> buffer) {
    if (buffer.length > maxSamples) {
      buffer.removeRange(0, buffer.length - maxSamples);
    }
  }

  int _maxTouchPoints() {
    if (kIsWeb) return 0; // browser reports this itself via navigator.maxTouchPoints
    if (Platform.isAndroid || Platform.isIOS) return 5; // typical for modern mobile devices
    return 0;
  }
}
