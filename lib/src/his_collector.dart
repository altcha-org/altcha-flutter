import 'dart:math' as math;

import 'package:flutter/gestures.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';

import 'his_platform.dart';

// ---------------------------------------------------------------------------
// Sample tuples — mirror the JS types (altcha/src/his.ts, payload v2) directly.
// ClickSample  : [x, y, t, hold, offsetX, offsetY, pointerType, moves]
// FocusSample  : [elapsed, tabIndex, tagCode, hasInteraction]
// KeySample    : [t, hold]
// PointerSample: [x, y, t]
// ScrollSample : [y, t]
// TouchSample  : [x, y, t, pressure, radiusX, radiusY]
//
// Clocks: click/pointer/touch `t` use `PointerEvent.timeStamp`, key `t` uses
// `KeyEvent.timeStamp`, focus and scroll use the collector's monotonic clock.
// The server only compares timestamps within one channel.
// ---------------------------------------------------------------------------

/// Collects Human Interaction Signature (HIS) data while the widget is shown.
///
/// Mirrors the JS `Collector` class in altcha/src/his.ts (payload `v: 2`).
/// Captures pointer movements (mouse/stylus hover + drag), touch movements,
/// clicks (press position, hold time, offset from the target's center, pointer
/// type, preceding movement), hardware key timing (never key values), scroll
/// events and interaction samples.  Movement and scroll channels are throttled
/// to [sampleIntervalMs]; every channel is capped to the newest [maxSamples]
/// entries.  Keep the defaults: the server flags samples denser than 40 ms or
/// buffers longer than 60 as tampered.
class HisCollector {
  final int maxSamples;
  final int sampleIntervalMs;

  final _Channel<List<int>> _click = _Channel();
  final _Channel<List<int>> _focus = _Channel();
  final _Channel<List<int>> _key = _Channel();
  final _Channel<List<int>> _pointer = _Channel();
  final _Channel<List<int>> _scroll = _Channel();
  final _Channel<List<num>> _touch = _Channel();

  /// Monotonic clock for channels without an event timestamp (focus, scroll).
  final Stopwatch _clock = Stopwatch()..start();

  // Last-recorded timestamps per throttled channel, in the channel's clock (ms).
  double _lastPointerMs = 0;
  double _lastTouchMs = 0;
  double _lastScrollMs = 0;

  /// Raw (unthrottled) non-touch pointer move timestamps, newest last.
  final List<double> _moveTimes = [];

  ({List<int> sample, double down})? _pendingClick;

  final Map<PhysicalKeyboardKey, ({List<int> sample, double down})> _keysDown =
      {};

  /// Whether key timestamps come from [_clock] instead of
  /// `KeyEvent.timeStamp`; latched on the first key event so the channel
  /// never mixes clocks.  Guards against embedders reporting a zero timestamp.
  bool? _keyUsesClock;

  /// Whether [mark] was called; [exportSinceMark] returns [export] until then.
  bool _marked = false;

  HisCollector({this.maxSamples = 60, this.sampleIntervalMs = 50});

  /// Collected `[x, y, t, hold, offsetX, offsetY, pointerType, moves]` samples.
  List<List<int>> get click => _click.samples;

  /// Collected `[elapsed, tabIndex, tagCode, hasInteraction]` samples.
  List<List<int>> get focus => _focus.samples;

  /// Collected `[t, hold]` samples.
  List<List<int>> get key => _key.samples;

  /// Collected `[x, y, t]` samples.
  List<List<int>> get pointer => _pointer.samples;

  /// Collected `[y, t]` samples.
  List<List<int>> get scroll => _scroll.samples;

  /// Collected `[x, y, t, pressure, radiusX, radiusY]` samples.
  List<List<num>> get touch => _touch.samples;

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /// Register a global pointer route and keyboard handler so this collector
  /// receives all pointer and hardware key events across the entire app.
  /// Call once at app start for early collection.
  void attach() {
    GestureBinding.instance.pointerRouter.addGlobalRoute(_onPointerEvent);
    HardwareKeyboard.instance.addHandler(_onKeyEvent);
  }

  /// Remove the global pointer route and keyboard handler registered by
  /// [attach].
  void detach() {
    GestureBinding.instance.pointerRouter.removeGlobalRoute(_onPointerEvent);
    HardwareKeyboard.instance.removeHandler(_onKeyEvent);
  }

  void _onPointerEvent(PointerEvent event) {
    if (event is PointerDownEvent) {
      _recordPointerDown(event);
    } else if (event is PointerUpEvent) {
      _recordPointerUp(event);
    } else if (event is PointerHoverEvent || event is PointerMoveEvent) {
      if (event.kind != PointerDeviceKind.touch) {
        recordPointer(event);
      } else if (event is PointerMoveEvent) {
        recordTouch(event);
      }
    }
  }

  bool _onKeyEvent(KeyEvent event) {
    // Synthesized events are the framework reconciling key state (e.g. after
    // the window regains focus), not user input.  Repeats are not presses.
    if (event.synthesized || event is KeyRepeatEvent) {
      return false;
    }
    _keyUsesClock ??= event.timeStamp == Duration.zero;
    final now = _keyUsesClock! ? _clockMs : _ms(event.timeStamp);
    if (event is KeyDownEvent) {
      final sample = [now.round(), -1];
      _key.add(sample, maxSamples);
      _keysDown[event.physicalKey] = (sample: sample, down: now);
    } else if (event is KeyUpEvent) {
      final pending = _keysDown.remove(event.physicalKey);
      if (pending != null) {
        pending.sample[1] = (now - pending.down).round();
      }
    }
    return false;
  }

  // ── Public recording API ──────────────────────────────────────────────────

  /// Record a non-touch (mouse, stylus) pointer movement.
  ///
  /// Accepts both [PointerMoveEvent] (button pressed) and [PointerHoverEvent]
  /// (no button pressed) — both correspond to JS `pointermove` with
  /// `pointerType !== 'touch'`.
  void recordPointer(PointerEvent event) {
    final now = _ms(event.timeStamp);
    _moveTimes.add(now);
    if (_moveTimes.length > 32) {
      _moveTimes.removeAt(0);
    }
    if (now - _lastPointerMs >= sampleIntervalMs) {
      _pointer.add([
        event.position.dx.round(),
        event.position.dy.round(),
        now.round(),
      ], maxSamples);
      _lastPointerMs = now;
    }
  }

  /// Record a touch movement event.
  ///
  /// Corresponds to JS `touchmove`.
  void recordTouch(PointerMoveEvent event) {
    final now = _ms(event.timeStamp);
    if (now - _lastTouchMs >= sampleIntervalMs) {
      _touch.add([
        event.position.dx.round(),
        event.position.dy.round(),
        now.round(),
        0, // (event.pressure * 1000).round() / 1000,
        event.radiusMajor.round(),
        event.radiusMinor.round(),
      ], maxSamples);
      _lastTouchMs = now;
    }
  }

  /// Record a scroll update.  [pixels] is the current scroll offset.
  ///
  /// Corresponds to JS `scroll` event using `window.scrollY`.  Timestamped
  /// with the collector's monotonic clock.
  void recordScroll(double pixels) {
    final now = _clockMs;
    if (now - _lastScrollMs < sampleIntervalMs) return;
    _scroll.add([pixels.round(), now.round()], maxSamples);
    _lastScrollMs = now;
  }

  /// Record a user interaction (tap / key press) on the widget.
  ///
  /// Analogous to the JS `onFocus` + `onInteraction` pair.  In Flutter there
  /// is no global `focusin` event, so a sample is recorded whenever the user
  /// taps the ALTCHA widget itself.
  void recordInteraction() {
    _focus.add([_clockMs.round(), 0, 0, 1], maxSamples);
  }

  // ── Export ────────────────────────────────────────────────────────────────

  /// Returns the collected data in the same JSON-serialisable shape as the JS
  /// `Collector.export()` method.
  Map<String, dynamic> export() {
    return _payload(
      click: _click.samples,
      focus: _focus.samples,
      key: _key.samples,
      pointer: _pointer.samples,
      scroll: _scroll.samples,
      touch: _touch.samples,
    );
  }

  /// Starts the window of [exportSinceMark]; collected samples are kept.
  void mark() {
    _marked = true;
    _click.mark();
    _focus.mark();
    _key.mark();
    _pointer.mark();
    _scroll.mark();
    _touch.mark();
  }

  /// Same shape as [export], limited to samples collected since the latest
  /// [mark].  Focus `elapsed` is rebased to the first sample in the window.
  Map<String, dynamic> exportSinceMark() {
    if (!_marked) {
      return export();
    }
    final focus = _focus.sinceMark();
    final first = focus.isEmpty ? 0 : focus.first[0];
    return _payload(
      click: _click.sinceMark(),
      focus: [
        for (final s in focus) [s[0] - first, s[1], s[2], s[3]],
      ],
      key: _key.sinceMark(),
      pointer: _pointer.sinceMark(),
      scroll: _scroll.sinceMark(),
      touch: _touch.sinceMark(),
    );
  }

  // ── Internal ──────────────────────────────────────────────────────────────

  Map<String, dynamic> _payload({
    required List<List<int>> click,
    required List<List<int>> focus,
    required List<List<int>> key,
    required List<List<int>> pointer,
    required List<List<int>> scroll,
    required List<List<num>> touch,
  }) {
    return {
      'click': click,
      'focus': focus,
      'key': key,
      'maxTouchPoints': hisMaxTouchPoints,
      'pointer': pointer,
      'scroll': scroll,
      'time': DateTime.now().millisecondsSinceEpoch,
      'touch': touch,
      // Flutter has no script-dispatched (untrusted) input events.
      'untrusted': 0,
      'v': 2,
      'webdriver': hisWebdriver,
    };
  }

  double get _clockMs => _clock.elapsedMicroseconds / 1000;

  static double _ms(Duration d) => d.inMicroseconds / 1000;

  void _recordPointerDown(PointerDownEvent event) {
    final now = _ms(event.timeStamp);
    var moves = 0;
    for (final t in _moveTimes) {
      if (t >= now - 500 && t < now) {
        moves++;
      }
    }
    final offset = _targetOffset(event);
    final sample = [
      event.position.dx.round(),
      event.position.dy.round(),
      now.round(),
      -1,
      offset.dx.round(),
      offset.dy.round(),
      _pointerType(event.kind),
      moves,
    ];
    _click.add(sample, maxSamples);
    _pendingClick = (sample: sample, down: now);
  }

  void _recordPointerUp(PointerUpEvent event) {
    final pending = _pendingClick;
    if (pending != null) {
      pending.sample[3] = (_ms(event.timeStamp) - pending.down).round();
      _pendingClick = null;
    }
  }

  /// Offset of [event] from the center of the innermost render box under it
  /// (JS: `clientX - (rect.left + rect.width / 2)`); zero when none is found.
  static Offset _targetOffset(PointerDownEvent event) {
    final result = HitTestResult();
    GestureBinding.instance.hitTestInView(result, event.position, event.viewId);
    for (final entry in result.path) {
      final target = entry.target;
      final transform = entry.transform;
      if (target is RenderBox && target.hasSize && transform != null) {
        return MatrixUtils.transformPoint(transform, event.position) -
            target.size.center(Offset.zero);
      }
    }
    return Offset.zero;
  }

  /// JS `POINTER_TYPES`: mouse 0, pen 1, touch 2, other 3.
  static int _pointerType(PointerDeviceKind kind) => switch (kind) {
    PointerDeviceKind.mouse => 0,
    PointerDeviceKind.stylus || PointerDeviceKind.invertedStylus => 1,
    PointerDeviceKind.touch => 2,
    _ => 3,
  };
}

/// A capped sample buffer that remembers how many samples were added since
/// the latest [mark], independent of the samples' clock.
class _Channel<T> {
  final List<T> samples = [];
  int _added = 0;
  int _addedAtMark = 0;

  void add(T sample, int maxSamples) {
    samples.add(sample);
    _added++;
    if (samples.length > maxSamples) {
      samples.removeRange(0, samples.length - maxSamples);
    }
  }

  void mark() => _addedAtMark = _added;

  List<T> sinceMark() =>
      samples.sublist(math.max(0, samples.length - (_added - _addedAtMark)));
}
