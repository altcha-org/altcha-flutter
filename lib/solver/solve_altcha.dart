// solve_altcha.dart
// Programmatic ALTCHA solver using.

// Exports a single function `solveAltchaProgrammatic` which inserts a hidden
// AltchaWidget into the app's Overlay, triggers verification using the
// package's internal `verify()` method, waits for the `onVerified` callback,
// parses the returned payload and returns a Map with the expected fields:
// { "algorithm", "challenge", "number", "salt", "signature" }
// or `null` if timed out / failed / unparsable.

import 'dart:async';
import 'dart:convert';
import 'dart:developer' as dev;
import 'package:flutter/material.dart';
import '../widget.dart';

/// Attempts to solve an ALTCHA challenge programmatically using the package's
/// own solving logic. This does not show any visible UI: the AltchaWidget is
/// inserted into the app's Overlay inside an Offstage container and removed
/// as soon as the operation completes or times out.
///
/// [context] is required to get the Overlay. Provide either [challengeUrl]
/// or [challengeJson] like the widget expects. [timeout] controls how long
/// we will wait before giving up.
///
/// Returns a Map containing at least these keys: "algorithm", "challenge",
/// "number", "salt", "signature" — or `null` on timeout / failure / parse error.
///


Future<Map<String, dynamic>?> solveAltcha(
    BuildContext context, {
      String? challengeUrl,
      Map<String, dynamic>? challengeJson,
      Map<String, String>? httpHeaders,
      Duration timeout = const Duration(seconds: 20),
    }) async {
  final completer = Completer<Map<String, dynamic>?>();
  final key = GlobalKey<AltchaWidgetState>();
  OverlayEntry? entry;

  dev.log('[altcha] starting programmatic solve (timeout: ${timeout.inSeconds}s)');

  void cleanUp() {
    try {
      if (entry != null && entry.mounted) {
        entry.remove();
        dev.log('[altcha] removed overlay entry');
      }
    } catch (e, st) {
      dev.log('[altcha] cleanup error: \$e', stackTrace: st);
    }
  }

  // Build the hidden AltchaWidget
  final widget = Offstage(
    offstage: true,
    child: Material(
      child: AltchaWidget(
        key: key,
        challengeUrl: challengeUrl,
        challengeJson: challengeJson,
        httpHeaders: httpHeaders,
        debug: false,
        hideLogo: true,
        hideFooter: true,
        // Called when the widget solved the challenge and produced a payload
        onVerified: (payload) {
          dev.log('[altcha] onVerified called (payload length: \${payload?.length ?? 0})');

          Map<String, dynamic>? parsed;
          try {
            // Try direct JSON parse
            try {
              final j = json.decode(payload);
              if (j is Map<String, dynamic>) parsed = j;
            } catch (_) {
              // Maybe it's base64 -> JSON
              try {
                final bytes = base64.decode(payload);
                final txt = utf8.decode(bytes);
                final j2 = json.decode(txt);
                if (j2 is Map<String, dynamic>) parsed = j2;
              } catch (_) {
                // fallback: not JSON
                dev.log('[altcha] payload not JSON nor base64(JSON)');
              }
            }
          } catch (e, st) {
            dev.log('[altcha] parse error: \$e', stackTrace: st);
          }

          if (parsed != null) {
            // Ensure keys exist (algorithm, challenge, number, salt, signature)
            final ok = parsed.containsKey('algorithm') && parsed.containsKey('challenge') && parsed.containsKey('number') && parsed.containsKey('salt') && parsed.containsKey('signature');
            if (ok) {
              dev.log('[altcha] parsed payload contains expected keys');
              if (!completer.isCompleted) completer.complete(Map<String, dynamic>.from(parsed));
            } else {
              dev.log('[altcha] parsed payload missing expected keys: \${parsed.keys.toList()}');
              // still return parsed if it contains a nested "challenge" object
              if (!completer.isCompleted) completer.complete(parsed);
            }
          } else {
            dev.log('[altcha] payload unparsable — returning null');
            if (!completer.isCompleted) completer.complete(null);
          }
        },
        onFailed: (err) {
          dev.log('[altcha] onFailed: \$err');
          if (!completer.isCompleted) completer.complete(null);
        },
      ),
    ),
  );

  try {
    final overlay = Overlay.of(context);

    entry = OverlayEntry(builder: (_) => widget, maintainState: true);
    overlay.insert(entry);
    dev.log('[altcha] inserted hidden AltchaWidget into overlay');

    // Wait a frame to let the widget initialize
    await Future.delayed(const Duration(milliseconds: 50));

    // Trigger verification using the package's verify() method on the state
    final state = key.currentState;
    if (state == null) {
      dev.log('[altcha] AltchaWidgetState not available (null)');
      cleanUp();
      return null;
    }

    dev.log('[altcha] calling verify() on AltchaWidgetState');
    // call verify() and wait for the callback via completer
    try {
      // verify() may return Future<void> or be void — we don't rely on it
      await state.verify();
    } catch (e, st) {
      dev.log('[altcha] verify() threw: \$e', stackTrace: st);
    }

    // Wait for result or timeout
    final result = await completer.future.timeout(timeout, onTimeout: () {
      dev.log('[altcha] timeout waiting for verification result');
      return null;
    });

    return result;
  } catch (e, st) {
    dev.log('[altcha] unexpected error: \$e', stackTrace: st);
    return null;
  } finally {
    cleanUp();
  }
}