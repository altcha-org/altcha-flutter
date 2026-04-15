import 'dart:isolate';
import 'dart:typed_data';

import 'package:altcha_lib/algorithms.dart' show adaptiveDeriveKey;
import 'package:altcha_widget/altcha_widget.dart' show channelDeriveKey;
import 'package:altcha_lib/altcha_lib.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show MethodChannel;
// ---------------------------------------------------------------------------
// Benchmark configurations
// ---------------------------------------------------------------------------

class _Config {
  final String label;
  final String algorithm;
  final int cost;
  final int? memoryCost;
  final int? parallelism;
  // Fixed counter — the solver always finds this exact value, making the
  // benchmark deterministic (same number of key-derivation calls every run).
  final int counter;
  // When true, skip this config on web (algorithm cannot run reasonably
  // in a single-threaded JS environment).
  final bool webUnsupported;

  const _Config({
    required this.label,
    required this.algorithm,
    required this.cost,
    this.memoryCost,
    this.parallelism,
    required this.counter,
    this.webUnsupported = false,
  });
}

const _configs = [
  _Config(
    label: 'PBKDF2/SHA-256',
    algorithm: 'PBKDF2/SHA-256',
    cost: 5000,
    counter: 5000,
  ),
  _Config(label: 'SHA-256', algorithm: 'SHA-256', cost: 1000, counter: 1000),
  _Config(
    label: 'Argon2id (dart)',
    algorithm: 'ARGON2ID',
    cost: 2,
    memoryCost: 32768,
    parallelism: 1,
    counter: 10,
    webUnsupported: true,
  ),
  _Config(
    label: 'Scrypt (dart)',
    algorithm: 'SCRYPT',
    cost: 32768,
    memoryCost: 8,
    parallelism: 1,
    counter: 10,
    webUnsupported: true,
  ),
];

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

class _BenchmarkResult {
  final String label;
  final String algorithm;
  final int cost;
  final int? memoryCost;
  final int? counter;
  final int timeMs;
  final String? error;

  const _BenchmarkResult({
    required this.label,
    required this.algorithm,
    required this.cost,
    this.memoryCost,
    this.counter,
    required this.timeMs,
    this.error,
  });
}

// ---------------------------------------------------------------------------
// Challenge factory — runs in a background isolate so blocking key derivation
// (Scrypt, Argon2id) does not freeze the UI during setup.
// ---------------------------------------------------------------------------

Future<Challenge> _createChallenge(_Config config) {
  // Capture only primitives so the closure is sendable across isolate boundary.
  final algorithm = config.algorithm;
  final cost = config.cost;
  final memoryCost = config.memoryCost;
  final parallelism = config.parallelism;
  final counter = config.counter;

  Future<Challenge> fn() => createChallenge(
    algorithm: algorithm,
    cost: cost,
    memoryCost: memoryCost,
    parallelism: parallelism,
    counter: counter,
    keyLength: 32,
    deriveKey: adaptiveDeriveKey,
  );

  // Isolate.run spawns a web worker on web, which works for pure-Dart code.
  // Skip it only if we know it would fail; for now it's safe for all platforms.
  return kIsWeb ? fn() : Isolate.run(fn);
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

class BenchmarkPage extends StatefulWidget {
  const BenchmarkPage({super.key});

  @override
  State<BenchmarkPage> createState() => _BenchmarkPageState();
}

class _BenchmarkPageState extends State<BenchmarkPage> {
  int _workers = 1;
  bool _running = false;
  String? _currentLabel;
  final List<_BenchmarkResult> _results = [];

  Future<void> _runAll() async {
    setState(() {
      _running = true;
      _results.clear();
      _currentLabel = null;
    });

    for (final config in _configs) {
      if (!mounted) break;
      setState(() => _currentLabel = config.label);
      final result = await _run(config);
      if (mounted) setState(() => _results.add(result));
    }

    if (mounted) {
      setState(() {
        _running = false;
        _currentLabel = null;
      });
    }
  }

  Future<_BenchmarkResult> _run(_Config config) async {
    // Skip unsupported configs on web before doing any work (challenge creation
    // itself can block for Scrypt/Argon2id).
    if (kIsWeb && config.webUnsupported) {
      return _BenchmarkResult(
        label: config.label,
        algorithm: config.algorithm,
        cost: config.cost,
        memoryCost: config.memoryCost,
        timeMs: 0,
        error: 'Not supported on web',
      );
    }

    try {
      // Build challenge in a background isolate — derives keyPrefix for the
      // given counter, which may block for several seconds on Scrypt/Argon2id.
      final challenge = await _createChallenge(config);

      final start = DateTime.now();
      Solution? solution;

      final isPbkdf2 = config.algorithm.toUpperCase().startsWith('PBKDF2');
      if (!kIsWeb && isPbkdf2) {
        solution = await _solveNativePbkdf2(challenge);
      } else if (kIsWeb) {
        // Web: channelDeriveKey routes PBKDF2 and SHA to SubtleCrypto
        // (each await yields to the event loop, keeping the UI responsive).
        solution = await solveChallenge(
          challenge: challenge,
          deriveKey: channelDeriveKey,
        );
      } else {
        solution = await solveChallengeIsolates(
          challenge: challenge,
          deriveKey: adaptiveDeriveKey,
          concurrency: _workers,
        );
      }

      final elapsed = DateTime.now().difference(start).inMilliseconds;
      return _BenchmarkResult(
        label: config.label,
        algorithm: config.algorithm,
        cost: config.cost,
        memoryCost: config.memoryCost,
        counter: solution?.counter,
        timeMs: elapsed,
        error: solution == null ? 'timed out' : null,
      );
    } catch (e) {
      return _BenchmarkResult(
        label: config.label,
        algorithm: config.algorithm,
        cost: config.cost,
        memoryCost: config.memoryCost,
        timeMs: 0,
        error: e.toString(),
      );
    }
  }

  Future<Solution?> _solveNativePbkdf2(Challenge challenge) async {
    final params = challenge.parameters;
    final hash = params.algorithm.contains('/')
        ? params.algorithm.split('/')[1].toUpperCase()
        : 'SHA-256';
    final raw = await const MethodChannel('altcha_widget/pbkdf2')
        .invokeMethod<Map<dynamic, dynamic>>('solve', {
          'nonce': Uint8List.fromList(hexToBuffer(params.nonce)),
          'salt': Uint8List.fromList(hexToBuffer(params.salt)),
          'cost': params.cost,
          'keyLength': params.keyLength,
          'keyPrefix': params.keyPrefix,
          'hash': hash,
          'concurrency': _workers,
          'timeoutMs': 90000,
        });
    if (raw == null) return null;
    return Solution(
      counter: raw['counter'] as int,
      derivedKey: (raw['derivedKey'] as Uint8List)
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;

    return Scaffold(
      appBar: AppBar(title: const Text('Benchmark')),
      body: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // ── Controls ──────────────────────────────────────────────────
            Row(
              children: [
                if (!kIsWeb) ...[
                  const Text('Workers'),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Slider(
                      value: _workers.toDouble(),
                      min: 1,
                      max: 16,
                      divisions: 15,
                      label: '$_workers',
                      onChanged: _running
                          ? null
                          : (v) => setState(() => _workers = v.round()),
                    ),
                  ),
                  SizedBox(
                    width: 24,
                    child: Text(
                      '$_workers',
                      textAlign: TextAlign.right,
                      style: const TextStyle(fontWeight: FontWeight.bold),
                    ),
                  ),
                  const SizedBox(width: 16),
                ] else
                  const Spacer(),
                FilledButton(
                  onPressed: _running ? null : _runAll,
                  child: Text(_running ? 'Running…' : 'Run'),
                ),
              ],
            ),

            // ── Progress indicator ─────────────────────────────────────────
            AnimatedSize(
              duration: const Duration(milliseconds: 200),
              child: _running && _currentLabel != null
                  ? Padding(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      child: Row(
                        children: [
                          const SizedBox(
                            width: 14,
                            height: 14,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          ),
                          const SizedBox(width: 10),
                          Text(
                            'Running $_currentLabel…',
                            style: TextStyle(
                              fontSize: 13,
                              color: colorScheme.outline,
                            ),
                          ),
                        ],
                      ),
                    )
                  : const SizedBox.shrink(),
            ),

            const SizedBox(height: 8),

            // ── Results ───────────────────────────────────────────────────
            if (_results.isEmpty && !_running)
              Expanded(
                child: Center(
                  child: Text(
                    'Press Run to start benchmark',
                    style: TextStyle(color: colorScheme.outline),
                  ),
                ),
              )
            else
              Expanded(
                child: ListView(
                  children: _results
                      .map((r) => _ResultCard(result: r))
                      .toList(),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Result card
// ---------------------------------------------------------------------------

class _ResultCard extends StatelessWidget {
  final _BenchmarkResult result;
  const _ResultCard({required this.result});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final hasError = result.error != null;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              result.label,
              style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15),
            ),
            const SizedBox(height: 8),
            _Field('Algorithm', result.algorithm),
            _Field('Cost', '${result.cost}'),
            if (result.memoryCost != null)
              _Field('Mem cost', '${result.memoryCost}'),
            if (hasError)
              _Field('Error', result.error!, valueColor: colorScheme.error)
            else ...[
              _Field(
                'Counter',
                result.counter != null ? '${result.counter}' : '—',
              ),
              _Field(
                'Time',
                '${result.timeMs} ms',
                valueColor: colorScheme.primary,
                bold: true,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _Field extends StatelessWidget {
  final String label;
  final String value;
  final Color? valueColor;
  final bool bold;

  const _Field(this.label, this.value, {this.valueColor, this.bold = false});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          SizedBox(
            width: 80,
            child: Text(
              label,
              style: TextStyle(
                fontSize: 12,
                color: Theme.of(context).colorScheme.outline,
              ),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontSize: 12,
                fontWeight: bold ? FontWeight.bold : FontWeight.normal,
                color: valueColor,
              ),
            ),
          ),
        ],
      ),
    );
  }
}
