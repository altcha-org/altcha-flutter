import 'dart:convert';
import 'package:altcha_widget/altcha_widget.dart';
import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';

import 'benchmark_page.dart';

void main() {
  runApp(const PreviewApp());
}

class PreviewApp extends StatefulWidget {
  const PreviewApp({super.key});

  @override
  State<PreviewApp> createState() => _PreviewAppState();
}

class _PreviewAppState extends State<PreviewApp> {
  ThemeMode _themeMode = ThemeMode.dark;
  Locale _locale = const Locale('en');

  void _toggleTheme() {
    setState(() {
      _themeMode =
          _themeMode == ThemeMode.dark ? ThemeMode.light : ThemeMode.dark;
    });
  }

  void _setLocale(Locale newLocale) {
    setState(() {
      _locale = newLocale;
    });
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'AltchaWidget Preview',
      supportedLocales: const [
        Locale('en'),
        Locale('de'),
        Locale('es'),
        Locale('fr'),
        Locale('it'),
        Locale('pt'),
      ],
      locale: _locale,
      localizationsDelegates: [
        const AltchaLocalizationsDelegate(
          customTranslations: {
            // Add custom translation overrides here
          },
        ),
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ],
      theme: ThemeData.light(),
      darkTheme: ThemeData.dark(),
      themeMode: _themeMode,
      home: AltchaDemoPage(
        onToggleTheme: _toggleTheme,
        themeMode: _themeMode,
        locale: _locale,
        onLocaleChanged: _setLocale,
      ),
    );
  }
}

class AltchaDemoPage extends StatefulWidget {
  final VoidCallback onToggleTheme;
  final ThemeMode themeMode;
  final Locale locale;
  final ValueChanged<Locale> onLocaleChanged;

  const AltchaDemoPage({
    super.key,
    required this.onToggleTheme,
    required this.themeMode,
    required this.locale,
    required this.onLocaleChanged,
  });

  @override
  State<AltchaDemoPage> createState() => _AltchaDemoPageState();
}

class _AltchaDemoPageState extends State<AltchaDemoPage> {
  final GlobalKey<AltchaWidgetState> _altchaKey = GlobalKey();

  final TextEditingController _challengeUrlController = TextEditingController(
    text: 'https://sentinel-test.b-cdn.net/v1/challenge?apiKey=key_1j4lrsfk900a3ukffs7', //'http://127.0.0.1:3000/v1/challenge',
  );

  String _challengeUrl = 'https://sentinel-test.b-cdn.net/v1/challenge?apiKey=key_1j4lrsfk900a3ukffs7'; //'http://127.0.0.1:3000/v1/challenge';

  String? _verifiedPayload;
  AltchaServerVerification? _serverVerification;

  final String _origin = 'com.example.myapp';

  final List<Locale> _locales = const [
    Locale('en'),
    Locale('de'),
    Locale('es'),
    Locale('fr'),
    Locale('it'),
    Locale('pt'),
  ];

  @override
  void dispose() {
    _challengeUrlController.dispose();
    super.dispose();
  }

  void _updateParams() {
    setState(() {
      _challengeUrl = _challengeUrlController.text;
      _verifiedPayload = null;
      _serverVerification = null;
    });
    _altchaKey.currentState?.reset();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final isDark = widget.themeMode == ThemeMode.dark;

    return Scaffold(
      appBar: AppBar(
        title: const Text('AltchaWidget Preview'),
        actions: [
          TextButton.icon(
            icon: const Icon(Icons.speed),
            label: const Text('Benchmark'),
            onPressed: () => Navigator.push(
              context,
              MaterialPageRoute(builder: (_) => const BenchmarkPage()),
            ),
          ),
        ],
      ),
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 360),
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: colorScheme.surface,
                    border: Border.all(color: colorScheme.outline),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      TextField(
                        controller: _challengeUrlController,
                        decoration: const InputDecoration(
                          labelText: 'Challenge URL',
                        ),
                        onSubmitted: (_) => _updateParams(),
                      ),
                      const SizedBox(height: 16),
                      AltchaWidget(
                        key: _altchaKey,
                        challenge: _challengeUrl,
                        debug: true,
                        origin: _origin,
                        onFailed: (e) {
                          debugPrint('altcha failed: $e');
                        },
                        onServerVerification: (verification) {
                          setState(() => _serverVerification = verification);
                          debugPrint('altcha server verification: $verification');
                        },
                        onVerified: (value) {
                          setState(() => _verifiedPayload = value);
                          debugPrint('altcha verified: $value');
                        },
                      ),
                      const SizedBox(height: 16),
                      ElevatedButton(
                        onPressed: _updateParams,
                        child: const Text('Update & Reset'),
                      ),
                      const SizedBox(height: 8),
                      ElevatedButton(
                        onPressed: widget.onToggleTheme,
                        child: Text(
                          isDark
                              ? 'Switch to Light Mode'
                              : 'Switch to Dark Mode',
                        ),
                      ),
                      const SizedBox(height: 16),
                      Row(
                        children: [
                          const Text('Locale: '),
                          const SizedBox(width: 12),
                          Expanded(
                            child: DropdownButton<Locale>(
                              isExpanded: true,
                              value: widget.locale,
                              items: _locales.map((locale) {
                                return DropdownMenuItem<Locale>(
                                  value: locale,
                                  child: Text(
                                      locale.languageCode.toUpperCase()),
                                );
                              }).toList(),
                              onChanged: (newLocale) {
                                if (newLocale != null) {
                                  widget.onLocaleChanged(newLocale);
                                }
                              },
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                if (_verifiedPayload != null || _serverVerification != null) ...[
                  const SizedBox(height: 16),
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        if (_verifiedPayload != null) ...[
                          const Text(
                            'Payload:',
                            style: TextStyle(
                                fontWeight: FontWeight.bold, fontSize: 12),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            _verifiedPayload!,
                            style: const TextStyle(fontSize: 11),
                          ),
                        ],
                        if (_serverVerification != null) ...[
                          const SizedBox(height: 8),
                          const Text(
                            'Server Verification:',
                            style: TextStyle(
                                fontWeight: FontWeight.bold, fontSize: 12),
                          ),
                          const SizedBox(height: 4),
                          Text(
                            const JsonEncoder.withIndent('  ')
                                .convert(_serverVerification!.toJson()),
                            style: const TextStyle(fontSize: 11),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }
}
