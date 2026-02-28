import 'package:altcha_widget/widget.dart';
import 'package:flutter/material.dart';
import 'package:flutter_svg/svg.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:mocktail/mocktail.dart';
import 'dart:convert';

class MockHttpClient extends Mock implements http.Client {}

void main() {
  final testChallenge = {
    'algorithm': 'SHA-256',
    'challenge': 'c2fc6c6adf8ba0f575a35f48df52c0968a3dcd3c577c2769dc2f1035943b975e', // hash for "salt123"
    'maxNumber': 1000,
    'salt': 'salt',
    'signature': '612d40361f9708e5cf44f6001e66542efb70cb337a8b6bc47c7f32609d503127', // HMAC Key "secret123"
  };

  late MockHttpClient httpClient;

  setUp(() {
    httpClient = MockHttpClient();
    registerFallbackValue(Uri.parse('https://example.com'));
  });

  testWidgets('AltchaWidget builds and shows checkbox', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeUrl: 'https://example.com/altcha',
            debug: true,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    expect(find.byType(Checkbox), findsOneWidget);

    expect(find.text('I\'m not a robot'), findsOneWidget);
  });

  testWidgets('AltchaWidget builds and hides the footer', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeUrl: 'https://example.com/altcha',
            debug: true,
            hideFooter: true,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    expect(find.byType(Checkbox), findsOneWidget);

    expect(find.text('Protected by ALTCHA'), findsNothing);
  });

  testWidgets('AltchaWidget builds and hides the logo', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeUrl: 'https://example.com/altcha',
            debug: true,
            hideLogo: true,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    expect(find.byType(Checkbox), findsOneWidget);

    expect(find.byType(SvgPicture), findsNothing);
  });

  testWidgets('AltchaWidget passes basic verification with challengeJson', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeJson: testChallenge,
            debug: true,
            useIsolate: false,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    final checkboxFinder = find.byType(Checkbox);
    expect(checkboxFinder, findsOneWidget);

    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(seconds: 2));

    expect(find.text('Verified'), findsOneWidget);
  });

  testWidgets('AltchaWidget opens code challenge bottom sheet with challengeJson', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeJson: {
              ...testChallenge,
              'codeChallenge': {
                'image': 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
              },
            },
            debug: true,
            useIsolate: false,
            verifyUrl: 'https://example.com/verify',
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    final checkboxFinder = find.byType(Checkbox);
    expect(checkboxFinder, findsOneWidget);

    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(seconds: 2));

    expect(find.text('Verification required!'), findsOneWidget);
    expect(find.byKey(const Key('code_input')), findsOneWidget);
  });

  testWidgets('AltchaWidget passes verification with challengeUrl', (WidgetTester tester) async {
    when(() => httpClient.get(any(), headers: any(named: 'headers')))
        .thenAnswer((_) async => http.Response(jsonEncode(testChallenge), 200));

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeUrl: 'https://example.com/altcha',
            debug: true,
            httpClient: httpClient,
            useIsolate: false,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    final checkboxFinder = find.byType(Checkbox);
    expect(checkboxFinder, findsOneWidget);

    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(seconds: 2));

    expect(find.text('Verified'), findsOneWidget);
  });

  testWidgets('AltchaWidget shows error when request fails', (WidgetTester tester) async {
    when(() => httpClient.get(any(), headers: any(named: 'headers')))
        .thenAnswer((_) async => http.Response(jsonEncode({}), 404));

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: AltchaWidget(
            challengeUrl: 'https://example.com/altcha',
            debug: true,
            httpClient: httpClient,
            useIsolate: false,
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(AltchaWidget), findsOneWidget);

    final checkboxFinder = find.byType(Checkbox);
    expect(checkboxFinder, findsOneWidget);

    await tester.tap(checkboxFinder);
    await tester.pump(const Duration(seconds: 2));

    expect(find.text('Verification failed. Try again later.'), findsOneWidget);
  });
}
