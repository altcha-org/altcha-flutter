import 'package:web/web.dart' as web;

/// The browser's `navigator.maxTouchPoints`.
int get hisMaxTouchPoints => web.window.navigator.maxTouchPoints;

/// The browser's `navigator.webdriver`.
bool get hisWebdriver => web.window.navigator.webdriver;
