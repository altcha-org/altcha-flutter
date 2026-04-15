import 'package:flutter/material.dart';

class AltchaLocalizations {
  final Locale locale;
  final Map<String, Map<String, String>> _customTranslations;

  AltchaLocalizations(
    this.locale, [
    Map<String, Map<String, String>>? customTranslations,
  ]) : _customTranslations = customTranslations ?? {};

  static AltchaLocalizations of(BuildContext context) {
    return Localizations.of<AltchaLocalizations>(
          context,
          AltchaLocalizations,
        ) ??
        AltchaLocalizations(const Locale('en'));
  }

  static const Map<String, Map<String, String>> _defaultLocalizedValues = {
    'en': {
      'cancel': 'Cancel',
      'enterCode': 'Enter code',
      'error': 'Verification failed. Try again later.',
      'expired': 'Verification expired. Try again.',
      'footer': 'Protected by ALTCHA',
      'incompleteCode': 'Incomplete code. Try again.',
      'label': 'I\'m not a robot',
      'playAudio': 'Play Audio',
      'reload': 'Reload',
      'required': 'Required',
      'stopAudio': 'Stop Audio',
      'verify': 'Verify',
      'verificationRequired': 'Verification required!',
      'verified': 'Verified',
      'verifying': 'Verifying...',
    },
    'de': {
      'cancel': 'Abbrechen',
      'enterCode': 'Code eingeben',
      'error': 'Verifizierung fehlgeschlagen. Bitte versuchen Sie es später erneut.',
      'expired': 'Verifizierung abgelaufen. Bitte erneut versuchen.',
      'footer': 'Geschützt von ALTCHA',
      'incompleteCode': 'Unvollständiger Code. Bitte erneut versuchen.',
      'label': 'Ich bin kein Roboter',
      'playAudio': 'Audio abspielen',
      'reload': 'Neu laden',
      'required': 'Erforderlich',
      'stopAudio': 'Audio stoppen',
      'verify': 'Verifizieren',
      'verificationRequired': 'Verifizierung erforderlich!',
      'verified': 'Verifiziert',
      'verifying': 'Verifiziere...',
    },
    'es': {
      'cancel': 'Cancelar',
      'enterCode': 'Introducir código',
      'error': 'La verificación falló. Inténtalo más tarde.',
      'expired': 'La verificación expiró. Inténtalo de nuevo.',
      'footer': 'Protegido por ALTCHA',
      'incompleteCode': 'Código incompleto. Inténtalo de nuevo.',
      'label': 'No soy un robot',
      'playAudio': 'Reproducir audio',
      'reload': 'Recargar',
      'required': 'Requerido',
      'stopAudio': 'Detener audio',
      'verify': 'Verificar',
      'verificationRequired': '¡Se requiere verificación!',
      'verified': 'Verificado',
      'verifying': 'Verificando...',
    },
    'fr': {
      'cancel': 'Annuler',
      'enterCode': 'Entrer le code',
      'error': 'Échec de la vérification. Réessayez plus tard.',
      'expired': 'La vérification a expiré. Réessayez.',
      'footer': 'Protégé par ALTCHA',
      'incompleteCode': 'Code incomplet. Réessayez.',
      'label': 'Je ne suis pas un robot',
      'playAudio': 'Lire l\'audio',
      'reload': 'Recharger',
      'required': 'Obligatoire',
      'stopAudio': 'Arrêter l\'audio',
      'verify': 'Vérifier',
      'verificationRequired': 'Vérification requise !',
      'verified': 'Vérifié',
      'verifying': 'Vérification en cours...',
    },
    'it': {
      'cancel': 'Annulla',
      'enterCode': 'Inserisci il codice',
      'error': 'Verifica fallita. Riprova più tardi.',
      'expired': 'La verifica è scaduta. Riprova.',
      'footer': 'Protetto da ALTCHA',
      'incompleteCode': 'Codice incompleto. Riprova.',
      'label': 'Non sono un robot',
      'playAudio': 'Riproduci audio',
      'reload': 'Ricarica',
      'required': 'Obbligatorio',
      'stopAudio': 'Ferma audio',
      'verify': 'Verifica',
      'verificationRequired': 'Verifica richiesta!',
      'verified': 'Verificato',
      'verifying': 'Verifica in corso...',
    },
    'pt': {
      'cancel': 'Cancelar',
      'enterCode': 'Digite o código',
      'error': 'Verificação falhou. Tente novamente mais tarde.',
      'expired': 'Verificação expirada. Tente novamente.',
      'footer': 'Protegido por ALTCHA',
      'incompleteCode': 'Código incompleto. Tente novamente.',
      'label': 'Não sou um robô',
      'playAudio': 'Reproduzir áudio',
      'reload': 'Recarregar',
      'required': 'Obrigatório',
      'stopAudio': 'Parar áudio',
      'verify': 'Verificar',
      'verificationRequired': 'Verificação necessária!',
      'verified': 'Verificado',
      'verifying': 'Verificando...',
    },
  };

  String text(String key) {
    final languageCode = locale.languageCode;

    if (_customTranslations.containsKey(languageCode) &&
        _customTranslations[languageCode]!.containsKey(key)) {
      return _customTranslations[languageCode]![key]!;
    }

    if (_defaultLocalizedValues.containsKey(languageCode) &&
        _defaultLocalizedValues[languageCode]!.containsKey(key)) {
      return _defaultLocalizedValues[languageCode]![key]!;
    }

    return _defaultLocalizedValues['en']?[key] ?? key;
  }
}

class AltchaLocalizationsDelegate
    extends LocalizationsDelegate<AltchaLocalizations> {
  final Map<String, Map<String, String>> customTranslations;

  const AltchaLocalizationsDelegate({this.customTranslations = const {}});

  @override
  bool isSupported(Locale locale) =>
      ['en', 'de', 'es', 'fr', 'it', 'pt'].contains(locale.languageCode) ||
      customTranslations.containsKey(locale.languageCode);

  @override
  Future<AltchaLocalizations> load(Locale locale) async {
    return AltchaLocalizations(locale, customTranslations);
  }

  @override
  bool shouldReload(covariant LocalizationsDelegate<AltchaLocalizations> old) =>
      false;
}
