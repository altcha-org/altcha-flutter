import 'dart:convert';
import 'package:altcha_widget/src/localizations.dart';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'audio_button.dart';

class AltchaCodeChallengeWidget extends StatefulWidget {
  final void Function(String message)? log;
  final Uri? audioUrl;
  final int? codeLength;
  final String imageBase64;
  final void Function(String code) onSubmit;
  final VoidCallback onCancel;
  final VoidCallback onReload;
  final http.Client? httpClient;
  final Map<String, String>? httpHeaders;

  const AltchaCodeChallengeWidget({
    super.key,
    required this.imageBase64,
    required this.audioUrl,
    required this.onSubmit,
    required this.onCancel,
    required this.onReload,
    this.codeLength,
    this.log,
    this.httpClient,
    this.httpHeaders,
  });

  @override
  State<AltchaCodeChallengeWidget> createState() =>
      _AltchaCodeChallengeWidgetState();
}

class _AltchaCodeChallengeWidgetState
    extends State<AltchaCodeChallengeWidget> {
  final TextEditingController _controller = TextEditingController();
  final GlobalKey<FormState> _formKey = GlobalKey<FormState>();
  final FocusNode _inputFocusNode = FocusNode();

  void _submit() {
    if (_formKey.currentState?.validate() ?? false) {
      widget.onSubmit(_controller.text.trim());
    } else {
      _inputFocusNode.requestFocus();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    _inputFocusNode.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final localizations = AltchaLocalizations.of(context);
    final imageBytes = base64Decode(widget.imageBase64.split(',').last);

    final mq = MediaQuery.of(context);
    return Padding(
      padding: EdgeInsets.only(
        top: 16,
        left: 16,
        right: 16,
        bottom: mq.viewInsets.bottom + mq.viewPadding.bottom + 16,
      ),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 300),
        child: Form(
          key: _formKey,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: double.infinity,
                height: 80,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: Colors.white,
                  border: Border.all(color: colorScheme.outline, width: 1.0),
                  borderRadius: BorderRadius.circular(4.0),
                ),
                child: Image.memory(
                  imageBytes,
                  fit: BoxFit.none,
                  alignment: Alignment.center,
                  errorBuilder: (context, error, stackTrace) =>
                      const Text('Failed to load image'),
                ),
              ),
              const SizedBox(height: 12),
              TextFormField(
                key: const Key('code_input'),
                controller: _controller,
                focusNode: _inputFocusNode,
                decoration: InputDecoration(
                  labelText: localizations.text('enterCode'),
                  border: const OutlineInputBorder(),
                  counterText: widget.codeLength != null ? '' : null,
                ),
                maxLength: widget.codeLength,
                textInputAction: TextInputAction.done,
                validator: (value) {
                  if (value == null || value.trim().isEmpty) {
                    return localizations.text('required');
                  }
                  if (widget.codeLength != null &&
                      value.trim().length != widget.codeLength) {
                    return localizations.text('incompleteCode');
                  }
                  return null;
                },
                onChanged: (value) {
                  if (widget.codeLength != null &&
                      value.trim().length == widget.codeLength) {
                    _submit();
                  }
                },
                onFieldSubmitted: (_) => _submit(),
              ),
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  if (widget.audioUrl != null)
                    AltchaAudioButtonWidget(
                      log: widget.log,
                      url: widget.audioUrl!,
                      httpClient: widget.httpClient,
                      httpHeaders: widget.httpHeaders,
                    ),
                  const Spacer(),
                  IconButton(
                    onPressed: widget.onReload,
                    icon: const Icon(Icons.refresh),
                    tooltip: localizations.text('reload'),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: colorScheme.primary,
                    foregroundColor: colorScheme.onPrimary,
                  ),
                  onPressed: _submit,
                  child: Text(localizations.text('verify')),
                ),
              ),
              const SizedBox(height: 8),
              SizedBox(
                width: double.infinity,
                child: TextButton(
                  onPressed: widget.onCancel,
                  child: Text(localizations.text('cancel')),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
