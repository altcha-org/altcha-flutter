#ifndef FLUTTER_PLUGIN_ALTCHA_WIDGET_PLUGIN_H_INTERNAL_
#define FLUTTER_PLUGIN_ALTCHA_WIDGET_PLUGIN_H_INTERNAL_

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>

#include <memory>

class AltchaWidgetPlugin : public flutter::Plugin {
 public:
  static void RegisterWithRegistrar(flutter::PluginRegistrarWindows* registrar);

  AltchaWidgetPlugin();
  ~AltchaWidgetPlugin() override;

  AltchaWidgetPlugin(const AltchaWidgetPlugin&) = delete;
  AltchaWidgetPlugin& operator=(const AltchaWidgetPlugin&) = delete;

 private:
  void HandleMethodCall(
      const flutter::MethodCall<flutter::EncodableValue>& method_call,
      std::unique_ptr<flutter::MethodResult<flutter::EncodableValue>> result);
};

#endif  // FLUTTER_PLUGIN_ALTCHA_WIDGET_PLUGIN_H_INTERNAL_
