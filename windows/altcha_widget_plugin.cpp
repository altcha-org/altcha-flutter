// altcha_widget_plugin.cpp — Flutter Windows plugin for ALTCHA PBKDF2 solver.

#include "altcha_widget_plugin.h"
#include "include/altcha_widget/altcha_widget_plugin.h"

#include <flutter/method_channel.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "altcha_pbkdf2_solver.h"

namespace {

// ---------------------------------------------------------------------------
// Helpers to extract typed values from EncodableMap args
// ---------------------------------------------------------------------------

using EncodableMap   = flutter::EncodableMap;
using EncodableValue = flutter::EncodableValue;

static const EncodableValue* MapLookup(const EncodableMap& map,
                                       const std::string& key) {
    auto it = map.find(EncodableValue(key));
    return (it != map.end()) ? &it->second : nullptr;
}

static std::vector<uint8_t> GetBytes(const EncodableMap& map,
                                     const std::string& key) {
    const auto* v = MapLookup(map, key);
    if (!v) return {};
    return std::get<std::vector<uint8_t>>(*v);
}

static int GetInt(const EncodableMap& map, const std::string& key,
                  int def = 0) {
    const auto* v = MapLookup(map, key);
    if (!v) return def;
    if (std::holds_alternative<int32_t>(*v)) return std::get<int32_t>(*v);
    if (std::holds_alternative<int64_t>(*v))
        return static_cast<int>(std::get<int64_t>(*v));
    return def;
}

static int64_t GetInt64(const EncodableMap& map, const std::string& key,
                        int64_t def = 0) {
    const auto* v = MapLookup(map, key);
    if (!v) return def;
    if (std::holds_alternative<int64_t>(*v)) return std::get<int64_t>(*v);
    if (std::holds_alternative<int32_t>(*v)) return std::get<int32_t>(*v);
    return def;
}

static std::string GetString(const EncodableMap& map, const std::string& key) {
    const auto* v = MapLookup(map, key);
    if (!v) return {};
    return std::get<std::string>(*v);
}

static std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> out(hex.size() / 2, 0);
    for (size_t i = 0; i < out.size(); i++) {
        out[i] = (uint8_t)std::stoi(hex.substr(i * 2, 2), nullptr, 16);
    }
    return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// Plugin implementation
// ---------------------------------------------------------------------------

void AltchaWidgetPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows* registrar) {
    auto channel = std::make_unique<flutter::MethodChannel<EncodableValue>>(
        registrar->messenger(), "altcha_widget/pbkdf2",
        &flutter::StandardMethodCodec::GetInstance());

    auto plugin = std::make_unique<AltchaWidgetPlugin>();

    channel->SetMethodCallHandler(
        [plugin_ptr = plugin.get()](const auto& call, auto result) {
            plugin_ptr->HandleMethodCall(call, std::move(result));
        });

    registrar->AddPlugin(std::move(plugin));
}

AltchaWidgetPlugin::AltchaWidgetPlugin() {}
AltchaWidgetPlugin::~AltchaWidgetPlugin() {}

void AltchaWidgetPlugin::HandleMethodCall(
    const flutter::MethodCall<EncodableValue>& method_call,
    std::unique_ptr<flutter::MethodResult<EncodableValue>> result) {

    if (method_call.method_name() != "solve") {
        result->NotImplemented();
        return;
    }

    const auto* args_val = method_call.arguments();
    if (!args_val || !std::holds_alternative<EncodableMap>(*args_val)) {
        result->Error("BAD_ARGS", "Expected map");
        return;
    }
    const auto& args = std::get<EncodableMap>(*args_val);

    std::vector<uint8_t> nonce  = GetBytes(args, "nonce");
    std::vector<uint8_t> salt   = GetBytes(args, "salt");
    int  cost        = GetInt(args, "cost");
    int  key_length  = GetInt(args, "keyLength");
    int  concurrency = GetInt(args, "concurrency", 4);
    int64_t timeout  = GetInt64(args, "timeoutMs", 90000);

    std::string hash_str = GetString(args, "hash");
    int hash_id = 256;
    if (hash_str.find("512") != std::string::npos)      hash_id = 512;
    else if (hash_str.find("384") != std::string::npos) hash_id = 384;

    std::string prefix_hex = GetString(args, "keyPrefix");
    std::vector<uint8_t> prefix_bytes;
    if (!prefix_hex.empty()) prefix_bytes = HexToBytes(prefix_hex);

    // flutter::MethodResult is safe to call from another thread.
    auto shared_result = std::shared_ptr<flutter::MethodResult<EncodableValue>>(
        std::move(result));

    std::thread([=, shared_result = std::move(shared_result)]() mutable {
#if defined(__x86_64__) || defined(_M_X64)
        static bool once = (fprintf(stderr, "[ALTCHA native] solver: x86-64 SHA-NI %s\n",
            shani_detect() ? "hardware" : "scalar fallback"), fflush(stderr), true);
        (void)once;
#else
        static bool once = (fprintf(stderr, "[ALTCHA native] solver: scalar fallback\n"),
            fflush(stderr), true);
        (void)once;
#endif
        std::vector<uint8_t> out_key(key_length, 0);
        const auto t0 = std::chrono::steady_clock::now();
        int counter = altcha_pbkdf2_solve(
            nonce.data(),        (int)nonce.size(),
            salt.data(),         (int)salt.size(),
            cost, key_length, hash_id,
            prefix_bytes.empty() ? nullptr : prefix_bytes.data(),
            (int)prefix_bytes.size(),
            concurrency, timeout,
            out_key.data());
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        fprintf(stderr, "[ALTCHA native] solve: counter=%d time=%lldms workers=%d\n",
                counter, (long long)ms, concurrency);
        fflush(stderr);

        if (counter >= 0) {
            EncodableMap response_map;
            response_map[EncodableValue("counter")]    = EncodableValue(counter);
            response_map[EncodableValue("derivedKey")] = EncodableValue(out_key);
            shared_result->Success(EncodableValue(response_map));
        } else {
            // Timeout — Dart side treats null as "not found".
            shared_result->Success(EncodableValue());
        }
    }).detach();
}

// ---------------------------------------------------------------------------
// C entry point called by Flutter's generated plugin registrar
// ---------------------------------------------------------------------------

void AltchaWidgetPluginRegisterWithRegistrar(
    FlutterDesktopPluginRegistrarRef registrar) {
    AltchaWidgetPlugin::RegisterWithRegistrar(
        flutter::PluginRegistrarManager::GetInstance()
            ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
