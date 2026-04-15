// altcha_widget_plugin.cc — Flutter Linux plugin for ALTCHA PBKDF2 solver.

#include "include/altcha_widget/altcha_widget_plugin.h"

#include <flutter_linux/flutter_linux.h>
#include <gtk/gtk.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "altcha_pbkdf2_solver.h"

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

static std::vector<uint8_t> hex_to_bytes(const char* hex) {
    size_t len = strlen(hex);
    std::vector<uint8_t> out(len / 2, 0);
    for (size_t i = 0; i < len / 2; i++) {
        char buf[3] = {hex[i * 2], hex[i * 2 + 1], '\0'};
        out[i] = (uint8_t)strtol(buf, nullptr, 16);
    }
    return out;
}

// ---------------------------------------------------------------------------
// GObject plugin type
// ---------------------------------------------------------------------------

G_DECLARE_FINAL_TYPE(AltchaWidgetPlugin, altcha_widget_plugin,
                     ALTCHA_WIDGET, PLUGIN, GObject)

struct _AltchaWidgetPlugin {
    GObject parent_instance;
};

G_DEFINE_TYPE(AltchaWidgetPlugin, altcha_widget_plugin, G_TYPE_OBJECT)

// ---------------------------------------------------------------------------
// Async solve — keeps FlMethodCall alive across thread boundary.
// We use g_idle_add to deliver the response on the GLib main loop,
// which is required so that the GLib/GObject machinery stays on one thread.
// ---------------------------------------------------------------------------

struct SolveResult {
    FlMethodCall* method_call;  // owned ref
    int           counter;
    std::vector<uint8_t> key;
};

static gboolean deliver_result(gpointer user_data) {
    auto* res = static_cast<SolveResult*>(user_data);

    g_autoptr(GError) error = nullptr;
    if (res->counter >= 0) {
        g_autoptr(FlValue) map = fl_value_new_map();
        fl_value_set_string_take(
            map, "counter",
            fl_value_new_int(res->counter));
        fl_value_set_string_take(
            map, "derivedKey",
            fl_value_new_uint8_list(res->key.data(),
                                    static_cast<int64_t>(res->key.size())));
        g_autoptr(FlMethodSuccessResponse) response =
            fl_method_success_response_new(map);
        fl_method_call_respond(res->method_call,
                               FL_METHOD_RESPONSE(response), &error);
    } else {
        // Timeout — return null (Dart side treats null as "not found").
        g_autoptr(FlMethodSuccessResponse) response =
            fl_method_success_response_new(fl_value_new_null());
        fl_method_call_respond(res->method_call,
                               FL_METHOD_RESPONSE(response), &error);
    }

    g_object_unref(res->method_call);
    delete res;
    return G_SOURCE_REMOVE;
}

static void handle_solve(FlMethodCall* method_call) {
#if defined(__aarch64__) && defined(__GNUC__)
    static bool once = (fprintf(stderr, "[ALTCHA native] solver: ARM SHA-2 %s\n",
        arm_sha2_detect() ? "hardware (getauxval)" : "scalar fallback"), true);
    (void)once;
#elif defined(__x86_64__) || defined(_M_X64)
    static bool once = (fprintf(stderr, "[ALTCHA native] solver: x86-64 SHA-NI %s\n",
        shani_detect() ? "hardware" : "scalar fallback"), true);
    (void)once;
#else
    static bool once = (fprintf(stderr, "[ALTCHA native] solver: scalar fallback\n"), true);
    (void)once;
#endif
    FlValue* args = fl_method_call_get_args(method_call);
    if (fl_value_get_type(args) != FL_VALUE_TYPE_MAP) {
        g_autoptr(FlMethodErrorResponse) err =
            fl_method_error_response_new("BAD_ARGS", "Expected map", nullptr);
        GError* error = nullptr;
        fl_method_call_respond(method_call, FL_METHOD_RESPONSE(err), &error);
        return;
    }

    // Extract byte-array args.
    FlValue* v_nonce  = fl_value_lookup_string(args, "nonce");
    FlValue* v_salt   = fl_value_lookup_string(args, "salt");
    FlValue* v_prefix = fl_value_lookup_string(args, "keyPrefix");  // may be null

    const uint8_t* nonce_data  = fl_value_get_uint8_list(v_nonce);
    int             nonce_len  = (int)fl_value_get_length(v_nonce);
    const uint8_t* salt_data   = fl_value_get_uint8_list(v_salt);
    int             salt_len   = (int)fl_value_get_length(v_salt);

    int cost        = (int)fl_value_get_int(fl_value_lookup_string(args, "cost"));
    int key_length  = (int)fl_value_get_int(fl_value_lookup_string(args, "keyLength"));
    int concurrency = (int)fl_value_get_int(fl_value_lookup_string(args, "concurrency"));
    int64_t timeout = fl_value_get_int(fl_value_lookup_string(args, "timeoutMs"));

    const char* hash_str = fl_value_get_string(fl_value_lookup_string(args, "hash"));
    int hash_id = 256;
    if (hash_str != nullptr) {
        std::string hash(hash_str);
        if (hash.find("512") != std::string::npos)      hash_id = 512;
        else if (hash.find("384") != std::string::npos) hash_id = 384;
    }

    // Decode hex prefix (keyPrefix is an optional string like "00ab…").
    std::vector<uint8_t> prefix_bytes;
    if (v_prefix != nullptr && fl_value_get_type(v_prefix) == FL_VALUE_TYPE_STRING) {
        const char* px = fl_value_get_string(v_prefix);
        if (px && strlen(px) > 0) prefix_bytes = hex_to_bytes(px);
    }

    // Copy everything onto the heap so the thread can safely outlive this call.
    std::vector<uint8_t> nonce_copy(nonce_data, nonce_data + nonce_len);
    std::vector<uint8_t> salt_copy(salt_data,   salt_data  + salt_len);

    g_object_ref(method_call);

    std::thread([=, nc = std::move(nonce_copy),
                    sc = std::move(salt_copy),
                    pb = std::move(prefix_bytes)]() mutable {
        std::vector<uint8_t> out_key(key_length, 0);
        const auto t0 = std::chrono::steady_clock::now();
        int counter = altcha_pbkdf2_solve(
            nc.data(), (int)nc.size(),
            sc.data(), (int)sc.size(),
            cost, key_length, hash_id,
            pb.empty() ? nullptr : pb.data(), (int)pb.size(),
            concurrency, timeout,
            out_key.data());
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        fprintf(stderr, "[ALTCHA native] solve: counter=%d time=%ldms workers=%d\n",
                counter, (long)ms, concurrency);

        auto* res        = new SolveResult{};
        res->method_call = method_call;
        res->counter     = counter;
        res->key         = std::move(out_key);

        // Post back to the GLib main loop so respond is called on the UI thread.
        g_idle_add(deliver_result, res);
    }).detach();
}

// ---------------------------------------------------------------------------
// Method call handler
// ---------------------------------------------------------------------------

static void method_call_cb(FlMethodChannel* /*channel*/,
                            FlMethodCall*    method_call,
                            gpointer         /*user_data*/) {
    const gchar* method = fl_method_call_get_name(method_call);
    if (strcmp(method, "solve") == 0) {
        handle_solve(method_call);
    } else {
        fl_method_call_respond_not_implemented(method_call, nullptr);
    }
}

// ---------------------------------------------------------------------------
// GObject boilerplate
// ---------------------------------------------------------------------------

static void altcha_widget_plugin_dispose(GObject* object) {
    G_OBJECT_CLASS(altcha_widget_plugin_parent_class)->dispose(object);
}

static void altcha_widget_plugin_class_init(AltchaWidgetPluginClass* klass) {
    G_OBJECT_CLASS(klass)->dispose = altcha_widget_plugin_dispose;
}

static void altcha_widget_plugin_init(AltchaWidgetPlugin* /*self*/) {}

// ---------------------------------------------------------------------------
// Public registrar entry point
// ---------------------------------------------------------------------------

void altcha_widget_plugin_register_with_registrar(FlPluginRegistrar* registrar) {
    AltchaWidgetPlugin* plugin = ALTCHA_WIDGET_PLUGIN(
        g_object_new(altcha_widget_plugin_get_type(), nullptr));

    g_autoptr(FlStandardMethodCodec) codec = fl_standard_method_codec_new();
    g_autoptr(FlMethodChannel) channel = fl_method_channel_new(
        fl_plugin_registrar_get_messenger(registrar),
        "altcha_widget/pbkdf2",
        FL_METHOD_CODEC(codec));
    fl_method_channel_set_method_call_handler(
        channel, method_call_cb, g_object_ref(plugin), g_object_unref);

    g_object_unref(plugin);
}
