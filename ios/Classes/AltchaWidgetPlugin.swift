import Flutter
import Darwin

public class AltchaWidgetPlugin: NSObject, FlutterPlugin {
    // Logged once per process on first solve call.
    private static let _detectOnce: Void = {
        #if arch(arm64)
        fputs("[ALTCHA native] solver: ARM SHA-2 hardware\n", stderr)
        #else
        fputs("[ALTCHA native] solver: scalar fallback\n", stderr)
        #endif
    }()
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(
            name: "altcha_widget/pbkdf2",
            binaryMessenger: registrar.messenger()
        )
        registrar.addMethodCallDelegate(AltchaWidgetPlugin(), channel: channel)
    }

    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard call.method == "solve" else {
            result(FlutterMethodNotImplemented)
            return
        }
        guard
            let args        = call.arguments as? [String: Any],
            let nonceTyped  = args["nonce"]       as? FlutterStandardTypedData,
            let saltTyped   = args["salt"]        as? FlutterStandardTypedData,
            let cost        = args["cost"]        as? Int,
            let keyLength   = args["keyLength"]   as? Int,
            let keyPrefix   = args["keyPrefix"]   as? String,
            let hash        = args["hash"]        as? String,
            let concurrency = args["concurrency"] as? Int,
            let timeoutMs   = args["timeoutMs"]   as? Int
        else {
            result(FlutterError(code: "INVALID_ARGS", message: "Missing or invalid arguments", details: nil))
            return
        }

        let hashId: Int32
        switch hash {
        case "SHA-512": hashId = 512
        case "SHA-384": hashId = 384
        default:        hashId = 256
        }

        let nonceData  = nonceTyped.data
        let saltData   = saltTyped.data
        let prefixData = keyPrefix.count % 2 == 0 ? hexToData(keyPrefix) : nil

        _ = AltchaWidgetPlugin._detectOnce
        DispatchQueue.global(qos: .userInteractive).async {
            let outKey = NSMutableData(length: keyLength)!
            let t0 = DispatchTime.now()
            let counter = AltchaPbkdf2Bridge.solve(
                withNonce:   nonceData,
                salt:        saltData,
                cost:        Int32(cost),
                keyLength:   Int32(keyLength),
                hashId:      hashId,
                prefix:      prefixData,
                workerCount: Int32(concurrency),
                timeoutMs:   Int64(timeoutMs),
                outKey:      outKey
            )
            let ms = (DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1_000_000
            fputs("[ALTCHA native] solve: counter=\(counter) time=\(ms)ms workers=\(concurrency)\n", stderr)
            DispatchQueue.main.async {
                if counter >= 0 {
                    result(["counter": Int(counter),
                            "derivedKey": FlutterStandardTypedData(bytes: outKey as Data)])
                } else {
                    result(nil)
                }
            }
        }
    }

    private func hexToData(_ hex: String) -> Data? {
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var idx  = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx ..< next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        return data
    }
}
