package org.altcha.altcha_widget

import android.os.Handler
import android.os.Looper
import android.os.Process
import android.util.Log
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class AltchaWidgetPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var channel: MethodChannel

    companion object {
        private const val TAG = "AltchaWidget"

        // true if the native library loaded successfully
        private val nativeAvailable: Boolean = try {
            System.loadLibrary("altcha_pbkdf2")
            Log.d(TAG, "native library loaded")
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "native library not available: ${e.message}")
            false
        }
    }

    // Declared as external so the JVM knows to look in the native library.
    // hashId: 256 or 512
    private external fun nativePbkdf2(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int,
        hashId: Int,
    ): ByteArray

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "altcha_widget/pbkdf2")
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onMethodCall(call: MethodCall, result: Result) {
        when (call.method) {
            "solve" -> solve(call, result)
            else    -> result.notImplemented()
        }
    }

    private fun solve(call: MethodCall, result: Result) {
        val nonce       = call.argument<ByteArray>("nonce")!!
        val salt        = call.argument<ByteArray>("salt")!!
        val cost        = call.argument<Int>("cost")!!
        val keyLength   = call.argument<Int>("keyLength")!!
        val keyPrefix   = call.argument<String>("keyPrefix")!!
        val hash        = call.argument<String>("hash")!!
        val concurrency = call.argument<Int>("concurrency") ?: 2
        val timeoutMs   = (call.argument<Int>("timeoutMs") ?: 90000).toLong()

        val workerCount = concurrency.coerceIn(1, 16)
        val hashId      = if (hash.contains("512")) 512 else 256
        Log.d(TAG, "solve: hash=$hash hashId=$hashId cost=$cost keyLength=$keyLength workers=$workerCount native=$nativeAvailable")

        val prefixBytes: ByteArray? = if (keyPrefix.length % 2 == 0) hexToBytes(keyPrefix) else null

        val executor      = Executors.newFixedThreadPool(workerCount)
        val latch         = CountDownLatch(workerCount)
        val found         = AtomicBoolean(false)
        val resultCounter = AtomicInteger(-1)
        val resultKey     = AtomicReference<ByteArray?>(null)
        val deadline      = System.currentTimeMillis() + timeoutMs

        for (workerIdx in 0 until workerCount) {
            executor.submit {
                Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_DISPLAY)
                try {
                    val password = ByteArray(nonce.size + 4)
                    nonce.copyInto(password)

                    var counter = workerIdx
                    while (!found.get() && System.currentTimeMillis() < deadline) {
                        password[nonce.size]     = (counter ushr 24).toByte()
                        password[nonce.size + 1] = (counter ushr 16).toByte()
                        password[nonce.size + 2] = (counter ushr 8).toByte()
                        password[nonce.size + 3] = counter.toByte()

                        val derivedKey = pbkdf2(password, salt, cost, keyLength, hashId)

                        val matches = if (prefixBytes != null) {
                            prefixMatch(derivedKey, prefixBytes)
                        } else {
                            derivedKey.joinToString("") { "%02x".format(it) }.startsWith(keyPrefix)
                        }

                        if (matches) {
                            if (found.compareAndSet(false, true)) {
                                resultCounter.set(counter)
                                resultKey.set(derivedKey)
                            }
                            break
                        }
                        counter += workerCount
                    }
                } catch (_: Exception) {
                } finally {
                    latch.countDown()
                }
            }
        }

        Thread {
            latch.await(timeoutMs + 5_000L, TimeUnit.MILLISECONDS)
            executor.shutdownNow()
            val c = resultCounter.get()
            val k = resultKey.get()
            Handler(Looper.getMainLooper()).post {
                if (c >= 0 && k != null) {
                    result.success(mapOf("counter" to c, "derivedKey" to k))
                } else {
                    result.success(null)
                }
            }
        }.start()
    }

    private fun pbkdf2(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        keyLength: Int,
        hashId: Int,
    ): ByteArray {
        // --- Tier 1: native C++ (single JNI call, no per-iteration overhead) ---
        if (nativeAvailable) {
            return nativePbkdf2(password, salt, iterations, keyLength, hashId)
        }

        // --- Tier 2: manual Mac-based PBKDF2 (correct, but slower due to JNI per iteration) ---
        Log.d(TAG, "pbkdf2: using manual Mac fallback")
        val macAlgorithm = if (hashId == 512) "HmacSHA512" else "HmacSHA256"
        val mac = Mac.getInstance(macAlgorithm)
        mac.init(SecretKeySpec(password, macAlgorithm))

        val digestLength = mac.macLength
        val numBlocks    = (keyLength + digestLength - 1) / digestLength
        val output       = ByteArray(keyLength)
        val u            = ByteArray(digestLength)
        val f            = ByteArray(digestLength)
        val saltBlock    = ByteArray(salt.size + 4)
        salt.copyInto(saltBlock)

        for (blockNum in 1..numBlocks) {
            saltBlock[salt.size]     = (blockNum shr 24).toByte()
            saltBlock[salt.size + 1] = (blockNum shr 16).toByte()
            saltBlock[salt.size + 2] = (blockNum shr 8).toByte()
            saltBlock[salt.size + 3] = blockNum.toByte()

            mac.reset()
            mac.update(saltBlock)
            mac.doFinal(u, 0)
            u.copyInto(f)

            repeat(iterations - 1) {
                mac.reset()
                mac.update(u, 0, digestLength)
                mac.doFinal(u, 0)
                for (i in 0 until digestLength) f[i] = (f[i].toInt() xor u[i].toInt()).toByte()
            }

            val start  = (blockNum - 1) * digestLength
            val toCopy = minOf(digestLength, keyLength - start)
            f.copyInto(output, start, 0, toCopy)
        }

        return output
    }

    private fun prefixMatch(key: ByteArray, prefix: ByteArray): Boolean {
        if (key.size < prefix.size) return false
        for (i in prefix.indices) if (key[i] != prefix[i]) return false
        return true
    }

    private fun hexToBytes(hex: String): ByteArray =
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
}
