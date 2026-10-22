package dev.cipher.ciphernative

import android.app.Activity
import android.content.pm.ApplicationInfo
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.view.WindowManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import org.json.JSONObject
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * Owns the Android Keystore identity and the secure-window flags.
 *
 * The private key is generated with PURPOSE_SIGN and is never exported: only
 * its public certificate and signatures leave this class.  RSA PKCS#1 v1.5 is
 * used because it is deterministic, which lets Python derive the same master
 * KEK on every launch without storing key material.
 */
class CipherNativePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private var activity: Activity? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, CHANNEL)
        channel.setMethodCallHandler(this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        activity = binding.activity
        applySecure(binding.activity, true)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        activity = null
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        activity = binding.activity
        applySecure(binding.activity, true)
    }

    override fun onDetachedFromActivity() {
        activity = null
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "status" -> result.success(statusJson().toString())
                "ensureIdentity" -> result.success(ensureIdentityJson().toString())
                "sign" -> {
                    val data = call.argument<String>("data") ?: ""
                    val bytes = Base64.decode(data, Base64.NO_WRAP)
                    result.success(signJson(bytes).toString())
                }
                "setSecure" -> {
                    val enabled = call.argument<String>("enabled")?.toBoolean() ?: true
                    // Release builds cannot turn screen protection off; only a
                    // debuggable build may clear the flag for local inspection.
                    val effective = enabled || !isDebuggable()
                    applySecure(activity, effective)
                    result.success(
                        JSONObject()
                            .put("available", true)
                            .put("ok", true)
                            .put("secure", isSecure())
                            .toString()
                    )
                }
                "destroyIdentity" -> {
                    destroyIdentity()
                    result.success(
                        JSONObject()
                            .put("available", true)
                            .put("ok", true)
                            .put("destroyed", true)
                            .toString()
                    )
                }
                else -> result.notImplemented()
            }
        } catch (error: Exception) {
            result.error("cipher_native_error", null, null)
        }
    }

    // ---- identity -------------------------------------------------------

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    @Synchronized
    private fun ensureKey(): PrivateKey {
        val store = keyStore()
        val existing = store.getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
        if (existing != null) {
            return existing.privateKey
        }

        var strongBox = false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateKey(strongBox = true)
                strongBox = true
            } catch (_: Exception) {
                // StrongBox may be absent or busy; delete any partial entry.
                try {
                    store.deleteEntry(ALIAS)
                } catch (_: Exception) {
                }
            }
        }
        if (!strongBox) {
            generateKey(strongBox = false)
        }

        val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("keystore did not return an identity key")
        return entry.privateKey
    }

    private fun generateKey(strongBox: Boolean) {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA,
            ANDROID_KEYSTORE,
        )
        val builder = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setKeySize(2048)
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            .setUserAuthenticationRequired(false)
        if (strongBox) {
            builder.setIsStrongBoxBacked(true)
        }
        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun ensureIdentityJson(): JSONObject {
        val privateKey = ensureKey()
        val certificate = keyStore().getCertificate(ALIAS)
            ?: throw IllegalStateException("keystore certificate is missing")
        val publicDer = certificate.publicKey.encoded
        val (hardware, strongBox) = keySecurity(privateKey)
        return JSONObject()
            .put("available", true)
            .put("ok", true)
            .put("publicKey", Base64.encodeToString(publicDer, Base64.NO_WRAP))
            .put("hardware", hardware)
            .put("strongbox", strongBox)
            .put("api", 1)
    }

    private fun signJson(data: ByteArray): JSONObject {
        val privateKey = ensureKey()
        val signer = try {
            Signature.getInstance("SHA256withRSA/PKCS1Padding")
        } catch (_: Exception) {
            Signature.getInstance("SHA256withRSA")
        }
        signer.initSign(privateKey)
        signer.update(data)
        val signature = signer.sign()
        return JSONObject()
            .put("available", true)
            .put("ok", true)
            .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
    }

    private fun keySecurity(privateKey: PrivateKey): Pair<Boolean, Boolean> {
        return try {
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val info = factory.getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val level = info.securityLevel
                Pair(
                    level != KeyProperties.SECURITY_LEVEL_SOFTWARE,
                    level == KeyProperties.SECURITY_LEVEL_STRONGBOX,
                )
            } else {
                @Suppress("DEPRECATION")
                Pair(info.isInsideSecureHardware, false)
            }
        } catch (_: Exception) {
            Pair(false, false)
        }
    }

    private fun destroyIdentity() {
        try {
            keyStore().deleteEntry(ALIAS)
        } catch (_: Exception) {
            // Nothing to delete.
        }
    }

    private fun statusJson(): JSONObject {
        val hasIdentity = try {
            keyStore().containsAlias(ALIAS)
        } catch (_: Exception) {
            false
        }
        var hardware = false
        var strongBox = false
        if (hasIdentity) {
            try {
                val entry = keyStore().getEntry(ALIAS, null) as? KeyStore.PrivateKeyEntry
                if (entry != null) {
                    val security = keySecurity(entry.privateKey)
                    hardware = security.first
                    strongBox = security.second
                }
            } catch (_: Exception) {
            }
        }
        return JSONObject()
            .put("available", true)
            .put("ok", true)
            .put("api", 1)
            .put("sdk", Build.VERSION.SDK_INT)
            .put("hardware", hardware)
            .put("strongbox", strongBox)
            .put("identity", hasIdentity)
            .put("secure", isSecure())
    }

    // ---- window protection ---------------------------------------------

    private fun applySecure(target: Activity?, enabled: Boolean) {
        if (target == null) return
        target.runOnUiThread {
            val window = target.window
            if (enabled) {
                window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    target.setRecentsScreenshotEnabled(false)
                }
                window.decorView.setFilterTouchesWhenObscured(true)
            } else {
                window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    target.setRecentsScreenshotEnabled(true)
                }
                window.decorView.setFilterTouchesWhenObscured(false)
            }
        }
    }

    private fun isSecure(): Boolean {
        val target = activity ?: return false
        return (target.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
    }

    private fun isDebuggable(): Boolean {
        val target = activity ?: return false
        return (target.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    companion object {
        private const val CHANNEL = "dev.cipher/native"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val ALIAS = "cipher.identity.v1"
    }
}
