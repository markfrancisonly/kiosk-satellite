package me.jxl.kiosk_satellite

import android.util.Base64
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodChannel
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.Collections

/**
 * Flutter bridge for the device's TLS identity (core/tls_identity.dart).
 *
 * Methods:
 *  - generate {hostnames, days}: a self-signed certificate for those names
 *    and the addresses the device holds right now, as {certificate,
 *    privateKey} PEM text and its notAfter (epoch milliseconds).
 *
 * Runs off the main thread: a key pair takes a moment on a slow panel.
 */
class TlsBridge(messenger: BinaryMessenger) {
    private val worker = MethodWorker("ks-tls")

    init {
        MethodChannel(messenger, "kiosk_satellite/tls").setMethodCallHandler { call, result ->
            when (call.method) {
                "generate" -> worker.read(result) {
                    val now = System.currentTimeMillis()
                    val days = call.argument<Int>("days") ?: 825
                    val pem = TlsCertificate.generate(
                        call.argument<List<String>>("hostnames") ?: emptyList(),
                        addresses(),
                        days,
                        { Base64.encodeToString(it, Base64.NO_WRAP) },
                        now,
                    )
                    mapOf(
                        "certificate" to pem.certificate,
                        "privateKey" to pem.privateKey,
                        "notAfter" to now + days * 86_400_000L,
                    )
                }
                else -> result.notImplemented()
            }
        }
    }

    /** The addresses a browser may open the kiosk by: every routable one, IPv4 and IPv6. */
    private fun addresses(): List<InetAddress> = try {
        Collections.list(NetworkInterface.getNetworkInterfaces()).filter { it.isUp && !it.isLoopback }
            .flatMap { Collections.list(it.inetAddresses) }
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isAnyLocalAddress }
    } catch (_: Exception) {
        emptyList()
    }
}
