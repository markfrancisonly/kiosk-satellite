package me.jxl.kiosk_satellite

import java.security.Security
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/** A client context that takes any server certificate, the way ffmpeg and go2rtc meet a kiosk. */
internal fun trustAllContext(): SSLContext = SSLContext.getInstance("TLS").apply {
    init(null, arrayOf(object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }), null)
}

/**
 * Runs [block] with the JDK's own TLS provider first. Robolectric installs
 * Conscrypt for its tests and the JVM keeps it for every class that follows,
 * and Conscrypt cannot handshake under the JDK's module rules without
 * `--add-opens`. Android itself runs on Conscrypt, where none of this applies.
 */
internal fun <T> withJdkTls(block: () -> T): T {
    val jsse = Security.getProvider("SunJSSE") ?: return block()
    val position = Security.getProviders().indexOf(jsse) + 1
    Security.removeProvider(jsse.name)
    Security.insertProviderAt(jsse, 1)
    try {
        return block()
    } finally {
        Security.removeProvider(jsse.name)
        Security.insertProviderAt(jsse, position)
    }
}
