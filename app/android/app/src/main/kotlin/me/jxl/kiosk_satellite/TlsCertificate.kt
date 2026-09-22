package me.jxl.kiosk_satellite

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.text.SimpleDateFormat
import java.util.Calendar
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * The kiosk's TLS identity, shared by the remote admin (HTTPS) and the
 * camera stream (RTSPS): a self-signed certificate made here without a
 * certificate library, since the X.509 structure it needs is small enough
 * to write out by hand, and the SSLContext the pair loads into.
 *
 * EC P-256 keys: a signature costs about a millisecond on the slowest
 * kiosk, and every client this app meets (browsers, ffmpeg, go2rtc, Home
 * Assistant) takes ECDSA certificates. Base64 comes from the caller, as in
 * the ONVIF service: java.util.Base64 is API 26 and this also runs under
 * plain JVM tests.
 */
object TlsCertificate {
    class Pem(val certificate: String, val privateKey: String)

    private const val PASSWORD = "kiosk"

    /**
     * A fresh key pair and a self-signed certificate for [hostnames] (the
     * first is the subject) and [addresses], valid for [days] from [now].
     */
    fun generate(
        hostnames: List<String>,
        addresses: List<InetAddress>,
        days: Int,
        encode: (ByteArray) -> String,
        now: Long = System.currentTimeMillis(),
    ): Pem {
        require(hostnames.isNotEmpty()) { "A hostname is required." }
        val keys = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        val algorithm = seq(oid("1.2.840.10045.4.3.2")) // ecdsa-with-SHA256
        val name = seq(tlv(0x31, seq(oid("2.5.4.3"), tlv(0x0c, hostnames.first().toByteArray()))))
        val names = hostnames.map { tlv(0x82, it.toByteArray(Charsets.US_ASCII)) } + addresses.map { tlv(0x87, it.address) }
        val extensions = seq(
            extension("2.5.29.19", seq(), critical = true), // basicConstraints: not a CA
            extension("2.5.29.15", tlv(0x03, byteArrayOf(7, 0x80.toByte())), critical = true), // keyUsage: digitalSignature
            extension("2.5.29.37", seq(oid("1.3.6.1.5.5.7.3.1"))), // extKeyUsage: serverAuth
            extension("2.5.29.17", seq(*names.toTypedArray())), // subjectAltName
        )
        val tbs = seq(
            tlv(0xa0, tlv(0x02, byteArrayOf(2))), // v3
            tlv(0x02, BigInteger(127, SecureRandom()).toByteArray()),
            algorithm,
            name,
            seq(time(now), time(now + days * 86_400_000L)),
            name,
            keys.public.encoded,
            tlv(0xa3, extensions),
        )
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(keys.private); update(tbs) }.sign()
        val certificate = seq(tbs, algorithm, tlv(0x03, byteArrayOf(0) + signature))
        return Pem(pem("CERTIFICATE", certificate, encode), pem("PRIVATE KEY", keys.private.encoded, encode))
    }

    /** The SSLContext for a pair [generate] made. */
    fun sslContext(certificatePem: String, privateKeyPem: String, decode: (String) -> ByteArray): SSLContext {
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(certificatePem.byteInputStream()) as X509Certificate
        val store = KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry("kiosk", privateKey(privateKeyPem, decode), PASSWORD.toCharArray(), arrayOf(certificate))
        }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, PASSWORD.toCharArray()) }
        return SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
    }

    private fun privateKey(pem: String, decode: (String) -> ByteArray): PrivateKey {
        val body = pem.replace(Regex("-----[A-Z ]+-----|\\s"), "")
        return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(decode(body)))
    }

    // DER, just the handful of encodings a certificate takes.

    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(content.size + 4)
        out.write(tag)
        val n = content.size
        when {
            n < 0x80 -> out.write(n)
            n < 0x100 -> { out.write(0x81); out.write(n) }
            else -> { out.write(0x82); out.write(n shr 8); out.write(n and 0xff) }
        }
        out.write(content)
        return out.toByteArray()
    }

    private fun seq(vararg parts: ByteArray) = tlv(0x30, parts.fold(ByteArray(0), ByteArray::plus))

    private fun extension(id: String, value: ByteArray, critical: Boolean = false) =
        seq(oid(id), *(if (critical) arrayOf(tlv(0x01, byteArrayOf(0xff.toByte()))) else emptyArray()), tlv(0x04, value))

    private fun oid(text: String): ByteArray {
        val arcs = text.split('.').map { it.toLong() }
        val out = ByteArrayOutputStream()
        for (arc in listOf(arcs[0] * 40 + arcs[1]) + arcs.drop(2)) {
            val groups = generateSequence(arc) { it shr 7 }.takeWhile { it > 0 }.map { (it and 0x7f).toInt() }.toList().ifEmpty { listOf(0) }
            for (i in groups.indices.reversed()) out.write(groups[i] or if (i == 0) 0 else 0x80)
        }
        return tlv(0x06, out.toByteArray())
    }

    private fun time(millis: Long): ByteArray {
        val utc = TimeZone.getTimeZone("UTC")
        val generalized = Calendar.getInstance(utc).apply { timeInMillis = millis }.get(Calendar.YEAR) >= 2050
        val format = SimpleDateFormat(if (generalized) "yyyyMMddHHmmss'Z'" else "yyMMddHHmmss'Z'", Locale.US).apply { timeZone = utc }
        return tlv(if (generalized) 0x18 else 0x17, format.format(Date(millis)).toByteArray(Charsets.US_ASCII))
    }

    private fun pem(label: String, der: ByteArray, encode: (ByteArray) -> String) =
        "-----BEGIN $label-----\n" + encode(der).chunked(64).joinToString("\n") + "\n-----END $label-----\n"
}
