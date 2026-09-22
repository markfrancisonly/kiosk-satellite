package me.jxl.kiosk_satellite

import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLSocket

class TlsCertificateTest {
    private val encode = { bytes: ByteArray -> Base64.getEncoder().encodeToString(bytes) }
    private val decode = { text: String -> Base64.getDecoder().decode(text) }

    private fun parse(pem: String) =
        CertificateFactory.getInstance("X.509").generateCertificate(pem.byteInputStream()) as X509Certificate

    @Test fun selfSignedCertificateNamesTheKioskAndVerifiesWithItsOwnKey() {
        val now = System.currentTimeMillis()
        val pem = TlsCertificate.generate(
            listOf("ks-kitchen.local", "ks-kitchen"), listOf(InetAddress.getByName("192.168.1.5")), 825, encode, now,
        )
        val certificate = parse(pem.certificate)
        certificate.verify(certificate.publicKey)
        certificate.checkValidity()
        assertEquals(3, certificate.version)
        assertEquals("CN=ks-kitchen.local", certificate.subjectX500Principal.name)
        assertEquals(certificate.subjectX500Principal, certificate.issuerX500Principal)
        assertEquals(
            listOf(listOf(2, "ks-kitchen.local"), listOf(2, "ks-kitchen"), listOf(7, "192.168.1.5")),
            certificate.subjectAlternativeNames.map { it.toList() },
        )
        assertTrue(certificate.keyUsage[0])
        assertEquals(listOf("1.3.6.1.5.5.7.3.1"), certificate.extendedKeyUsage)
        assertEquals(-1, certificate.basicConstraints)
        assertEquals(now / 1000 + 825L * 86_400, certificate.notAfter.time / 1000)
        assertEquals("EC", certificate.publicKey.algorithm)
        assertTrue(pem.certificate.startsWith("-----BEGIN CERTIFICATE-----\n"))
        assertTrue(pem.privateKey.startsWith("-----BEGIN PRIVATE KEY-----\n"))
        assertTrue(pem.certificate.lines().all { it.length <= 64 })
    }

    @Test fun thePemPairServesATlsHandshake() = withJdkTls {
        val pem = TlsCertificate.generate(listOf("localhost"), listOf(InetAddress.getByName("127.0.0.1")), 10, encode)
        val server = TlsCertificate.sslContext(pem.certificate, pem.privateKey, decode).serverSocketFactory.createServerSocket(0)
        val client = trustAllContext().socketFactory.createSocket("127.0.0.1", server.localPort) as SSLSocket
        val accepted = server.accept() as SSLSocket
        val serverSide = CompletableFuture.runAsync { accepted.startHandshake() }
        client.startHandshake()
        serverSide.get(5, TimeUnit.SECONDS)
        assertEquals(parse(pem.certificate), client.session.peerCertificates.single())
        client.close(); accepted.close(); server.close()
    }
}
