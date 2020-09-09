package ru.niisokb.grabcertificate

import com.google.common.truth.Truth.assertThat
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Test
import java.security.Security
import javax.net.ssl.SSLContext

class CertificateGrabberTest {
    private val sslContext: SSLContext
    private val serverCertificates: String

    init {
        Security.addProvider(BouncyCastleProvider())
        sslContext = getSecureSslContext("keystore.bks", "1qaz2wsx")
        serverCertificates = getCertificate("certificate.pem")
    }

    private lateinit var server: MockWebServer

    @Test
    fun test_ssl_connection() {
        server = MockWebServer().apply {
            useHttps(sslContext.socketFactory, false)
            start()
        }
        val serverUrl = server.url("/").toUrl()
        val connection = getTrustfulHttpsConnection(serverUrl)

        connection.connect()
        val result = connection.serverCertificates.toPemString()
        connection.disconnect()

        assertThat(result).isEqualTo(serverCertificates)
    }

    @Test
    fun grab_certificate_from_ssl_connection() {
        server = MockWebServer().apply {
            useHttps(sslContext.socketFactory, false)
            start()
        }
        val serverUrl = server.url("/").toUrl()

        val result = CertificateGrabber.grabCertificate(serverUrl.toString())
        assertThat(result).isEqualTo(serverCertificates)
    }

    @After
    fun after() {
        server.shutdown()
    }
}