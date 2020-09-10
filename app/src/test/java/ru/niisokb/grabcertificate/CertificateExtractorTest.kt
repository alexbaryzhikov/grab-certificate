package ru.niisokb.grabcertificate

import com.google.common.truth.Truth.assertThat
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.net.URL
import java.security.Security
import javax.net.ssl.SSLContext

class CertificateExtractorTest {
    private val serverSslContext: SSLContext
    private val serverCertificates: String

    init {
        Security.addProvider(BouncyCastleProvider())
        serverSslContext = getSecureSslContext("server.bks", "1qaz2wsx")
        serverCertificates = getCertificates("server_certs.pem")
    }

    private lateinit var server: MockWebServer
    private lateinit var serverUrl: URL

    @Before
    fun before() {
        server = MockWebServer().apply {
            useHttps(serverSslContext.socketFactory, false)
            start()
        }
        serverUrl = server.url("/").toUrl()
    }

    @Test
    fun test_https_connection() {
        val connection = getTrustfulHttpsConnection(serverUrl)

        connection.connect()
        val result = CertificateExtractor.fromHttpsConnection(connection)
        connection.disconnect()

        assertThat(result).isEqualTo(serverCertificates)
    }

    @Test
    fun test_ssl_socket() {
        val sslSocket = getTrustfulSslSocket(serverUrl.host, serverUrl.port)

        val result = CertificateExtractor.fromSslSocket(sslSocket)
        sslSocket.close()

        assertThat(result).isEqualTo(serverCertificates)
    }

    @After
    fun after() {
        server.shutdown()
    }
}