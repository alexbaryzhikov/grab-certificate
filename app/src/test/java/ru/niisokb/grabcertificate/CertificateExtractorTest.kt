package ru.niisokb.grabcertificate

import com.google.common.truth.Truth.assertThat
import okhttp3.mockwebserver.MockWebServer
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.*
import java.net.URL
import java.security.Security
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLHandshakeException

class CertificateExtractorTest {
    private val serverSslContext: SSLContext
    private val serverCertificates: String

    init {
        val keyStore = loadBksKeyStore(SERVER_KEYSTORE_PATH, SERVER_KEYSTORE_PASSWORD)
        serverSslContext = createSslContext(keyStore, SERVER_KEYSTORE_PASSWORD)
        serverCertificates = loadCertificate(SERVER_CERTS_PATH)
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
    fun test_grab_certs_from_https_connection() {
        val connection = createHttpsConnection(createSslContext(), serverUrl)
        connection.connect()
        val certs = CertificateExtractor.fromHttpsConnection(connection)
        connection.disconnect()

        assertThat(certs.toPemString()).isEqualTo(serverCertificates)
    }

    @Test
    fun test_grab_certs_from_ssl_socket() {
        val certs = createSslSocket(createSslContext(), serverUrl).use {
            CertificateExtractor.fromSslSocket(it)
        }

        assertThat(certs.toPemString()).isEqualTo(serverCertificates)
    }

    @Test(expected = SSLHandshakeException::class)
    fun test_secure_socket_no_trusted_certificates() {
        val keyStore = createBksKeyStore("password")
        val sslContext = createSslContext(keyStore, "password")

        createSslSocket(sslContext, serverUrl).use { it.startHandshake() }
    }

    @Test
    fun test_secure_socket_with_extracted_certificates() {
        val certs = createSslSocket(createSslContext(), serverUrl).use {
            CertificateExtractor.fromSslSocket(it)
        }
        val keyStore = createBksKeyStore("password").apply {
            certs.forEachIndexed { i, cert -> setCertificateEntry("cert_$i", cert) }
        }
        val sslContext = createSslContext(keyStore, "password")

        createSslSocket(sslContext, serverUrl).use { it.startHandshake() }
    }

    @Test
    fun test_pem_to_certificates_to_pem() {
        val certs = CertificateFactory.getInstance("X.509")
            .generateCertificates(getResourceStream(SERVER_CERTS_PATH))

        assertThat(certs.toTypedArray().toPemString()).isEqualTo(serverCertificates)
    }

    @Test
    fun test_secure_socket_with_extracted_saved_and_restored_certificates() {
        val certs = createSslSocket(createSslContext(), serverUrl)
            .use { CertificateExtractor.fromSslSocket(it) }
            .toPemString()
            .byteInputStream()
            .let { CertificateFactory.getInstance("X.509").generateCertificates(it) }
        val keyStore = createBksKeyStore("password").apply {
            certs.forEachIndexed { i, cert -> setCertificateEntry("cert_$i", cert) }
        }
        val sslContext = createSslContext(keyStore, "password")

        createSslSocket(sslContext, serverUrl).use { it.startHandshake() }
    }

    @After
    fun after() {
        server.shutdown()
    }

    companion object {
        private const val SERVER_KEYSTORE_PATH = "server.bks"
        private const val SERVER_KEYSTORE_PASSWORD = "1qaz2wsx"
        private const val SERVER_CERTS_PATH = "server_certs.pem"

        @BeforeClass
        @JvmStatic
        fun beforeClass() {
            Security.addProvider(BouncyCastleProvider())
        }

        @AfterClass
        @JvmStatic
        fun afterClass() {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        }
    }
}