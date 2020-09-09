package ru.niisokb.grabcertificate

import org.bouncycastle.openssl.PEMWriter
import java.io.StringWriter
import java.net.URL
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext

object CertificateGrabber {

    fun grabCertificate(serverUrl: String): String {
        val connection = getTrustfulHttpsConnection(URL(serverUrl))
        connection.connect()
        val serverCertificates = connection.serverCertificates
        connection.disconnect()
        return serverCertificates.toPemString()
    }

    private fun getTrustfulHttpsConnection(serverUrl: URL): HttpsURLConnection {
        return (serverUrl.openConnection() as HttpsURLConnection).apply {
            hostnameVerifier = HostnameVerifier { _, _ -> true }
            sslSocketFactory = getTrustfulSslContext().socketFactory
        }
    }

    private fun getTrustfulSslContext(): SSLContext {
        return SSLContext.getInstance("SSL").apply {
            init(null, arrayOf(EmptyX509TrustManager()), null)
        }
    }

    private fun Array<Certificate>.toPemString(): String =
        joinToString("") { (it as X509Certificate).toPemString() }

    private fun X509Certificate.toPemString(): String {
        val stringWriter = StringWriter()
        PEMWriter(stringWriter).use { it.writeObject(this) }
        return stringWriter.toString().replace("\r", "")
    }
}