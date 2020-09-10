package ru.niisokb.grabcertificate

import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket

object CertificateExtractor {

    fun fromHttpsConnection(connection: HttpsURLConnection): String =
        connection.serverCertificates.toPemString()

    fun fromSslSocket(sslSocket: SSLSocket): String =
        sslSocket.session.peerCertificates.toPemString()
}