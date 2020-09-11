package ru.niisokb.grabcertificate

import java.security.cert.Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket

object CertificateExtractor {

    fun fromHttpsConnection(connection: HttpsURLConnection): Array<Certificate> =
        connection.serverCertificates

    fun fromSslSocket(sslSocket: SSLSocket): Array<Certificate> =
        sslSocket.session.peerCertificates
}