package ru.niisokb.grabcertificate

import android.os.Build
import androidx.annotation.RequiresApi
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMWriter
import java.io.InputStream
import java.io.StringWriter
import java.net.URL
import java.security.KeyStore
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.*

fun createHttpsConnection(sslContext: SSLContext, serverUrl: URL): HttpsURLConnection {
    return (serverUrl.openConnection() as HttpsURLConnection).apply {
        hostnameVerifier = HostnameVerifier { _, _ -> true }
        sslSocketFactory = sslContext.socketFactory
    }
}

fun createSslSocket(sslContext: SSLContext, serverUrl: URL): SSLSocket =
    sslContext.socketFactory.createSocket(serverUrl.host, serverUrl.port) as SSLSocket

fun createSslContext(): SSLContext {
    return SSLContext.getInstance("SSL").apply {
        init(null, arrayOf(EmptyX509TrustManager()), null)
    }
}

fun createSslContext(keyStore: KeyStore, password: String): SSLContext {
    val algorithm = KeyManagerFactory.getDefaultAlgorithm()
    val kmf = KeyManagerFactory.getInstance(algorithm)
    kmf.init(keyStore, password.toCharArray())

    val tmf = TrustManagerFactory.getInstance(algorithm)
    tmf.init(keyStore)

    return SSLContext.getInstance("SSL").apply {
        init(kmf.keyManagers, tmf.trustManagers, null)
    }
}

fun createBksKeyStore(password: String): KeyStore {
    val keyStore = KeyStore.getInstance("BKS", BouncyCastleProvider.PROVIDER_NAME)
    keyStore.load(null, password.toCharArray())
    return keyStore
}

fun loadBksKeyStore(keyStorePath: String, password: String): KeyStore {
    val keyStore = KeyStore.getInstance("BKS", BouncyCastleProvider.PROVIDER_NAME)
    getResourceStream(keyStorePath).use { stream ->
        keyStore.load(stream, password.toCharArray())
    }
    return keyStore
}

fun loadCertificate(certificatePath: String): String {
    return getResourceStream(certificatePath).use { stream ->
        String(stream.readBytes()).replace("\r", "")
    }
}

fun getResourceStream(path: String): InputStream {
    val classLoader = Thread.currentThread().contextClassLoader!!
    return classLoader.getResourceAsStream(path)
}

fun Array<Certificate>.toPemString(): String =
    joinToString("") { (it as X509Certificate).toPemString() }

/** Requires BouncyCastle */
fun X509Certificate.toPemString(): String {
    val stringWriter = StringWriter()
    PEMWriter(stringWriter).use { it.writeObject(this) }
    return stringWriter.toString().replace("\r", "")
}

/** Requires API 26 */
@RequiresApi(Build.VERSION_CODES.O)
fun X509Certificate.toPemString2(): String {
    val begin = "-----BEGIN CERTIFICATE-----"
    val end = "-----END CERTIFICATE-----"
    val ls = "\n"
    val encoder = Base64.getMimeEncoder(64, ls.toByteArray())
    return begin + ls + String(encoder.encode(encoded)) + ls + end + ls
}
