package com.aethervpn.vpncore.transport

import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

class SniBypassSocketFactory(
    private val strategy: SniStrategy,
    private val splitPosition: Int = 40,
    private val splitDelayMs: Long = 10,
    private val customSni: String? = null,
    private val strictCert: Boolean = false,
    private val socketProtector: SocketProtector? = null,
    private val onCertificateCaptured: ((X509Certificate) -> Unit)? = null
) {

    private val trustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (chain != null && chain.isNotEmpty()) {
                onCertificateCaptured?.invoke(chain[0])
            }
            if (strictCert) {
                // If strict validation is requested, delegate to system default
                val defaultTm = getDefaultTrustManager()
                defaultTm.checkServerTrusted(chain, authType)
            }
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }

    private fun getDefaultTrustManager(): X509TrustManager {
        val tmf = javax.net.ssl.TrustManagerFactory.getInstance(
            javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm()
        )
        tmf.init(null as java.security.KeyStore?)
        return tmf.trustManagers.first { it is X509TrustManager } as X509TrustManager
    }

    fun createAndConnectSocket(
        host: String,
        ipAddress: InetAddress,
        port: Int,
        timeoutMs: Int = 10000
    ): SSLSocket {
        // Step 1: Create raw TCP socket and protect it
        val rawSocket = Socket()
        socketProtector?.protect(rawSocket)
        rawSocket.tcpNoDelay = true
        rawSocket.soTimeout = timeoutMs
        rawSocket.connect(InetSocketAddress(ipAddress, port), timeoutMs)

        // Step 2: Wrap socket stream if fragmentation strategy is enabled
        val wrappedSocket = when (strategy) {
            SniStrategy.TCP_FRAGMENTATION -> FragmentedTcpSocket(rawSocket, splitPosition, splitDelayMs)
            SniStrategy.TLS_RECORD_FRAGMENTATION -> TlsRecordFragmentedSocket(rawSocket, splitPosition)
            else -> rawSocket
        }

        // Step 3: Wrap with SSLSocket
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf<TrustManager>(trustManager), null)
        val sslSocketFactory: SSLSocketFactory = sslContext.socketFactory

        val sslSocket = when (strategy) {
            SniStrategy.DIRECT_IP_NO_SNI -> {
                // Connecting with IP address as host name disables SNI in Conscrypt/JSSE
                sslSocketFactory.createSocket(
                    wrappedSocket,
                    ipAddress.hostAddress,
                    port,
                    true
                ) as SSLSocket
            }
            SniStrategy.CUSTOM_SNI -> {
                val sock = sslSocketFactory.createSocket(
                    wrappedSocket,
                    ipAddress.hostAddress,
                    port,
                    true
                ) as SSLSocket
                val params = sock.sslParameters ?: SSLParameters()
                val sniHost = customSni?.takeIf { it.isNotBlank() } ?: host
                params.serverNames = listOf(SNIHostName(sniHost))
                sock.sslParameters = params
                sock
            }
            else -> {
                // Normal host or fragmented
                val sock = sslSocketFactory.createSocket(
                    wrappedSocket,
                    host,
                    port,
                    true
                ) as SSLSocket
                if (strategy == SniStrategy.TCP_FRAGMENTATION || strategy == SniStrategy.TLS_RECORD_FRAGMENTATION) {
                    val params = sock.sslParameters ?: SSLParameters()
                    if (!customSni.isNullOrBlank()) {
                        params.serverNames = listOf(SNIHostName(customSni))
                    }
                    sock.sslParameters = params
                }
                sock
            }
        }

        sslSocket.useClientMode = true
        sslSocket.startHandshake()
        return sslSocket
    }

    /**
     * Splits the initial TLS ClientHello at the TCP level into two chunks.
     */
    private class FragmentedTcpSocket(
        private val delegate: Socket,
        private val splitPos: Int,
        private val splitDelayMs: Long
    ) : Socket() {
        private var fragmented = false

        override fun getInputStream(): InputStream = delegate.inputStream

        override fun getOutputStream(): OutputStream {
            val original = delegate.outputStream
            return object : FilterOutputStream(original) {
                override fun write(b: ByteArray, off: Int, len: Int) {
                    // Check if this is the first write and looks like a TLS Handshake record (0x16 0x03)
                    if (!fragmented && len > splitPos && b[off] == 0x16.toByte() && b[off + 1] == 0x03.toByte()) {
                        fragmented = true
                        // Write chunk 1
                        original.write(b, off, splitPos)
                        original.flush()
                        try {
                            if (splitDelayMs > 0) {
                                Thread.sleep(splitDelayMs)
                            }
                        } catch (_: InterruptedException) {}
                        // Write chunk 2
                        original.write(b, off + splitPos, len - splitPos)
                        original.flush()
                    } else {
                        original.write(b, off, len)
                    }
                }

                override fun write(b: Int) {
                    original.write(b)
                }

                override fun flush() {
                    original.flush()
                }

                override fun close() {
                    original.close()
                }
            }
        }

        override fun isConnected(): Boolean = delegate.isConnected
        override fun isClosed(): Boolean = delegate.isClosed
        override fun close() = delegate.close()
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun getSoTimeout(): Int = delegate.soTimeout
    }

    /**
     * Splits a single TLS Handshake record into two valid TLS Handshake records.
     */
    private class TlsRecordFragmentedSocket(
        private val delegate: Socket,
        private val splitPos: Int
    ) : Socket() {
        private var fragmented = false

        override fun getInputStream(): InputStream = delegate.inputStream

        override fun getOutputStream(): OutputStream {
            val original = delegate.outputStream
            return object : FilterOutputStream(original) {
                override fun write(b: ByteArray, off: Int, len: Int) {
                    // TLS Record Header: [0]=ContentType, [1..2]=Version, [3..4]=Length
                    if (!fragmented && len > 5 + splitPos && b[off] == 0x16.toByte() && b[off + 1] == 0x03.toByte()) {
                        fragmented = true
                        val recordVersionMajor = b[off + 1]
                        val recordVersionMinor = b[off + 2]
                        val payloadLen = ((b[off + 3].toInt() and 0xFF) shl 8) or (b[off + 4].toInt() and 0xFF)

                        if (len == 5 + payloadLen && splitPos < payloadLen) {
                            val chunk1Len = splitPos
                            val chunk2Len = payloadLen - chunk1Len

                            // Record 1
                            val rec1 = ByteArray(5 + chunk1Len)
                            rec1[0] = 0x16.toByte()
                            rec1[1] = recordVersionMajor
                            rec1[2] = recordVersionMinor
                            rec1[3] = ((chunk1Len ushr 8) and 0xFF).toByte()
                            rec1[4] = (chunk1Len and 0xFF).toByte()
                            System.arraycopy(b, off + 5, rec1, 5, chunk1Len)

                            // Record 2
                            val rec2 = ByteArray(5 + chunk2Len)
                            rec2[0] = 0x16.toByte()
                            rec2[1] = recordVersionMajor
                            rec2[2] = recordVersionMinor
                            rec2[3] = ((chunk2Len ushr 8) and 0xFF).toByte()
                            rec2[4] = (chunk2Len and 0xFF).toByte()
                            System.arraycopy(b, off + 5 + chunk1Len, rec2, 5, chunk2Len)

                            original.write(rec1)
                            original.flush()
                            original.write(rec2)
                            original.flush()
                            return
                        }
                    }
                    original.write(b, off, len)
                }

                override fun write(b: Int) {
                    original.write(b)
                }

                override fun flush() {
                    original.flush()
                }

                override fun close() {
                    original.close()
                }
            }
        }

        override fun isConnected(): Boolean = delegate.isConnected
        override fun isClosed(): Boolean = delegate.isClosed
        override fun close() = delegate.close()
        override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
        override fun getSoTimeout(): Int = delegate.soTimeout
    }
}

