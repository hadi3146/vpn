package com.aethervpn.vpncore.dns

import com.aethervpn.vpncore.transport.SocketProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class DnsOverTlsClient(
    private val resolver: DnsResolver,
    private val socketProtector: SocketProtector? = null,
    private val connectTimeoutMs: Int = 5000,
    private val readTimeoutMs: Int = 4000
) {
    private var sslSocket: SSLSocket? = null
    private var inputStream: BufferedInputStream? = null
    private var outputStream: BufferedOutputStream? = null
    private val socketLock = Any()

    // Simple in-memory response cache: DNS payload hash -> (timestamp, response bytes)
    private val cache = ConcurrentHashMap<Int, Pair<Long, ByteArray>>()
    private val cacheTtlMs = 60_000L // 60 seconds TTL

    private fun getOrCreateSocket(): SSLSocket {
        synchronized(socketLock) {
            val existing = sslSocket
            if (existing != null && existing.isConnected && !existing.isClosed) {
                return existing
            }
            closeSocket()

            val rawSocket = Socket()
            socketProtector?.protect(rawSocket)
            rawSocket.tcpNoDelay = true
            rawSocket.soTimeout = readTimeoutMs
            val inetAddr = InetAddress.getByName(resolver.ip)
            rawSocket.connect(InetSocketAddress(inetAddr, resolver.port), connectTimeoutMs)

            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, null, null)
            val factory: SSLSocketFactory = sslContext.socketFactory
            val sock = factory.createSocket(rawSocket, resolver.host, resolver.port, true) as SSLSocket
            sock.useClientMode = true
            sock.startHandshake()

            sslSocket = sock
            inputStream = BufferedInputStream(sock.inputStream, 4096)
            outputStream = BufferedOutputStream(sock.outputStream, 4096)
            return sock
        }
    }

    private fun closeSocket() {
        try { sslSocket?.close() } catch (_: Exception) {}
        sslSocket = null
        inputStream = null
        outputStream = null
    }

    /**
     * Resolves a raw DNS query over TLS (RFC 7858).
     * @param queryWire DNS query in wire format
     * @return DNS response in wire format, matching original query transaction ID
     */
    fun query(queryWire: ByteArray): ByteArray {
        require(queryWire.size >= 12) { "DNS query too short: ${queryWire.size} bytes" }

        // Cache lookup based on question (skip the first 2 bytes transaction ID)
        val cacheKey = queryWire.copyOfRange(2, queryWire.size).contentHashCode()
        val now = System.currentTimeMillis()
        cache[cacheKey]?.let { (cachedTime, cachedResp) ->
            if (now - cachedTime < cacheTtlMs) {
                val cloned = cachedResp.clone()
                // Update transaction ID to match current query
                cloned[0] = queryWire[0]
                cloned[1] = queryWire[1]
                return cloned
            } else {
                cache.remove(cacheKey)
            }
        }

        synchronized(socketLock) {
            var attempts = 0
            while (attempts < 2) {
                attempts++
                try {
                    getOrCreateSocket()
                    val os = outputStream ?: throw IllegalStateException("Output stream is null")
                    val is_ = inputStream ?: throw IllegalStateException("Input stream is null")

                    // RFC 7858: 2-byte big-endian length prefix followed by DNS message
                    val lenBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
                    lenBuf.putShort(queryWire.size.toShort())
                    os.write(lenBuf.array())
                    os.write(queryWire)
                    os.flush()

                    // Read 2-byte response length
                    val respLenBuf = ByteArray(2)
                    var read = 0
                    while (read < 2) {
                        val count = is_.read(respLenBuf, read, 2 - read)
                        if (count == -1) throw IllegalStateException("EOF from DoT server")
                        read += count
                    }
                    val respLen = ((respLenBuf[0].toInt() and 0xFF) shl 8) or (respLenBuf[1].toInt() and 0xFF)

                    // Read full response message
                    val response = ByteArray(respLen)
                    read = 0
                    while (read < respLen) {
                        val count = is_.read(response, read, respLen - read)
                        if (count == -1) throw IllegalStateException("Incomplete DNS response")
                        read += count
                    }

                    // Store in cache
                    if (response.size >= 12) {
                        cache[cacheKey] = Pair(now, response.clone())
                    }

                    return response
                } catch (e: Exception) {
                    closeSocket()
                    if (attempts >= 2) throw e
                }
            }
            throw IllegalStateException("Failed to query DoT server after retries")
        }
    }

    suspend fun testLatencyMs(): Long = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        try {
            // DNS query for example.com A record
            val exampleQuery = byteArrayOf(
                0x12, 0x34, // ID
                0x01, 0x00, // Standard query
                0x00, 0x01, // Questions: 1
                0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional: 0
                0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
                0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
                0x00, // Null root
                0x00, 0x01, // Type: A
                0x00, 0x01  // Class: IN
            )
            query(exampleQuery)
            System.currentTimeMillis() - start
        } catch (_: Exception) {
            -1L
        }
    }

    fun close() {
        synchronized(socketLock) {
            closeSocket()
            cache.clear()
        }
    }
}

