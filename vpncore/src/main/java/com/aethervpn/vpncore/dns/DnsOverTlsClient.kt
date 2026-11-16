package com.aethervpn.vpncore.dns

import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.openProtectedTcpSocket
import com.aethervpn.vpncore.tun.TunnelPackets
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class DnsOverTlsClient(
    private val resolver: DnsResolver,
    private val socketProtector: SocketProtector? = null,
    private val connectTimeoutMs: Int = 3500,
    private val readTimeoutMs: Int = 3500,
    private val fallbackResolvers: List<DnsResolver> = listOf(
        DnsResolver.CLOUDFLARE,
        DnsResolver.GOOGLE,
        DnsResolver.QUAD9
    ),
    private val enableDohFallback: Boolean = true,
    private val failureCooldownMs: Long = 45_000L
) {
    private var sslSocket: SSLSocket? = null
    private var inputStream: BufferedInputStream? = null
    private var outputStream: BufferedOutputStream? = null
    private var activeResolver: DnsResolver = resolver
    private val socketLock = Any()

    @Volatile
    private var bypassUntilMs: Long = 0L
    private val dohClient by lazy {
        DnsOverHttpsClient(
            socketProtector = socketProtector,
            connectTimeoutMs = connectTimeoutMs,
            readTimeoutMs = readTimeoutMs
        )
    }

    // In-memory response cache: question hash -> (timestamp, response bytes)
    private val cache = ConcurrentHashMap<Int, Pair<Long, ByteArray>>()
    private val cacheTtlMs = 60_000L

    private fun openResolverSocket(target: DnsResolver) {
        closeSocket()
        val inetAddr = InetAddress.getByName(target.ip)
        val rawSocket = openProtectedTcpSocket(
            ipAddress = inetAddr,
            port = target.port,
            connectTimeoutMs = connectTimeoutMs,
            readTimeoutMs = readTimeoutMs,
            socketProtector = socketProtector
        )

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, null, null)
        val factory: SSLSocketFactory = sslContext.socketFactory
        val sock = factory.createSocket(rawSocket, target.host, target.port, true) as SSLSocket
        sock.useClientMode = true
        sock.startHandshake()

        activeResolver = target
        sslSocket = sock
        inputStream = BufferedInputStream(sock.inputStream, 4096)
        outputStream = BufferedOutputStream(sock.outputStream, 4096)
    }

    private fun closeSocket() {
        try { sslSocket?.close() } catch (_: Exception) {}
        sslSocket = null
        inputStream = null
        outputStream = null
    }

    /**
     * Resolves a raw DNS query over TLS (RFC 7858), automatically failing over across
     * backup DoT resolvers and DoH over port 443 if enabled.
     */
    fun query(queryWire: ByteArray): ByteArray {
        require(queryWire.size >= 12) { "DNS query too short: ${queryWire.size} bytes" }

        val cacheKey = queryWire.copyOfRange(2, queryWire.size).contentHashCode()
        val now = System.currentTimeMillis()
        cache[cacheKey]?.let { (cachedTime, cachedResp) ->
            if (now - cachedTime < cacheTtlMs) {
                val cloned = cachedResp.clone()
                cloned[0] = queryWire[0]
                cloned[1] = queryWire[1]
                return cloned
            } else {
                cache.remove(cacheKey)
            }
        }

        if (failureCooldownMs > 0L && now < bypassUntilMs) {
            throw IllegalStateException("DoT/DoH in temporary cooldown after upstream failure")
        }

        val orderedResolvers = buildList {
            add(resolver)
            for (alt in fallbackResolvers) {
                if (alt.ip != resolver.ip) add(alt)
            }
        }

        var lastError: Exception? = null
        synchronized(socketLock) {
            for (target in orderedResolvers) {
                val maxAttempts = if (target.ip == activeResolver.ip && sslSocket != null) 2 else 1
                var attempt = 0
                while (attempt < maxAttempts) {
                    attempt++
                    try {
                        val existing = sslSocket
                        if (existing == null || existing.isClosed || !existing.isConnected || activeResolver.ip != target.ip) {
                            openResolverSocket(target)
                        }
                        val resp = sendAndReadDot(queryWire)
                        if (resp.size >= 12) {
                            bypassUntilMs = 0L
                            cache[cacheKey] = Pair(System.currentTimeMillis(), resp.clone())
                        }
                        return resp
                    } catch (e: Exception) {
                        lastError = e
                        closeSocket()
                    }
                }
            }
        }

        if (enableDohFallback) {
            try {
                val dohResp = dohClient.query(queryWire)
                if (dohResp.size >= 12) {
                    bypassUntilMs = 0L
                    cache[cacheKey] = Pair(System.currentTimeMillis(), dohResp.clone())
                }
                return dohResp
            } catch (dohErr: Exception) {
                if (failureCooldownMs > 0L) {
                    bypassUntilMs = System.currentTimeMillis() + failureCooldownMs
                }
                throw IllegalStateException(
                    "DoT (${lastError?.message ?: "failed"}); DoH (${dohErr.message ?: "failed"})",
                    dohErr
                )
            }
        }

        if (failureCooldownMs > 0L) {
            bypassUntilMs = System.currentTimeMillis() + failureCooldownMs
        }
        throw IllegalStateException("Failed to query DoT resolvers: ${lastError?.message}", lastError)
    }

    private fun sendAndReadDot(queryWire: ByteArray): ByteArray {
        val os = outputStream ?: throw IllegalStateException("Output stream is null")
        val is_ = inputStream ?: throw IllegalStateException("Input stream is null")

        val lenBuf = ByteBuffer.allocate(2).order(ByteOrder.BIG_ENDIAN)
        lenBuf.putShort(queryWire.size.toShort())
        os.write(lenBuf.array())
        os.write(queryWire)
        os.flush()

        val respLenBuf = ByteArray(2)
        var read = 0
        while (read < 2) {
            val count = is_.read(respLenBuf, read, 2 - read)
            if (count == -1) throw IllegalStateException("EOF from DoT server")
            read += count
        }
        val respLen = ((respLenBuf[0].toInt() and 0xFF) shl 8) or (respLenBuf[1].toInt() and 0xFF)
        require(respLen in 12..16384) { "Invalid DoT response length: $respLen" }

        val response = ByteArray(respLen)
        read = 0
        while (read < respLen) {
            val count = is_.read(response, read, respLen - read)
            if (count == -1) throw IllegalStateException("Incomplete DNS response")
            read += count
        }
        return response
    }

    /**
     * Resolves an A record using encrypted DoT/DoH, filtering out private/bogon sinkholes.
     */
    fun resolvePublicIpv4(domain: String): Inet4Address? {
        return try {
            val txId = (System.nanoTime() and 0xFFFF).toInt()
            val wireQuery = TunnelPackets.buildDnsARecordQuery(domain, txId)
            val wireResp = query(wireQuery)
            TunnelPackets.parseDnsARecordFirstPublicIpv4(wireResp)
        } catch (_: Exception) {
            null
        }
    }

    suspend fun testLatencyMs(): Long = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        try {
            val exampleQuery = TunnelPackets.buildDnsARecordQuery("example.com", 0x1234)
            query(exampleQuery)
            System.currentTimeMillis() - start
        } catch (_: Exception) {
            -1L
        }
    }

    fun close() {
        synchronized(socketLock) {
            bypassUntilMs = 0L
            closeSocket()
            cache.clear()
        }
    }
}
