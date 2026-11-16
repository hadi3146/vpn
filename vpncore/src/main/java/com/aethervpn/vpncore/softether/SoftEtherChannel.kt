package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.SstpTransport
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext

/**
 * An individual TCP/TLS channel to a SoftEther VPN Server.
 * Supports primary session negotiation (login) and secondary channel joining (additional_connect).
 */
class SoftEtherChannel(
    val channelId: Int,
    val host: String,
    val ipAddress: String,
    val port: Int,
    val isPrimary: Boolean,
    val sniStrategy: SniStrategy,
    val customSni: String?,
    val strictCert: Boolean,
    val socketProtector: SocketProtector?,
    val connectTimeoutMs: Int = 10000
) {
    private var transport: SstpTransport? = null
    private var input: InputStream? = null
    private var output: OutputStream? = null

    val isConnected = AtomicBoolean(false)
    val txBytes = AtomicLong(0)
    val rxBytes = AtomicLong(0)

    private val writeLock = Any()
    private val txBuffer = ByteBuffer.allocate(65536).apply { order(ByteOrder.BIG_ENDIAN) }

    suspend fun connectAndHandshake(
        username: String,
        password: String,
        hubName: String,
        targetConnections: Int,
        existingSessionKey: ByteArray? = null
    ): SoftEtherSessionInfo = withContext(Dispatchers.IO) {
        val socketFactory = SniBypassSocketFactory(
            strategy = sniStrategy,
            customSni = customSni,
            strictCert = strictCert,
            socketProtector = socketProtector
        )

        val inetAddr = try {
            java.net.InetAddress.getByName(ipAddress)
        } catch (_: Exception) {
            java.net.InetAddress.getByName(host)
        }

        val t = socketFactory.createAndConnectTransport(
            host = host,
            ipAddress = inetAddr,
            port = port,
            timeoutMs = connectTimeoutMs
        )
        transport = t
        input = BufferedInputStream(t.inputStream, 65536)
        output = BufferedOutputStream(t.outputStream, 65536)

        val inStream = input ?: throw IllegalStateException("Input stream unavailable")
        val outStream = output ?: throw IllegalStateException("Output stream unavailable")

        // 1. Send VPNCONNECT Handshake Signature
        val targetHost = ipAddress.ifBlank { host }
        val watermarkHttp = buildHttpPost(
            target = SoftEtherConstants.HTTP_CONNECT_TARGET,
            host = targetHost,
            body = SoftEtherConstants.VPNCONNECT_BODY,
            contentType = "image/jpeg"
        )
        outStream.write(watermarkHttp)
        outStream.flush()

        val helloResponse = readHttpResponse(inStream)
        if (helloResponse.statusCode != 200) {
            throw IllegalStateException("SoftEther connect.cgi returned HTTP ${helloResponse.statusCode}")
        }
        val helloPack = SoftEtherPack.decode(helloResponse.body)

        val serverChallenge = helloPack.bytesProperties[SoftEtherConstants.SEP_RANDOM]
            ?: ByteArray(20) { it.toByte() }

        if (isPrimary) {
            // Primary Channel: Perform Login
            val loginPack = SoftEtherPack().apply {
                intProperties[SoftEtherConstants.SEP_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_VERSION] = SoftEtherConstants.COMPATIBLE_VERSION
                intProperties[SoftEtherConstants.SEP_CLIENT_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_CLIENT_VER] = SoftEtherConstants.COMPATIBLE_VERSION
                intProperties[SoftEtherConstants.SEP_CLIENT_ID] = 0
                intProperties[SoftEtherConstants.SEP_PROTOCOL] = 0
                intProperties[SoftEtherConstants.SEP_AUTH_TYPE] = 1 // Password Auth
                intProperties[SoftEtherConstants.SEP_MAX_CONNECTION] = targetConnections
                intProperties[SoftEtherConstants.SEP_HALF_CONNECTION] = 0

                stringProperties[SoftEtherConstants.SEP_CLIENT_STR] = "RadinVPN"
                stringProperties[SoftEtherConstants.SEP_CLIENT_OS_NAME] = "Android"
                stringProperties[SoftEtherConstants.SEP_METHOD] = SoftEtherConstants.METHOD_LOGIN
                stringProperties[SoftEtherConstants.SEP_USERNAME] = username
                stringProperties[SoftEtherConstants.SEP_HUB_NAME] = hubName

                booleanProperties[SoftEtherConstants.SEP_USE_ENCRYPT] = true
                booleanProperties[SoftEtherConstants.SEP_USE_COMPRESS] = false

                bytesProperties[SoftEtherConstants.SEP_UNIQUE_ID_CAMEL] = ByteArray(16).apply { SecureRandom().nextBytes(this) }
                bytesProperties[SoftEtherConstants.SEP_SECURE_PASSWORD] =
                    SoftEtherCrypto.calcSecurePassword(password, username, serverChallenge)
            }

            val loginBytes = loginPack.encode()
            val loginHttp = buildHttpPost(SoftEtherConstants.HTTP_VPN_TARGET, targetHost, loginBytes, "application/octet-stream")
            outStream.write(loginHttp)
            outStream.flush()

            val welcomeResponse = readHttpResponse(inStream)
            if (welcomeResponse.statusCode != 200) {
                throw IllegalStateException("SoftEther login returned HTTP ${welcomeResponse.statusCode}")
            }
            val welcomePack = SoftEtherPack.decode(welcomeResponse.body)

            val err = welcomePack.intProperties[SoftEtherConstants.SEP_ERROR]
            if (err != null && err != 0) {
                throw IllegalStateException("SoftEther login failed with server error code $err")
            }

            val sessionKey = welcomePack.bytesProperties[SoftEtherConstants.SEP_SESSION_KEY]
                ?: ByteArray(20).apply { SecureRandom().nextBytes(this) }
            val serverMaxConn = welcomePack.intProperties[SoftEtherConstants.SEP_MAX_CONNECTION] ?: targetConnections

            isConnected.set(true)
            SoftEtherSessionInfo(sessionKey = sessionKey, maxConnections = serverMaxConn)
        } else {
            // Secondary Channel: Join existing session with additional_connect
            val sessionKey = existingSessionKey ?: throw IllegalArgumentException("Session key required for secondary channel")

            val addPack = SoftEtherPack().apply {
                stringProperties[SoftEtherConstants.SEP_METHOD] = SoftEtherConstants.METHOD_ADDITIONAL_CONNECT
                bytesProperties[SoftEtherConstants.SEP_SESSION_KEY] = sessionKey
                intProperties[SoftEtherConstants.SEP_BUILD] = SoftEtherConstants.COMPATIBLE_BUILD
                intProperties[SoftEtherConstants.SEP_VERSION] = SoftEtherConstants.COMPATIBLE_VERSION
            }

            val addBytes = addPack.encode()
            val addHttp = buildHttpPost(SoftEtherConstants.HTTP_VPN_TARGET, targetHost, addBytes, "application/octet-stream")
            outStream.write(addHttp)
            outStream.flush()

            val addResponse = readHttpResponse(inStream)
            if (addResponse.statusCode != 200) {
                throw IllegalStateException("SoftEther additional_connect returned HTTP ${addResponse.statusCode}")
            }

            isConnected.set(true)
            SoftEtherSessionInfo(sessionKey = sessionKey, maxConnections = targetConnections)
        }
    }

    /**
     * Transmit a single Ethernet frame over this channel.
     * Returns true if frame was successfully written, or false if channel write failed / disconnected.
     */
    fun sendEthernetFrame(frame: ByteArray): Boolean {
        val out = output ?: return false
        if (!isConnected.get()) return false

        return synchronized(writeLock) {
            try {
                txBuffer.clear()
                txBuffer.putInt(1) // 1 frame
                txBuffer.putInt(frame.size)
                txBuffer.put(frame)
                txBuffer.flip()

                out.write(txBuffer.array(), 0, txBuffer.limit())
                out.flush()
                txBytes.addAndGet(txBuffer.limit().toLong())
                true
            } catch (e: Exception) {
                isConnected.set(false)
                close()
                false
            }
        }
    }

    /**
     * Send Cedar keepalive probe (block count = 0).
     */
    fun sendKeepalive() {
        val out = output ?: return
        if (!isConnected.get()) return
        synchronized(writeLock) {
            try {
                txBuffer.clear()
                txBuffer.putInt(0)
                txBuffer.flip()
                out.write(txBuffer.array(), 0, txBuffer.limit())
                out.flush()
            } catch (_: Exception) {
                isConnected.set(false)
                close()
            }
        }
    }

    /**
     * Read loop that continuously reads Ethernet frames from the server and delivers them.
     */
    suspend fun readLoop(onFrameReceived: (ByteArray) -> Unit) = withContext(Dispatchers.IO) {
        val inStream = input ?: return@withContext
        val headerBuf = ByteArray(8)

        try {
            while (isActive && isConnected.get()) {
                // Read 4 bytes: number of frames in block
                if (!readFully(inStream, headerBuf, 0, 4)) break
                val numFrames = (((headerBuf[0].toInt() and 0xFF) shl 24) or
                        ((headerBuf[1].toInt() and 0xFF) shl 16) or
                        ((headerBuf[2].toInt() and 0xFF) shl 8) or
                        (headerBuf[3].toInt() and 0xFF))

                if (numFrames <= 0 || numFrames > 256) {
                    // Invalid or keepalive probe
                    continue
                }

                for (i in 0 until numFrames) {
                    if (!readFully(inStream, headerBuf, 0, 4)) break
                    val frameLen = (((headerBuf[0].toInt() and 0xFF) shl 24) or
                            ((headerBuf[1].toInt() and 0xFF) shl 16) or
                            ((headerBuf[2].toInt() and 0xFF) shl 8) or
                            (headerBuf[3].toInt() and 0xFF))

                    if (frameLen in 14..65535) {
                        val frameData = ByteArray(frameLen)
                        if (readFully(inStream, frameData, 0, frameLen)) {
                            rxBytes.addAndGet(frameLen.toLong())
                            onFrameReceived(frameData)
                        } else {
                            break
                        }
                    }
                }
            }
        } catch (_: CancellationException) {
            // Normal shutdown
        } catch (_: Exception) {
            // Socket disconnected
        } finally {
            close()
        }
    }

    private fun readFully(inStream: InputStream, target: ByteArray, offset: Int, length: Int): Boolean {
        var total = 0
        while (total < length) {
            val r = inStream.read(target, offset + total, length - total)
            if (r == -1) return false
            total += r
        }
        return true
    }

    private fun buildHttpPost(target: String, host: String, body: ByteArray, contentType: String): ByteArray {
        val headers = "POST $target HTTP/1.1\r\n" +
                "Host: $host\r\n" +
                "User-Agent: ${SoftEtherConstants.HTTP_DEFAULT_USER_AGENT}\r\n" +
                "Content-Type: $contentType\r\n" +
                "Content-Length: ${body.size}\r\n" +
                "Connection: Keep-Alive\r\n" +
                "Keep-Alive: ${SoftEtherConstants.HTTP_KEEP_ALIVE}\r\n\r\n"
        val headerBytes = headers.toByteArray(Charsets.US_ASCII)
        val full = ByteArray(headerBytes.size + body.size)
        System.arraycopy(headerBytes, 0, full, 0, headerBytes.size)
        System.arraycopy(body, 0, full, headerBytes.size, body.size)
        return full
    }

    private fun readHttpResponse(inStream: InputStream): HttpResponse {
        val headerBytes = mutableListOf<Byte>()
        var foundSuffix = false

        while (true) {
            val b = inStream.read()
            if (b == -1) throw IllegalStateException("Unexpected EOF while reading HTTP header")
            headerBytes.add(b.toByte())
            val size = headerBytes.size
            if (size >= 4 &&
                headerBytes[size - 4] == '\r'.code.toByte() &&
                headerBytes[size - 3] == '\n'.code.toByte() &&
                headerBytes[size - 2] == '\r'.code.toByte() &&
                headerBytes[size - 1] == '\n'.code.toByte()
            ) {
                foundSuffix = true
                break
            }
        }

        val headerStr = String(headerBytes.toByteArray(), Charsets.US_ASCII)
        val lines = headerStr.split("\r\n")
        val statusLine = lines.firstOrNull().orEmpty()
        val statusCode = statusLine.split(" ").getOrNull(1)?.toIntOrNull() ?: 200

        var contentLength = 0
        for (line in lines) {
            if (line.startsWith("Content-Length:", ignoreCase = true)) {
                contentLength = line.substringAfter(":").trim().toIntOrNull() ?: 0
            }
        }

        val body = ByteArray(contentLength)
        if (contentLength > 0) {
            readFully(inStream, body, 0, contentLength)
        }

        return HttpResponse(statusCode, body)
    }

    fun close() {
        isConnected.set(false)
        try { transport?.close() } catch (_: Exception) {}
        transport = null
        input = null
        output = null
    }

    private data class HttpResponse(val statusCode: Int, val body: ByteArray)
}

data class SoftEtherSessionInfo(
    val sessionKey: ByteArray,
    val maxConnections: Int
)
