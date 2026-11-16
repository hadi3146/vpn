package com.aethervpn.vpncore.dns

import com.aethervpn.vpncore.transport.SniBypassSocketFactory
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.SstpTransport
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.util.Locale

/**
 * Lightweight RFC 8484 DNS-over-HTTPS (wire-format application/dns-message) client
 * running on TCP:443 with SNI-bypass support for networks that block DoT port 853.
 */
class DnsOverHttpsClient(
    private val socketProtector: SocketProtector? = null,
    private val connectTimeoutMs: Int = 4000,
    private val readTimeoutMs: Int = 4000
) {
    data class DohEndpoint(
        val host: String,
        val ip: String,
        val path: String = "/dns-query"
    )

    fun query(
        queryWire: ByteArray,
        endpoints: List<DohEndpoint> = DEFAULT_ENDPOINTS
    ): ByteArray {
        require(queryWire.size >= 12) { "DNS query too short: ${queryWire.size} bytes" }
        var lastError: Exception? = null
        val strategies = if (socketProtector == null) {
            // Inside active VPN tunnel, try clean SNI first before bypass strategies
            listOf(SniStrategy.DISABLED, SniStrategy.DIRECT_IP_NO_SNI)
        } else {
            listOf(SniStrategy.DIRECT_IP_NO_SNI, SniStrategy.TCP_FRAGMENTATION)
        }

        for (endpoint in endpoints) {
            val ipAddr = try {
                InetAddress.getByName(endpoint.ip)
            } catch (e: Exception) {
                lastError = e
                continue
            }
            for (strategy in strategies) {
                var transport: SstpTransport? = null
                try {
                    transport = SniBypassSocketFactory(
                        strategy = strategy,
                        splitPosition = 16,
                        splitDelayMs = 5,
                        strictCert = false,
                        socketProtector = socketProtector
                    ).createAndConnectTransport(
                        host = endpoint.host,
                        ipAddress = ipAddr,
                        port = 443,
                        timeoutMs = connectTimeoutMs
                    )
                    transport.setSoTimeout(readTimeoutMs)
                    val headers = buildString {
                        append("POST ${endpoint.path} HTTP/1.1\r\n")
                        append("Host: ${endpoint.host}\r\n")
                        append("Accept: application/dns-message\r\n")
                        append("Content-Type: application/dns-message\r\n")
                        append("Content-Length: ${queryWire.size}\r\n")
                        append("Connection: close\r\n")
                        append("\r\n")
                    }.toByteArray(Charsets.US_ASCII)

                    val out = transport.outputStream
                    out.write(headers)
                    out.write(queryWire)
                    out.flush()

                    val responseBody = readHttpBody(transport.inputStream)
                    if (responseBody != null && responseBody.size >= 12) {
                        return responseBody
                    }
                } catch (e: Exception) {
                    lastError = e
                } finally {
                    try { transport?.close() } catch (_: Exception) {}
                }
            }
        }
        throw IllegalStateException("DoH query failed: ${lastError?.message ?: "unreachable"}", lastError)
    }

    internal fun readHttpBody(input: InputStream): ByteArray? {
        val raw = ByteArrayOutputStream()
        val buf = ByteArray(4096)
        var headerEnd = -1
        var bytes = ByteArray(0)

        while (raw.size() < 16384) {
            val n = input.read(buf)
            if (n <= 0) break
            raw.write(buf, 0, n)
            bytes = raw.toByteArray()
            headerEnd = findHeaderEnd(bytes)
            if (headerEnd >= 0) break
        }
        if (headerEnd < 0) throw IOException("Incomplete HTTP headers from DoH endpoint")

        val headerText = String(bytes, 0, headerEnd, Charsets.ISO_8859_1)
        val lines = headerText.split("\r\n")
        val statusCode = lines.firstOrNull()?.trim()?.split(Regex("\\s+"))?.getOrNull(1)?.toIntOrNull()
        if (statusCode !in 200..299) {
            throw IOException("HTTP ${statusCode ?: "unknown"} from DoH endpoint")
        }

        var contentLength = -1
        var chunked = false
        for (i in 1 until lines.size) {
            val idx = lines[i].indexOf(':')
            if (idx <= 0) continue
            val k = lines[i].substring(0, idx).trim().lowercase(Locale.US)
            val v = lines[i].substring(idx + 1).trim()
            if (k == "content-length") contentLength = v.toIntOrNull() ?: -1
            if (k == "transfer-encoding" && v.contains("chunked", ignoreCase = true)) chunked = true
        }

        val bodyStart = headerEnd + 4
        val tail = ByteArrayOutputStream()
        if (bodyStart < bytes.size) {
            tail.write(bytes, bodyStart, bytes.size - bodyStart)
        }
        if (chunked) {
            decodeChunkedBytes(tail.toByteArray())?.let { return it }
        }
        while (contentLength < 0 || tail.size() < contentLength) {
            val n = input.read(buf)
            if (n <= 0) break
            tail.write(buf, 0, n)
            if (chunked) {
                decodeChunkedBytes(tail.toByteArray())?.let { return it }
            }
        }
        val rawBody = tail.toByteArray()
        return when {
            chunked -> decodeChunkedBytes(rawBody)
            contentLength > 0 && rawBody.size >= contentLength -> rawBody.copyOf(contentLength)
            rawBody.isNotEmpty() -> rawBody
            else -> null
        }
    }

    private fun decodeChunkedBytes(data: ByteArray): ByteArray? {
        val out = ByteArrayOutputStream()
        var pos = 0
        while (pos < data.size) {
            var crlf = -1
            for (i in pos until data.size - 1) {
                if (data[i] == '\r'.code.toByte() && data[i + 1] == '\n'.code.toByte()) {
                    crlf = i
                    break
                }
            }
            if (crlf < 0) break
            val sizeStr = String(data, pos, crlf - pos, Charsets.US_ASCII).substringBefore(';').trim()
            val chunkLen = sizeStr.toIntOrNull(16) ?: break
            pos = crlf + 2
            if (chunkLen == 0) return out.toByteArray()
            if (pos + chunkLen > data.size) break
            out.write(data, pos, chunkLen)
            pos += chunkLen + 2
        }
        return if (out.size() >= 12) out.toByteArray() else null
    }

    private fun findHeaderEnd(data: ByteArray): Int {
        for (i in 0..data.size - 4) {
            if (data[i] == '\r'.code.toByte() &&
                data[i + 1] == '\n'.code.toByte() &&
                data[i + 2] == '\r'.code.toByte() &&
                data[i + 3] == '\n'.code.toByte()
            ) {
                return i
            }
        }
        return -1
    }

    companion object {
        val DEFAULT_ENDPOINTS = listOf(
            DohEndpoint(host = "cloudflare-dns.com", ip = "1.1.1.1"),
            DohEndpoint(host = "dns.google", ip = "8.8.8.8"),
            DohEndpoint(host = "dns.quad9.net", ip = "9.9.9.9")
        )
    }
}

