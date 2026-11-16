package com.aethervpn.vpncore.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream

class DnsOverTlsClientTest {

    @Test
    fun testDnsResolverPresets() {
        val cloudflare = DnsResolver.findById("cloudflare")
        assertEquals("one.one.one.one", cloudflare.host)
        assertEquals("1.1.1.1", cloudflare.ip)
        assertEquals(853, cloudflare.port)

        val google = DnsResolver.findById("google")
        assertEquals("dns.google", google.host)
        assertEquals("8.8.8.8", google.ip)

        val quad9 = DnsResolver.findById("quad9")
        assertEquals("9.9.9.9", quad9.ip)
    }

    @Test
    fun testDnsQueryWireFormat() {
        // Construct standard DNS A-record query for example.com
        val exampleQuery = byteArrayOf(
            0x12, 0x34, // ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answers: 0
            0x00, 0x00, // Authority: 0
            0x00, 0x00, // Additional: 0
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00, // Null root
            0x00, 0x01, // Type: A
            0x00, 0x01  // Class: IN
        )
        assertNotNull(exampleQuery)
        assertEquals(29, exampleQuery.size)
        val built = com.aethervpn.vpncore.tun.TunnelPackets.buildDnsARecordQuery("example.com", 0x1234)
        org.junit.Assert.assertArrayEquals(exampleQuery, built)
    }

    @Test
    fun testDohDefaultEndpointsIncludeMajorResolvers() {
        val ips = DnsOverHttpsClient.DEFAULT_ENDPOINTS.map { it.ip }.toSet()
        assertTrue(ips.contains("1.1.1.1"))
        assertTrue(ips.contains("8.8.8.8"))
        assertTrue(ips.contains("9.9.9.9"))
    }

    @Test
    fun testDohChunkedResponseStopsImmediatelyWithoutEof() {
        val fakeDns = ByteArray(14) { (it + 1).toByte() }
        val chunkHex = fakeDns.size.toString(16)
        val headers = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n$chunkHex\r\n".toByteArray(Charsets.US_ASCII)
        val trailer = "\r\n0\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val streamBytes = headers + fakeDns + trailer
        var eofRequestedAfterChunk = false
        val stallingStream = object : InputStream() {
            private var pos = 0
            override fun read(): Int = if (pos < streamBytes.size) streamBytes[pos++].toInt() and 0xFF else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pos >= streamBytes.size) {
                    eofRequestedAfterChunk = true
                    throw AssertionError("Should stop once chunked zero-terminator is read without blocking for EOF")
                }
                val count = minOf(len, streamBytes.size - pos)
                System.arraycopy(streamBytes, pos, b, off, count)
                pos += count
                return count
            }
        }

        val decoded = DnsOverHttpsClient().readHttpBody(stallingStream)
        assertNotNull(decoded)
        assertArrayEquals(fakeDns, decoded)
        assertTrue(!eofRequestedAfterChunk)
    }

    @Test
    fun testDohNon2xxStatusThrowsDescriptiveError() {
        val response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val err = assertThrows(IOException::class.java) {
            DnsOverHttpsClient().readHttpBody(ByteArrayInputStream(response))
        }
        assertTrue(err.message?.contains("403") == true)
    }
}

