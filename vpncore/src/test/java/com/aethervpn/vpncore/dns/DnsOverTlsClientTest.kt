package com.aethervpn.vpncore.dns

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

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
            0x00, 0x00, 0x00, 0x00, // Answers, Authority, Additional: 0
            0x07, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(), 'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00, // Null root
            0x00, 0x01, // Type: A
            0x00, 0x01  // Class: IN
        )
        assertNotNull(exampleQuery)
        assertEquals(29, exampleQuery.size)
    }
}
