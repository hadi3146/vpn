package com.aethervpn.client.data.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SstpUriCodecTest {

    @Test
    fun testParseFullSstpUri() {
        val uri = "sstp://admin:secret123@vpn.example.com:992?sni=decoy.domain.com#My%20Work%20VPN"
        val server = SstpUriCodec.parse(uri)

        assertNotNull(server)
        assertEquals("vpn.example.com", server!!.hostName)
        assertEquals("vpn.example.com", server.ip)
        assertEquals(992, server.customPort)
        assertEquals("admin", server.customUsername)
        assertEquals("secret123", server.customPassword)
        assertEquals("decoy.domain.com", server.customSni)
        assertEquals("My Work VPN", server.countryLong)
        assertTrue(server.isCustom)
    }

    @Test
    fun testParseMinimalHostPort() {
        val server = SstpUriCodec.parse("192.168.1.100:5555")

        assertNotNull(server)
        assertEquals("192.168.1.100", server!!.hostName)
        assertEquals(5555, server.customPort)
        assertEquals("vpn", server.customUsername)
        assertEquals("vpn", server.customPassword)
        assertNull(server.customSni)
    }

    @Test
    fun testEncodeAndDecodeRoundtrip() {
        val original = VpnServer(
            hostName = "node1.softether.net",
            ip = "node1.softether.net",
            countryLong = "Tokyo Server",
            isCustom = true,
            customPort = 992,
            customUsername = "testuser",
            customPassword = "testpass",
            customSni = "teams.microsoft.com"
        )

        val encoded = SstpUriCodec.encode(original)
        assertTrue(encoded.startsWith("sstp://testuser:testpass@node1.softether.net:992?sni=teams.microsoft.com#Tokyo+Server"))

        val decoded = SstpUriCodec.parse(encoded)
        assertNotNull(decoded)
        assertEquals(original.hostName, decoded!!.hostName)
        assertEquals(original.customPort, decoded.customPort)
        assertEquals(original.customUsername, decoded.customUsername)
        assertEquals(original.customPassword, decoded.customPassword)
        assertEquals(original.customSni, decoded.customSni)
    }

    @Test
    fun testParseVlessUri() {
        val uri = "vless://a1b2c3d4-e5f6-7890-abcd-ef1234567890@myvless.example.com:443?security=reality&sni=speed.cloudflare.com&fp=chrome#Private%20Reality"
        val server = SstpUriCodec.parse(uri)

        assertNotNull(server)
        assertEquals("myvless.example.com", server!!.hostName)
        assertEquals(443, server.customPort)
        assertEquals("a1b2c3d4-e5f6-7890-abcd-ef1234567890", server.customUsername)
        assertEquals("speed.cloudflare.com", server.customSni)
        assertEquals("Private Reality", server.countryLong)
        assertEquals("VLESS", server.logType)
        assertTrue(server.isCustom)
    }

    @Test
    fun testParseShadowsocksUri() {
        val uri = "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZDEyMw@198.51.100.1:8388#Fast%20SS"
        val server = SstpUriCodec.parse(uri)

        assertNotNull(server)
        assertEquals("198.51.100.1", server!!.hostName)
        assertEquals(8388, server.customPort)
        assertEquals("chacha20-ietf-poly1305", server.customUsername)
        assertEquals("password123", server.customPassword)
        assertEquals("Fast SS", server.countryLong)
        assertEquals("SHADOWSOCKS", server.logType)
    }

    @Test
    fun testParseTrojanUri() {
        val uri = "trojan://supersecret@trojan.node.net:443?sni=gateway.icloud.com#Trojan%20Decoy"
        val server = SstpUriCodec.parse(uri)

        assertNotNull(server)
        assertEquals("trojan.node.net", server!!.hostName)
        assertEquals(443, server.customPort)
        assertEquals("supersecret", server.customPassword)
        assertEquals("gateway.icloud.com", server.customSni)
        assertEquals("Trojan Decoy", server.countryLong)
        assertEquals("TROJAN", server.logType)
    }
}

