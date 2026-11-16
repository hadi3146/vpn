package com.aethervpn.vpncore.softether

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer

class SoftEtherPackTest {

    @Test
    fun testSha0KnownVectorEmpty() {
        // Known SHA-0 hash of empty input: f96cea198ad1dd5617ac084a3d92c6107708c0ef
        val emptyHash = SoftEtherCrypto.hashSha0(ByteArray(0))
        assertEquals(20, emptyHash.size)
        val hex = emptyHash.joinToString("") { "%02x".format(it) }
        assertEquals("f96cea198ad1dd5617ac084a3d92c6107708c0ef", hex)
    }

    @Test
    fun testSha0KnownVectorAbc() {
        // Known SHA-0 hash of ASCII "abc": 0164b8a914cd2a5e74c4f7ff082c4d97f1edf880
        val abcHash = SoftEtherCrypto.hashSha0("abc".toByteArray(Charsets.US_ASCII))
        val hex = abcHash.joinToString("") { "%02x".format(it) }
        assertEquals("0164b8a914cd2a5e74c4f7ff082c4d97f1edf880", hex)
    }

    @Test
    fun testCalcSecurePassword() {
        val random = ByteArray(20) { it.toByte() }
        val securePass = SoftEtherCrypto.calcSecurePassword("vpn", "vpn", random)
        assertNotNull(securePass)
        assertEquals(20, securePass.size)
    }

    @Test
    fun testWatermarkValidity() {
        assertTrue(SoftEtherConstants.WATERMARK.size > 200)
        // First 6 bytes must be "GIF89a"
        val header = String(SoftEtherConstants.WATERMARK.sliceArray(0..5), Charsets.US_ASCII)
        assertEquals("GIF89a", header)
    }

    @Test
    fun testPackEncodingAndDecodingRoundtrip() {
        val pack = SoftEtherPack().apply {
            intProperties[SoftEtherConstants.SEP_BUILD] = 9807
            intProperties[SoftEtherConstants.SEP_VERSION] = 444
            intProperties[SoftEtherConstants.SEP_AUTH_TYPE] = 1
            intProperties[SoftEtherConstants.SEP_MAX_CONNECTION] = 8

            booleanProperties[SoftEtherConstants.SEP_USE_ENCRYPT] = true
            booleanProperties[SoftEtherConstants.SEP_USE_COMPRESS] = false

            stringProperties[SoftEtherConstants.SEP_METHOD] = SoftEtherConstants.METHOD_LOGIN
            stringProperties[SoftEtherConstants.SEP_USERNAME] = "vpn"
            stringProperties[SoftEtherConstants.SEP_HUB_NAME] = "VPNGATE"

            bytesProperties[SoftEtherConstants.SEP_RANDOM] = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
            addressProperties[SoftEtherConstants.SEP_CLIENT_IP_ADDRESS] = byteArrayOf(192.toByte(), 168.toByte(), 1, 100)
        }

        val encoded = pack.encode()
        assertTrue(encoded.isNotEmpty())

        val decoded = SoftEtherPack.decode(encoded)

        assertEquals(9807, decoded.intProperties[SoftEtherConstants.SEP_BUILD])
        assertEquals(444, decoded.intProperties[SoftEtherConstants.SEP_VERSION])
        assertEquals(1, decoded.intProperties[SoftEtherConstants.SEP_AUTH_TYPE])
        assertEquals(8, decoded.intProperties[SoftEtherConstants.SEP_MAX_CONNECTION])

        assertEquals(true, decoded.booleanProperties[SoftEtherConstants.SEP_USE_ENCRYPT])
        assertEquals(false, decoded.booleanProperties[SoftEtherConstants.SEP_USE_COMPRESS])

        assertEquals(SoftEtherConstants.METHOD_LOGIN, decoded.stringProperties[SoftEtherConstants.SEP_METHOD])
        assertEquals("vpn", decoded.stringProperties[SoftEtherConstants.SEP_USERNAME])
        assertEquals("VPNGATE", decoded.stringProperties[SoftEtherConstants.SEP_HUB_NAME])

        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8), decoded.bytesProperties[SoftEtherConstants.SEP_RANDOM])
        assertArrayEquals(byteArrayOf(192.toByte(), 168.toByte(), 1, 100), decoded.addressProperties[SoftEtherConstants.SEP_CLIENT_IP_ADDRESS])
    }
}
