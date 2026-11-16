package com.aethervpn.vpncore.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class CryptoBindingTest {

    @Test
    fun testBuildCryptoBindingAttribute() {
        val nonce = ByteArray(32) { 0x11.toByte() }
        val certSha256 = ByteArray(32) { 0x22.toByte() }
        val certSha1 = ByteArray(20) { 0x33.toByte() }

        val attr = CryptoBinding.buildCryptoBindingAttribute(
            nonce = nonce,
            serverCertSha256 = certSha256,
            serverCertSha1 = certSha1,
            useSha256 = true
        )

        assertEquals(104, attr.size)
        assertEquals(0x03.toByte(), attr[1])
        assertEquals(CryptoBinding.SSTP_ATTRIB_CRYPTO_BINDING, attr[1])
        assertEquals(0x04.toByte(), com.aethervpn.vpncore.sstp.SstpAttribute.ATTRIB_CRYPTO_BINDING_REQ)
        assertEquals(CryptoBinding.CERT_HASH_PROTOCOL_SHA256, attr[7])
        // Cert hash occupies bytes 40..71 within the 104-byte attribute
        assertEquals(0x22.toByte(), attr[40])
        assertEquals(0x22.toByte(), attr[71])
        // Compound MAC field occupies bytes 72..103 (initially zeroed)
        assertEquals(0x00.toByte(), attr[72])
        assertEquals(0x00.toByte(), attr[103])
    }

    @Test
    fun testCompoundMacDerivationSha256AndOffsetPreservesCertHash() {
        val hlak = ByteArray(32) { (it + 1).toByte() }
        val cmk = CryptoBinding.deriveCompoundMacKey(hlak, useSha256 = true)
        assertEquals(32, cmk.size)

        // Independent MS-SSTP §3.2.5.2 reference check: "SSTP inner method derived CMK" + 0x20 0x00 0x01
        val expectedInput = "SSTP inner method derived CMK".toByteArray(StandardCharsets.US_ASCII) +
            byteArrayOf(0x20, 0x00, 0x01)
        val expectedCmk = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(hlak, "HmacSHA256"))
            doFinal(expectedInput)
        }
        assertArrayEquals(expectedCmk, cmk)

        // Simulate 112-byte Call Connected packet (8B SSTP header + 104B attribute)
        val packet = ByteArray(112)
        // Populate CertHash at offset 48..79 with 0xAA and keep Compound MAC 80..111 zeroed
        for (i in 48 until 80) packet[i] = 0xAA.toByte()

        val cmacOffset = 8 + 4 + 4 + 32 + 32 // 80
        val expectedCmac = Mac.getInstance("HmacSHA256").run {
            init(SecretKeySpec(cmk, "HmacSHA256"))
            doFinal(packet)
        }
        val computed = CryptoBinding.computeAndInsertCompoundMac(packet, cmk, cmacOffset, useSha256 = true)
        assertNotNull(computed)
        // CertHash at 48..79 must remain untouched
        for (i in 48 until 80) {
            assertEquals("CertHash corrupted at index $i", 0xAA.toByte(), computed[i])
        }
        assertArrayEquals(expectedCmac, computed.copyOfRange(80, 112))
    }

    @Test
    fun testCompoundMacDerivationSha1() {
        val hlak = ByteArray(32) { 0x55.toByte() }
        val cmk = CryptoBinding.deriveCompoundMacKey(hlak, useSha256 = false)
        assertEquals(20, cmk.size)

        val expectedInput = "SSTP inner method derived CMK".toByteArray(StandardCharsets.US_ASCII) +
            byteArrayOf(0x14, 0x00, 0x01)
        val expectedCmk = Mac.getInstance("HmacSHA1").run {
            init(SecretKeySpec(hlak, "HmacSHA1"))
            doFinal(expectedInput)
        }
        assertArrayEquals(expectedCmk, cmk)

        val packet = ByteArray(112)
        val computed = CryptoBinding.computeAndInsertCompoundMac(packet, cmk, 80, useSha256 = false)
        // Trailing 12 bytes of 32-byte CMAC field must stay 0 for SHA-1
        for (i in 100 until 112) {
            assertEquals(0.toByte(), computed[i])
        }
    }
}

