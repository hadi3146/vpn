package com.aethervpn.vpncore.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

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
        assertEquals(CryptoBinding.SSTP_ATTRIB_CRYPTO_BINDING, attr[1])
        assertEquals(CryptoBinding.CERT_HASH_PROTOCOL_SHA256, attr[7])
    }

    @Test
    fun testCompoundMacDerivation() {
        val masterKey = ByteArray(16) { 0x44.toByte() }
        val cmk = CryptoBinding.deriveCompoundMacKey(masterKey)
        assertNotNull(cmk)
        assertEquals(32, cmk.size)

        val packet = ByteArray(112)
        val computed = CryptoBinding.computeAndInsertCompoundMac(packet, cmk, 48)
        assertNotNull(computed)
    }
}

