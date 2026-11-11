package com.aethervpn.vpncore.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object CryptoBinding {

    const val SSTP_ATTRIB_CRYPTO_BINDING: Byte = 0x04
    const val CERT_HASH_PROTOCOL_SHA1: Byte = 0x01
    const val CERT_HASH_PROTOCOL_SHA256: Byte = 0x02

    private val SSTP_INNER_METHOD_SEED = "SSTP inner method key derivation"
        .toByteArray(StandardCharsets.US_ASCII)

    /**
     * Derives the Compound MAC Key (CMK) from MS-CHAPv2 master key (or send key).
     */
    fun deriveCompoundMacKey(msChapMasterKey: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(msChapMasterKey, "HmacSHA256"))
        return mac.doFinal(SSTP_INNER_METHOD_SEED)
    }

    /**
     * Builds the Crypto Binding Attribute bytes (104 bytes).
     *
     * @param nonce 32-byte nonce received from server in Call Connect Ack
     * @param serverCertSha256 32-byte SHA-256 hash of server certificate
     * @param serverCertSha1 20-byte SHA-1 hash of server certificate
     * @param useSha256 whether to use SHA-256 hash protocol bitmask
     */
    fun buildCryptoBindingAttribute(
        nonce: ByteArray,
        serverCertSha256: ByteArray,
        serverCertSha1: ByteArray?,
        useSha256: Boolean = true
    ): ByteArray {
        val buffer = ByteBuffer.allocate(104).order(ByteOrder.BIG_ENDIAN)
        // Attribute Header (4 bytes)
        buffer.put(0x00) // Reserved
        buffer.put(SSTP_ATTRIB_CRYPTO_BINDING) // Attrib ID
        buffer.putShort(104.toShort()) // Length

        // Reserved (3 bytes)
        buffer.put(0x00)
        buffer.put(0x00)
        buffer.put(0x00)

        // Hash Protocol Bitmask (1 byte)
        val hashProtocol = if (useSha256) CERT_HASH_PROTOCOL_SHA256 else CERT_HASH_PROTOCOL_SHA1
        buffer.put(hashProtocol)

        // Nonce (32 bytes)
        buffer.put(nonce, 0, 32)

        // Compound MAC placeholder (32 bytes zeroes)
        buffer.put(ByteArray(32))

        // Certificate Hash (32 bytes)
        if (useSha256) {
            buffer.put(serverCertSha256, 0, 32)
        } else {
            val paddedSha1 = ByteArray(32)
            if (serverCertSha1 != null) {
                System.arraycopy(serverCertSha1, 0, paddedSha1, 0, 20)
            }
            buffer.put(paddedSha1)
        }

        return buffer.array()
    }

    /**
     * Calculates the Compound MAC over the Call Connected packet
     * and inserts it at the Compound MAC offset in the attribute.
     */
    fun computeAndInsertCompoundMac(
        callConnectedPacket: ByteArray,
        compoundMacKey: ByteArray,
        compoundMacOffsetInPacket: Int
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(compoundMacKey, "HmacSHA256"))
        val cmac = mac.doFinal(callConnectedPacket)

        // Insert CMAC into packet
        System.arraycopy(cmac, 0, callConnectedPacket, compoundMacOffsetInPacket, 32)
        return callConnectedPacket
    }

    /**
     * Computes certificate hashes from encoded DER bytes.
     */
    fun computeCertHashSha256(derCert: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(derCert)
    }

    fun computeCertHashSha1(derCert: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-1").digest(derCert)
    }
}

