package com.aethervpn.vpncore.crypto

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.DESKeySpec

object Des {
    /**
     * Expands a 7-byte array into an 8-byte DES key with odd parity bits.
     */
    fun createDesKey(bytes7: ByteArray, offset: Int = 0): ByteArray {
        val key = ByteArray(8)
        key[0] = (bytes7[offset].toInt() and 0xFE).toByte()
        key[1] = (((bytes7[offset].toInt() and 0x01) shl 7) or ((bytes7[offset + 1].toInt() and 0xFC) ushr 1)).toByte()
        key[2] = (((bytes7[offset + 1].toInt() and 0x03) shl 6) or ((bytes7[offset + 2].toInt() and 0xF8) ushr 2)).toByte()
        key[3] = (((bytes7[offset + 2].toInt() and 0x07) shl 5) or ((bytes7[offset + 3].toInt() and 0xF0) ushr 3)).toByte()
        key[4] = (((bytes7[offset + 3].toInt() and 0x0F) shl 4) or ((bytes7[offset + 4].toInt() and 0xE0) ushr 4)).toByte()
        key[5] = (((bytes7[offset + 4].toInt() and 0x1F) shl 3) or ((bytes7[offset + 5].toInt() and 0xC0) ushr 5)).toByte()
        key[6] = (((bytes7[offset + 5].toInt() and 0x3F) shl 2) or ((bytes7[offset + 6].toInt() and 0x80) ushr 6)).toByte()
        key[7] = ((bytes7[offset + 6].toInt() and 0x7F) shl 1).toByte()

        // Set odd parity
        for (i in 0 until 8) {
            var b = key[i].toInt()
            var bitCount = 0
            for (j in 1..7) {
                if ((b and (1 shl j)) != 0) bitCount++
            }
            if (bitCount % 2 == 0) {
                b = b or 1
            } else {
                b = b and 0xFE
            }
            key[i] = b.toByte()
        }
        return key
    }

    /**
     * Encrypts 8 bytes of clear text using single DES with ECB and no padding.
     */
    fun desEncrypt(clearText8: ByteArray, key8WithParity: ByteArray): ByteArray {
        val desKeySpec = DESKeySpec(key8WithParity)
        val keyFactory = SecretKeyFactory.getInstance("DES")
        val secretKey = keyFactory.generateSecret(desKeySpec)
        val cipher = Cipher.getInstance("DES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(clearText8)
    }

    /**
     * MS-CHAPv2 ChallengeResponse (RFC 2759 Section 8.1 / 8.5):
     * Takes 21 bytes of password hash (or 16 bytes zero-padded to 21 bytes)
     * and 8 bytes challenge. Returns 24 bytes response.
     */
    fun challengeResponse(challenge8: ByteArray, passwordHash21: ByteArray): ByteArray {
        val response = ByteArray(24)
        val key1 = createDesKey(passwordHash21, 0)
        val res1 = desEncrypt(challenge8, key1)
        System.arraycopy(res1, 0, response, 0, 8)

        val key2 = createDesKey(passwordHash21, 7)
        val res2 = desEncrypt(challenge8, key2)
        System.arraycopy(res2, 0, response, 8, 8)

        val key3 = createDesKey(passwordHash21, 14)
        val res3 = desEncrypt(challenge8, key3)
        System.arraycopy(res3, 0, response, 16, 8)

        return response
    }
}

