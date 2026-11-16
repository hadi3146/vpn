package com.aethervpn.vpncore.softether

import java.nio.ByteBuffer

/**
 * Cryptographic operations required for SoftEther Native Protocol authentication.
 * SoftEther uses SHA-0 (FIPS-180 original without circular shift) for password hashing.
 */
object SoftEtherCrypto {

    private fun f(t: Int, b: Int, c: Int, d: Int): Int {
        return when (t) {
            in 0..19 -> (b and c) or (b.inv() and d)
            in 20..39, in 60..79 -> b xor c xor d
            in 40..59 -> (b and c) or (b and d) or (c and d)
            else -> 0
        }
    }

    private fun k(t: Int): Int {
        return when (t) {
            in 0..19 -> 0x5A827999
            in 20..39 -> 0x6ED9EBA1
            in 40..59 -> 0x8F1BBCDC.toInt()
            in 60..79 -> 0xCA62C1D6.toInt()
            else -> 0
        }
    }

    private fun rotl(n: Int, x: Int): Int {
        return (x shl n) or (x ushr (32 - n))
    }

    /**
     * Compute 160-bit SHA-0 hash of the input bytes.
     */
    fun hashSha0(input: ByteArray): ByteArray {
        val blockSize = (input.size + 9) / 64 + 1
        val paddedSize = blockSize * 64
        val padded = ByteBuffer.allocate(paddedSize)

        padded.put(input)
        padded.put(0x80.toByte())
        padded.position(paddedSize - 8)
        padded.putLong(input.size.toLong() * 8L)
        padded.flip()

        val w = IntArray(80)
        var h0 = 0x67452301
        var h1 = 0xEFCDAB89.toInt()
        var h2 = 0x98BADCFE.toInt()
        var h3 = 0x10325476
        var h4 = 0xC3D2E1F0.toInt()

        repeat(blockSize) {
            for (i in 0..15) {
                w[i] = padded.int
            }
            // SHA-0: NO circular shift on expansion
            for (i in 16..79) {
                w[i] = w[i - 3] xor w[i - 8] xor w[i - 14] xor w[i - 16]
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4

            for (i in 0..79) {
                val temp = rotl(5, a) + f(i, b, c, d) + e + w[i] + k(i)
                e = d
                d = c
                c = rotl(30, b)
                b = a
                a = temp
            }

            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
        }

        val out = ByteBuffer.allocate(20)
        out.putInt(h0)
        out.putInt(h1)
        out.putInt(h2)
        out.putInt(h3)
        out.putInt(h4)
        return out.array()
    }

    /**
     * Compute SoftEther secure password hash:
     * hash = SHA0( SHA0( password + uppercase(username) ) + random_server_challenge )
     */
    fun calcSecurePassword(password: String, username: String, random: ByteArray): ByteArray {
        val passBytes = password.toByteArray(Charsets.US_ASCII)
        val userBytes = username.uppercase().toByteArray(Charsets.US_ASCII)

        val h1 = hashSha0(passBytes + userBytes)
        return hashSha0(h1 + random)
    }
}

