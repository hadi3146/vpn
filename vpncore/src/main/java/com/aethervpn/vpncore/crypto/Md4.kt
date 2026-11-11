package com.aethervpn.vpncore.crypto

/**
 * MD4 message-digest algorithm (RFC 1320).
 * Required for NT-Password-Hash in MS-CHAPv2.
 */
object Md4 {

    private fun f(x: Int, y: Int, z: Int): Int = (x and y) or (x.inv() and z)
    private fun g(x: Int, y: Int, z: Int): Int = (x and y) or (x and z) or (y and z)
    private fun h(x: Int, y: Int, z: Int): Int = x xor y xor z

    private fun rotl(x: Int, s: Int): Int = (x shl s) or (x ushr (32 - s))

    private fun ff(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int): Int =
        rotl(a + f(b, c, d) + x, s)

    private fun gg(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int): Int =
        rotl(a + g(b, c, d) + x + 0x5A827999, s)

    private fun hh(a: Int, b: Int, c: Int, d: Int, x: Int, s: Int): Int =
        rotl(a + h(b, c, d) + x + 0x6ED9EBA1, s)

    fun digest(data: ByteArray): ByteArray {
        val origLen = data.size
        val tailLen = origLen % 64
        val padLen = if (tailLen < 56) 56 - tailLen else 120 - tailLen
        val totalLen = origLen + padLen + 8

        val padded = ByteArray(totalLen)
        System.arraycopy(data, 0, padded, 0, origLen)
        padded[origLen] = 0x80.toByte()

        // Append bit length in little endian
        val bitLen = origLen.toLong() * 8
        for (i in 0 until 8) {
            padded[origLen + padLen + i] = ((bitLen ushr (8 * i)) and 0xFF).toByte()
        }

        var a = 0x67452301
        var b = 0xEFCDAB89.toInt()
        var c = 0x98BADCFE.toInt()
        var d = 0x10325476

        val x = IntArray(16)
        for (offset in 0 until totalLen step 64) {
            for (i in 0 until 16) {
                val idx = offset + i * 4
                x[i] = (padded[idx].toInt() and 0xFF) or
                        ((padded[idx + 1].toInt() and 0xFF) shl 8) or
                        ((padded[idx + 2].toInt() and 0xFF) shl 16) or
                        ((padded[idx + 3].toInt() and 0xFF) shl 24)
            }

            val aa = a
            val bb = b
            val cc = c
            val dd = d

            // Round 1
            a = ff(a, b, c, d, x[0], 3);  d = ff(d, a, b, c, x[1], 7);  c = ff(c, d, a, b, x[2], 11); b = ff(b, c, d, a, x[3], 19)
            a = ff(a, b, c, d, x[4], 3);  d = ff(d, a, b, c, x[5], 7);  c = ff(c, d, a, b, x[6], 11); b = ff(b, c, d, a, x[7], 19)
            a = ff(a, b, c, d, x[8], 3);  d = ff(d, a, b, c, x[9], 7);  c = ff(c, d, a, b, x[10], 11); b = ff(b, c, d, a, x[11], 19)
            a = ff(a, b, c, d, x[12], 3); d = ff(d, a, b, c, x[13], 7); c = ff(c, d, a, b, x[14], 11); b = ff(b, c, d, a, x[15], 19)

            // Round 2
            a = gg(a, b, c, d, x[0], 3);  d = gg(d, a, b, c, x[4], 5);  c = gg(c, d, a, b, x[8], 9);  b = gg(b, c, d, a, x[12], 13)
            a = gg(a, b, c, d, x[1], 3);  d = gg(d, a, b, c, x[5], 5);  c = gg(c, d, a, b, x[9], 9);  b = gg(b, c, d, a, x[13], 13)
            a = gg(a, b, c, d, x[2], 3);  d = gg(d, a, b, c, x[6], 5);  c = gg(c, d, a, b, x[10], 9); b = gg(b, c, d, a, x[14], 13)
            a = gg(a, b, c, d, x[3], 3);  d = gg(d, a, b, c, x[7], 5);  c = gg(c, d, a, b, x[11], 9); b = gg(b, c, d, a, x[15], 13)

            // Round 3
            a = hh(a, b, c, d, x[0], 3);  d = hh(d, a, b, c, x[8], 9);  c = hh(c, d, a, b, x[4], 11); b = hh(b, c, d, a, x[12], 15)
            a = hh(a, b, c, d, x[2], 3);  d = hh(d, a, b, c, x[10], 9); c = hh(c, d, a, b, x[6], 11); b = hh(b, c, d, a, x[14], 15)
            a = hh(a, b, c, d, x[1], 3);  d = hh(d, a, b, c, x[9], 9);  c = hh(c, d, a, b, x[5], 11); b = hh(b, c, d, a, x[13], 15)
            a = hh(a, b, c, d, x[3], 3);  d = hh(d, a, b, c, x[11], 9); c = hh(c, d, a, b, x[7], 11); b = hh(b, c, d, a, x[15], 15)

            a += aa
            b += bb
            c += cc
            d += dd
        }

        val out = ByteArray(16)
        for (i in 0 until 4) {
            out[i] = ((a ushr (i * 8)) and 0xFF).toByte()
            out[i + 4] = ((b ushr (i * 8)) and 0xFF).toByte()
            out[i + 8] = ((c ushr (i * 8)) and 0xFF).toByte()
            out[i + 12] = ((d ushr (i * 8)) and 0xFF).toByte()
        }
        return out
    }
}

