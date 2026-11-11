package com.aethervpn.vpncore.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class MsChapV2Test {

    private fun hexToBytes(hex: String): ByteArray {
        val clean = hex.replace(" ", "")
        val result = ByteArray(clean.length / 2)
        for (i in result.indices) {
            result[i] = clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        return result
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02X".format(it) }
    }

    @Test
    fun testRfc2759TestVectors() {
        val user = "User"
        val password = "clientPass"
        val authChallenge = hexToBytes("5B 5D 61 F6 4E 63 80 26 64 BF 35 08 4C 2A B4 A2")
        val peerChallenge = hexToBytes("21 4A 26 31 7E 02 94 A5 63 60 C8 27 96 93 6C 45")

        // Section 8.1: NtPasswordHash
        val ntHash = MsChapV2.ntPasswordHash(password)
        val expectedNtHash = hexToBytes("CD 06 97 42 82 E0 E3 20 07 E0 F1 DD 72 35 6D 3A")
        assertArrayEquals("NtPasswordHash mismatch", expectedNtHash, ntHash)

        // Section 8.2: ChallengeHash
        val challengeHash = MsChapV2.challengeHash(peerChallenge, authChallenge, user)
        val expectedChallengeHash = hexToBytes("D9 2E 92 70 8A 41 85 11")
        assertArrayEquals("ChallengeHash mismatch", expectedChallengeHash, challengeHash)

        // Section 8.5: GenerateNTResponse
        val ntResponse = MsChapV2.generateNtResponse(authChallenge, peerChallenge, user, password)
        val expectedNtResponse = hexToBytes("82 30 9E CD 8D 70 8B 5E A0 8F AA 7B 81 25 34 76 3E 42 F4 7F BF 17 EB 59")
        assertArrayEquals("NtResponse mismatch", expectedNtResponse, ntResponse)

        // Section 8.7: GenerateAuthenticatorResponse
        val authResp = MsChapV2.generateAuthenticatorResponse(
            password = password,
            ntResponse = ntResponse,
            peerChallenge = peerChallenge,
            authChallenge = authChallenge,
            userName = user
        )
        val expectedAuthResp = "S=407A5589115E72E6F1A6A00295141FF29C6079F8"
        assertEquals("AuthenticatorResponse mismatch", expectedAuthResp, authResp)
    }
}
