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
        // RFC 2759 Section 9.2: Hash Example
        val user = "User"
        val password = "clientPass"
        val authChallenge = hexToBytes("5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28")
        val peerChallenge = hexToBytes("21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E")

        // Section 8.1: NtPasswordHash
        val ntHash = MsChapV2.ntPasswordHash(password)
        val expectedNtHash = hexToBytes("44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE")
        assertArrayEquals("NtPasswordHash mismatch", expectedNtHash, ntHash)

        // Section 8.2: ChallengeHash
        val challengeHash = MsChapV2.challengeHash(peerChallenge, authChallenge, user)
        val expectedChallengeHash = hexToBytes("D0 2E 43 86 BC E9 12 26")
        assertArrayEquals("ChallengeHash mismatch", expectedChallengeHash, challengeHash)

        // Section 8.5: GenerateNTResponse
        val ntResponse = MsChapV2.generateNtResponse(authChallenge, peerChallenge, user, password)
        val expectedNtResponse = hexToBytes("82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF")
        assertArrayEquals("NtResponse mismatch", expectedNtResponse, ntResponse)

        // Section 8.7: GenerateAuthenticatorResponse
        val authResp = MsChapV2.generateAuthenticatorResponse(
            password = password,
            ntResponse = ntResponse,
            peerChallenge = peerChallenge,
            authChallenge = authChallenge,
            userName = user
        )
        val expectedAuthResp = "S=407A5589115FD0D6209F510FE9C04566932CDA56"
        assertEquals("AuthenticatorResponse mismatch", expectedAuthResp, authResp)
    }
}

