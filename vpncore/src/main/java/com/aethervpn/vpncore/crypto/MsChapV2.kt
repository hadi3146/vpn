package com.aethervpn.vpncore.crypto

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Locale

object MsChapV2 {

    private val secureRandom = SecureRandom()

    private val MAGIC_SERVER_1 = "Magic server to client signing constant".toByteArray(StandardCharsets.US_ASCII)
    private val MAGIC_SERVER_2 = "Pad to make it do more than one iteration".toByteArray(StandardCharsets.US_ASCII)
    private val MAGIC_CLIENT_1 = "Magic client to server signing constant".toByteArray(StandardCharsets.US_ASCII)

    private val MAGIC_MASTER_KEY = "This is the master key".toByteArray(StandardCharsets.US_ASCII)
    private val MAGIC_SEND_KEY = "On the client side, this is the send key; on the server side, it is the receive key."
        .toByteArray(StandardCharsets.US_ASCII)
    private val MAGIC_RECV_KEY = "On the client side, this is the receive key; on the server side, it is the send key."
        .toByteArray(StandardCharsets.US_ASCII)

    private val SHA_PAD_1 = ByteArray(40) { 0x00.toByte() }
    private val SHA_PAD_2 = ByteArray(40) { 0xF2.toByte() }

    fun generatePeerChallenge(): ByteArray {
        val challenge = ByteArray(16)
        secureRandom.nextBytes(challenge)
        return challenge
    }

    /**
     * RFC 2759 Section 8.1: NtPasswordHash
     * MD4(UTF-16LE(Password))
     */
    fun ntPasswordHash(password: String): ByteArray {
        val unicode = password.toByteArray(StandardCharsets.UTF_16LE)
        return Md4.digest(unicode)
    }

    /**
     * RFC 2759 Section 8.3: HashNtPasswordHash
     * MD4(NtPasswordHash)
     */
    fun hashNtPasswordHash(passwordHash: ByteArray): ByteArray {
        return Md4.digest(passwordHash)
    }

    /**
     * RFC 2759 Section 8.2: ChallengeHash
     * SHA1(PeerChallenge[16] + AuthChallenge[16] + UserName)[0..7]
     */
    fun challengeHash(peerChallenge: ByteArray, authChallenge: ByteArray, userName: String): ByteArray {
        val cleanUserName = userName.substringAfterLast('\\')
        val md = MessageDigest.getInstance("SHA-1")
        md.update(peerChallenge, 0, 16)
        md.update(authChallenge, 0, 16)
        md.update(cleanUserName.toByteArray(StandardCharsets.US_ASCII))
        val full = md.digest()
        val result = ByteArray(8)
        System.arraycopy(full, 0, result, 0, 8)
        return result
    }

    /**
     * RFC 2759 Section 8.5: GenerateNTResponse
     */
    fun generateNtResponse(
        authChallenge: ByteArray,
        peerChallenge: ByteArray,
        userName: String,
        password: String
    ): ByteArray {
        val challenge = challengeHash(peerChallenge, authChallenge, userName)
        val passwordHash = ntPasswordHash(password)
        val passwordHash21 = ByteArray(21)
        System.arraycopy(passwordHash, 0, passwordHash21, 0, 16)
        return Des.challengeResponse(challenge, passwordHash21)
    }

    /**
     * RFC 2759 Section 8.7: GenerateAuthenticatorResponse
     * Returns "S=" followed by 40 hex digits (uppercase).
     */
    fun generateAuthenticatorResponse(
        password: String,
        ntResponse: ByteArray,
        peerChallenge: ByteArray,
        authChallenge: ByteArray,
        userName: String
    ): String {
        val passwordHash = ntPasswordHash(password)
        val passwordHashHash = hashNtPasswordHash(passwordHash)

        val md = MessageDigest.getInstance("SHA-1")
        md.update(passwordHashHash, 0, 16)
        md.update(ntResponse, 0, 24)
        md.update(MAGIC_SERVER_1)
        val digest = md.digest()

        val challenge = challengeHash(peerChallenge, authChallenge, userName)

        md.reset()
        md.update(digest, 0, 20)
        md.update(challenge, 0, 8)
        md.update(MAGIC_SERVER_2)
        val authResp = md.digest()

        val hex = StringBuilder("S=")
        for (b in authResp) {
            hex.append(String.format(Locale.US, "%02X", b))
        }
        return hex.toString()
    }

    /**
     * RFC 3079 Section 3.1: MasterKey
     * Returns 16 bytes master key.
     */
    fun getMasterKey(passwordHashHash: ByteArray, ntResponse: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        md.update(passwordHashHash, 0, 16)
        md.update(ntResponse, 0, 24)
        md.update(MAGIC_MASTER_KEY)
        val full = md.digest()
        val masterKey = ByteArray(16)
        System.arraycopy(full, 0, masterKey, 0, 16)
        return masterKey
    }

    /**
     * RFC 3079 Section 3.2: Asymmetric Keys
     * Derives SendKey (isSend = true) or ReceiveKey (isSend = false).
     */
    fun getAsymmetricKey(masterKey: ByteArray, isSend: Boolean): ByteArray {
        val md = MessageDigest.getInstance("SHA-1")
        md.update(masterKey, 0, 16)
        md.update(SHA_PAD_1)
        md.update(if (isSend) MAGIC_SEND_KEY else MAGIC_RECV_KEY)
        md.update(SHA_PAD_2)
        val full = md.digest()
        val key = ByteArray(16)
        System.arraycopy(full, 0, key, 0, 16)
        return key
    }
}

