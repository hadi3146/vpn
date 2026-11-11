package com.aethervpn.vpncore.ppp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

data class ChapPacket(
    val code: Byte,
    val identifier: Byte,
    val data: ByteArray
) {
    companion object {
        const val CODE_CHALLENGE: Byte = 1
        const val CODE_RESPONSE: Byte = 2
        const val CODE_SUCCESS: Byte = 3
        const val CODE_FAILURE: Byte = 4

        fun decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): ChapPacket {
            require(length >= 4) { "CHAP packet too short: $length" }
            val code = bytes[offset]
            val id = bytes[offset + 1]
            val totalLen = ((bytes[offset + 2].toInt() and 0xFF) shl 8) or (bytes[offset + 3].toInt() and 0xFF)
            require(length >= totalLen) { "CHAP length mismatch: expected $totalLen, got $length" }

            val dataLen = totalLen - 4
            val data = ByteArray(dataLen)
            System.arraycopy(bytes, offset + 4, data, 0, dataLen)
            return ChapPacket(code, id, data)
        }

        fun buildMsChapV2Response(
            id: Byte,
            peerChallenge: ByteArray,
            ntResponse: ByteArray,
            userName: String
        ): ChapPacket {
            val userBytes = userName.toByteArray(StandardCharsets.US_ASCII)
            val valueSize = 16 + 8 + 24 + 1 // 49 bytes
            val totalDataLen = 1 + valueSize + userBytes.size
            val buf = ByteBuffer.allocate(totalDataLen).order(ByteOrder.BIG_ENDIAN)

            buf.put(valueSize.toByte()) // Value-Size: 49
            buf.put(peerChallenge, 0, 16) // PeerChallenge: 16
            buf.put(ByteArray(8)) // Reserved: 8 zeros
            buf.put(ntResponse, 0, 24) // NT-Response: 24
            buf.put(0x00) // Flags: 1 zero byte
            buf.put(userBytes) // Name: username

            return ChapPacket(CODE_RESPONSE, id, buf.array())
        }
    }

    fun encode(): ByteArray {
        val totalLen = 4 + data.size
        val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
        buffer.put(code)
        buffer.put(identifier)
        buffer.putShort(totalLen.toShort())
        buffer.put(data)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ChapPacket) return false
        return code == other.code && identifier == other.identifier && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = code.toInt()
        result = 31 * result + identifier.toInt()
        result = 31 * result + data.contentHashCode()
        return result
    }
}

