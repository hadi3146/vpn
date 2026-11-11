package com.aethervpn.vpncore.ppp

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class LcpPacket(
    val code: Byte,
    val identifier: Byte,
    val options: List<LcpOption> = emptyList(),
    val rawData: ByteArray? = null
) {
    companion object {
        const val CODE_CONFIGURE_REQUEST: Byte = 1
        const val CODE_CONFIGURE_ACK: Byte = 2
        const val CODE_CONFIGURE_NAK: Byte = 3
        const val CODE_CONFIGURE_REJECT: Byte = 4
        const val CODE_TERMINATE_REQUEST: Byte = 5
        const val CODE_TERMINATE_ACK: Byte = 6
        const val CODE_CODE_REJECT: Byte = 7
        const val CODE_PROTOCOL_REJECT: Byte = 8
        const val CODE_ECHO_REQUEST: Byte = 9
        const val CODE_ECHO_REPLY: Byte = 10
        const val CODE_DISCARD_REQUEST: Byte = 11

        fun decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): LcpPacket {
            require(length >= 4) { "LCP packet too short: $length" }
            val code = bytes[offset]
            val id = bytes[offset + 1]
            val totalLen = ((bytes[offset + 2].toInt() and 0xFF) shl 8) or (bytes[offset + 3].toInt() and 0xFF)
            require(length >= totalLen) { "LCP packet length mismatch: expected $totalLen, got $length" }

            val options = mutableListOf<LcpOption>()
            var optOffset = offset + 4
            val endOffset = offset + totalLen
            while (optOffset < endOffset) {
                if (endOffset - optOffset < 2) break
                val optType = bytes[optOffset]
                val optLen = bytes[optOffset + 1].toInt() and 0xFF
                if (optLen < 2 || optOffset + optLen > endOffset) break
                val valLen = optLen - 2
                val optVal = ByteArray(valLen)
                System.arraycopy(bytes, optOffset + 2, optVal, 0, valLen)
                options.add(LcpOption(optType, optVal))
                optOffset += optLen
            }

            return LcpPacket(code, id, options)
        }
    }

    fun encode(): ByteArray {
        val payloadLen = if (rawData != null) {
            rawData.size
        } else {
            options.sumOf { 2 + it.value.size }
        }
        val totalLen = 4 + payloadLen
        val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
        buffer.put(code)
        buffer.put(identifier)
        buffer.putShort(totalLen.toShort())
        if (rawData != null) {
            buffer.put(rawData)
        } else {
            for (opt in options) {
                buffer.put(opt.type)
                buffer.put((2 + opt.value.size).toByte())
                buffer.put(opt.value)
            }
        }
        return buffer.array()
    }
}

data class LcpOption(
    val type: Byte,
    val value: ByteArray
) {
    companion object {
        const val OPTION_MRU: Byte = 1
        const val OPTION_AUTH_PROTOCOL: Byte = 3
        const val OPTION_QUALITY_PROTOCOL: Byte = 4
        const val OPTION_MAGIC_NUMBER: Byte = 5
        const val OPTION_PFC: Byte = 7
        const val OPTION_ACFC: Byte = 8

        fun mru(mru: Int): LcpOption {
            return LcpOption(
                OPTION_MRU,
                byteArrayOf(((mru ushr 8) and 0xFF).toByte(), (mru and 0xFF).toByte())
            )
        }

        fun magicNumber(magic: Int): LcpOption {
            val buf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN)
            buf.putInt(magic)
            return LcpOption(OPTION_MAGIC_NUMBER, buf.array())
        }

        fun authMsChapV2(): LcpOption {
            // Protocol 0xC223, Algorithm 0x81 (MS-CHAPv2)
            return LcpOption(
                OPTION_AUTH_PROTOCOL,
                byteArrayOf(0xC2.toByte(), 0x23.toByte(), 0x81.toByte())
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LcpOption) return false
        return type == other.type && value.contentEquals(other.value)
    }

    override fun hashCode(): Int = 31 * type.toInt() + value.contentHashCode()
}

