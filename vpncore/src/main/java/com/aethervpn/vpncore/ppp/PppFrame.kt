package com.aethervpn.vpncore.ppp

import java.nio.ByteBuffer
import java.nio.ByteOrder

data class PppFrame(
    val protocol: Short,
    val payload: ByteArray
) {
    companion object {
        const val PROTO_IP: Short = 0x0021
        const val PROTO_IPV6: Short = 0x0057
        const val PROTO_IPCP: Short = 0x8021.toShort()
        const val PROTO_IPV6CP: Short = 0x8057.toShort()
        const val PROTO_LCP: Short = 0xC021.toShort()
        const val PROTO_PAP: Short = 0xC023.toShort()
        const val PROTO_CHAP: Short = 0xC223.toShort()

        fun decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): PppFrame {
            require(length >= 2) { "PPP frame too short: $length bytes" }
            val first = bytes[offset].toInt() and 0xFF
            val protocol: Short
            val headerLen: Int
            // Handle compressed protocol field if lowest bit of first byte is 1
            if ((first and 0x01) != 0) {
                protocol = first.toShort()
                headerLen = 1
            } else {
                protocol = (((first shl 8) or (bytes[offset + 1].toInt() and 0xFF))).toShort()
                headerLen = 2
            }
            val payloadLen = length - headerLen
            val payload = ByteArray(payloadLen)
            System.arraycopy(bytes, offset + headerLen, payload, 0, payloadLen)
            return PppFrame(protocol, payload)
        }
    }

    fun encode(): ByteArray {
        val buffer = ByteBuffer.allocate(2 + payload.size).order(ByteOrder.BIG_ENDIAN)
        buffer.putShort(protocol)
        buffer.put(payload)
        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PppFrame) return false
        return protocol == other.protocol && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int = 31 * protocol.toInt() + payload.contentHashCode()
}

