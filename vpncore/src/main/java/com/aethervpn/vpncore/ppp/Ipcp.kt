package com.aethervpn.vpncore.ppp

import java.net.Inet4Address
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class IpcpPacket(
    val code: Byte,
    val identifier: Byte,
    val options: List<IpcpOption> = emptyList()
) {
    companion object {
        const val CODE_CONFIGURE_REQUEST: Byte = 1
        const val CODE_CONFIGURE_ACK: Byte = 2
        const val CODE_CONFIGURE_NAK: Byte = 3
        const val CODE_CONFIGURE_REJECT: Byte = 4
        const val CODE_TERMINATE_REQUEST: Byte = 5
        const val CODE_TERMINATE_ACK: Byte = 6

        fun decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset): IpcpPacket {
            require(length >= 4) { "IPCP packet too short: $length" }
            val code = bytes[offset]
            val id = bytes[offset + 1]
            val totalLen = ((bytes[offset + 2].toInt() and 0xFF) shl 8) or (bytes[offset + 3].toInt() and 0xFF)
            require(length >= totalLen) { "IPCP packet length mismatch: expected $totalLen, got $length" }

            val options = mutableListOf<IpcpOption>()
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
                options.add(IpcpOption(optType, optVal))
                optOffset += optLen
            }

            return IpcpPacket(code, id, options)
        }
    }

    fun encode(): ByteArray {
        val payloadLen = options.sumOf { 2 + it.value.size }
        val totalLen = 4 + payloadLen
        val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
        buffer.put(code)
        buffer.put(identifier)
        buffer.putShort(totalLen.toShort())
        for (opt in options) {
            buffer.put(opt.type)
            buffer.put((2 + opt.value.size).toByte())
            buffer.put(opt.value)
        }
        return buffer.array()
    }
}

data class IpcpOption(
    val type: Byte,
    val value: ByteArray
) {
    companion object {
        const val OPTION_IP_ADDRESS: Byte = 3
        const val OPTION_PRIMARY_DNS: Byte = 129.toByte()
        const val OPTION_SECONDARY_DNS: Byte = 131.toByte()

        fun ipAddress(address: ByteArray = ByteArray(4)): IpcpOption {
            return IpcpOption(OPTION_IP_ADDRESS, address)
        }

        fun primaryDns(address: ByteArray = ByteArray(4)): IpcpOption {
            return IpcpOption(OPTION_PRIMARY_DNS, address)
        }

        fun secondaryDns(address: ByteArray = ByteArray(4)): IpcpOption {
            return IpcpOption(OPTION_SECONDARY_DNS, address)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IpcpOption) return false
        return type == other.type && value.contentEquals(other.value)
    }

    override fun hashCode(): Int = 31 * type.toInt() + value.contentHashCode()
}

