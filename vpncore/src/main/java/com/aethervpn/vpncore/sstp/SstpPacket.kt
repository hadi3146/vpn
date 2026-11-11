package com.aethervpn.vpncore.sstp

import java.nio.ByteBuffer
import java.nio.ByteOrder

sealed class SstpPacket {
    companion object {
        const val VERSION_1_0: Byte = 0x10
        const val FLAG_DATA: Byte = 0x00
        const val FLAG_CONTROL: Byte = 0x01

        const val MSG_CALL_CONNECT_REQUEST: Short = 0x0001
        const val MSG_CALL_CONNECT_ACK: Short = 0x0002
        const val MSG_CALL_CONNECT_NAK: Short = 0x0003
        const val MSG_CALL_CONNECTED: Short = 0x0004
        const val MSG_CALL_ABORT: Short = 0x0005
        const val MSG_CALL_DISCONNECT: Short = 0x0006
        const val MSG_CALL_DISCONNECT_ACK: Short = 0x0007
        const val MSG_ECHO_REQUEST: Short = 0x0008
        const val MSG_ECHO_RESPONSE: Short = 0x0009

        fun decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size): SstpPacket {
            require(length >= 4) { "Packet too short: $length bytes" }
            val version = bytes[offset]
            val flags = bytes[offset + 1]
            val len = ((bytes[offset + 2].toInt() and 0x0F) shl 8) or (bytes[offset + 3].toInt() and 0xFF)
            require(length >= len) { "Incomplete packet: expected $len bytes, got $length" }

            val isControl = (flags.toInt() and 0x01) != 0
            return if (isControl) {
                require(len >= 8) { "Control packet too short: $len bytes" }
                val buffer = ByteBuffer.wrap(bytes, offset + 4, len - 4).order(ByteOrder.BIG_ENDIAN)
                val msgType = buffer.short
                val numAttributes = buffer.short.toInt() and 0xFFFF
                val attributes = mutableListOf<SstpAttribute>()
                while (buffer.remaining() >= 4) {
                    val reserved = buffer.get()
                    val attribId = buffer.get()
                    val attribLen = buffer.short.toInt() and 0x0FFF
                    val valLen = attribLen - 4
                    val value = ByteArray(valLen)
                    if (valLen > 0 && buffer.remaining() >= valLen) {
                        buffer.get(value)
                    }
                    attributes.add(SstpAttribute(attribId, value))
                }
                ControlPacket(msgType, attributes, version)
            } else {
                val payload = ByteArray(len - 4)
                System.arraycopy(bytes, offset + 4, payload, 0, len - 4)
                DataPacket(payload, version)
            }
        }
    }

    abstract fun encode(): ByteArray

    data class DataPacket(
        val payload: ByteArray,
        val version: Byte = VERSION_1_0
    ) : SstpPacket() {
        override fun encode(): ByteArray {
            val totalLen = 4 + payload.size
            val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
            buffer.put(version)
            buffer.put(FLAG_DATA)
            buffer.putShort((totalLen and 0x0FFF).toShort())
            buffer.put(payload)
            return buffer.array()
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is DataPacket) return false
            return payload.contentEquals(other.payload) && version == other.version
        }

        override fun hashCode(): Int = 31 * payload.contentHashCode() + version
    }

    data class ControlPacket(
        val messageType: Short,
        val attributes: List<SstpAttribute> = emptyList(),
        val version: Byte = VERSION_1_0
    ) : SstpPacket() {
        override fun encode(): ByteArray {
            var attribTotalLen = 0
            for (attr in attributes) {
                attribTotalLen += 4 + attr.value.size
            }
            val totalLen = 8 + attribTotalLen
            val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)
            buffer.put(version)
            buffer.put(FLAG_CONTROL)
            buffer.putShort((totalLen and 0x0FFF).toShort())
            buffer.putShort(messageType)
            buffer.putShort(attributes.size.toShort())
            for (attr in attributes) {
                buffer.put(0x00) // Reserved
                buffer.put(attr.id)
                buffer.putShort(((attr.value.size + 4) and 0x0FFF).toShort())
                buffer.put(attr.value)
            }
            return buffer.array()
        }
    }
}

data class SstpAttribute(
    val id: Byte,
    val value: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SstpAttribute) return false
        return id == other.id && value.contentEquals(other.value)
    }

    override fun hashCode(): Int = 31 * id.toInt() + value.contentHashCode()

    companion object {
        const val ATTRIB_NO_ERROR: Byte = 0x00
        const val ATTRIB_ENCAPSULATED_PROTOCOL_ID: Byte = 0x01
        const val ATTRIB_STATUS_INFO: Byte = 0x02
        const val ATTRIB_CRYPTO_BINDING: Byte = 0x04
        const val ATTRIB_CRYPTO_BINDING_REQ: Byte = 0x08

        fun encapsulatedPpp(): SstpAttribute {
            // Protocol ID 0x0001 = PPP
            return SstpAttribute(ATTRIB_ENCAPSULATED_PROTOCOL_ID, byteArrayOf(0x00, 0x01))
        }
    }
}

