package com.aethervpn.vpncore.softether

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * SoftEther PACK serialization and deserialization container.
 * Represents the binary key-value protocol structure used in SoftEther RPC and session handshakes.
 */
class SoftEtherPack {

    val intProperties: MutableMap<String, Int> = mutableMapOf()
    val longProperties: MutableMap<String, Long> = mutableMapOf()
    val stringProperties: MutableMap<String, String> = mutableMapOf()
    val bytesProperties: MutableMap<String, ByteArray> = mutableMapOf()
    val booleanProperties: MutableMap<String, Boolean> = mutableMapOf()
    val addressProperties: MutableMap<String, ByteArray> = mutableMapOf()

    companion object {
        private val LITTLE_ENDIAN_INT_KEYS = setOf(
            SoftEtherConstants.SEP_CLIENT_PORT,
            SoftEtherConstants.SEP_CLIENT_PRODUCT_BUILD,
            SoftEtherConstants.SEP_CLIENT_PRODUCT_VER,
            SoftEtherConstants.SEP_PROXY_PORT,
            SoftEtherConstants.SEP_SERVER_PORT2,
            SoftEtherConstants.SEP_SERVER_PRODUCT_BUILD,
            SoftEtherConstants.SEP_SERVER_PRODUCT_VER
        )

        private val ADDRESS_KEYS = setOf(
            SoftEtherConstants.SEP_CLIENT_IP_ADDRESS,
            SoftEtherConstants.SEP_PROXY_IP_ADDRESS,
            SoftEtherConstants.SEP_SERVER_IP_ADDRESS
        )

        fun decode(bytes: ByteArray): SoftEtherPack {
            val pack = SoftEtherPack()
            pack.readFrom(ByteBuffer.wrap(bytes))
            return pack
        }
    }

    /**
     * Total serialized length in bytes.
     */
    fun calculateLength(): Int {
        var total = 4 // numElements (4B)

        // Boolean properties (serialized as VALUE_INT)
        for ((key, _) in booleanProperties) {
            total += 4 + key.length + 4 + 4 + 4 // keyLen(4) + key + type(4) + count(4) + int(4)
        }

        // Int properties
        for ((key, _) in intProperties) {
            total += 4 + key.length + 4 + 4 + 4
        }

        // Address properties (serialized as 4B reversed int)
        for ((key, _) in addressProperties) {
            total += 4 + key.length + 4 + 4 + 4
        }

        // Long properties
        for ((key, _) in longProperties) {
            total += 4 + key.length + 4 + 4 + 8
        }

        // Bytes properties
        for ((key, value) in bytesProperties) {
            total += 4 + key.length + 4 + 4 + 4 + value.size // + valueLen(4) + bytes
        }

        // String properties (ASCII / UTF-8)
        for ((key, value) in stringProperties) {
            val strBytes = value.toByteArray(Charsets.UTF_8)
            total += 4 + key.length + 4 + 4 + 4 + strBytes.size
        }

        return total
    }

    fun encode(): ByteArray {
        val totalLength = calculateLength()
        val buffer = ByteBuffer.allocate(totalLength)
        buffer.order(ByteOrder.BIG_ENDIAN)

        val totalElements = booleanProperties.size +
                intProperties.size +
                addressProperties.size +
                longProperties.size +
                bytesProperties.size +
                stringProperties.size

        buffer.putInt(totalElements)

        // Write Booleans
        for ((key, value) in booleanProperties) {
            writeHeader(buffer, key, SoftEtherConstants.VALUE_INT, 1)
            buffer.putInt(if (value) 1 else 0)
        }

        // Write Ints
        for ((key, value) in intProperties) {
            writeHeader(buffer, key, SoftEtherConstants.VALUE_INT, 1)
            if (key in LITTLE_ENDIAN_INT_KEYS) {
                buffer.putInt(Integer.reverseBytes(value))
            } else {
                buffer.putInt(value)
            }
        }

        // Write Addresses (IPv4 4-byte reversed array)
        for ((key, addr) in addressProperties) {
            writeHeader(buffer, key, SoftEtherConstants.VALUE_INT, 1)
            if (addr.size == 4) {
                buffer.put(addr[3])
                buffer.put(addr[2])
                buffer.put(addr[1])
                buffer.put(addr[0])
            } else {
                buffer.putInt(0)
            }
        }

        // Write Longs
        for ((key, value) in longProperties) {
            writeHeader(buffer, key, SoftEtherConstants.VALUE_INT64, 1)
            buffer.putLong(value)
        }

        // Write Bytes
        for ((key, value) in bytesProperties) {
            writeHeader(buffer, key, SoftEtherConstants.VALUE_DATA, 1)
            buffer.putInt(value.size)
            buffer.put(value)
        }

        // Write Strings
        for ((key, value) in stringProperties) {
            val strBytes = value.toByteArray(Charsets.UTF_8)
            writeHeader(buffer, key, SoftEtherConstants.VALUE_STR, 1)
            buffer.putInt(strBytes.size)
            buffer.put(strBytes)
        }

        return buffer.array()
    }

    private fun writeHeader(buffer: ByteBuffer, key: String, valueType: Int, count: Int) {
        val keyBytes = key.toByteArray(Charsets.US_ASCII)
        buffer.putInt(keyBytes.size + 1) // SoftEther expects key length + 1 (null-term count)
        buffer.put(keyBytes)
        buffer.putInt(valueType)
        buffer.putInt(count)
    }

    fun readFrom(buffer: ByteBuffer) {
        buffer.order(ByteOrder.BIG_ENDIAN)
        if (buffer.remaining() < 4) return
        val totalElements = buffer.int
        if (totalElements < 0 || totalElements > 10000) return

        for (i in 0 until totalElements) {
            if (buffer.remaining() < 4) break
            val keyLenWithNull = buffer.int
            val keyLen = keyLenWithNull - 1
            if (keyLen < 0 || keyLen > buffer.remaining()) break

            val keyBytes = ByteArray(keyLen)
            buffer.get(keyBytes)
            val key = String(keyBytes, Charsets.US_ASCII)

            if (buffer.remaining() < 8) break
            val valueType = buffer.int
            val count = buffer.int

            when (valueType) {
                SoftEtherConstants.VALUE_INT -> {
                    if (buffer.remaining() < 4) break
                    val rawInt = buffer.int
                    when {
                        key in ADDRESS_KEYS -> {
                            val addr = ByteArray(4)
                            addr[0] = (rawInt and 0xFF).toByte()
                            addr[1] = ((rawInt ushr 8) and 0xFF).toByte()
                            addr[2] = ((rawInt ushr 16) and 0xFF).toByte()
                            addr[3] = ((rawInt ushr 24) and 0xFF).toByte()
                            addressProperties[key] = addr
                        }
                        key.startsWith("use_") || key.endsWith("_use_encryption") || key.endsWith("_fast_disconnect_detect") -> {
                            booleanProperties[key] = rawInt != 0
                        }
                        key in LITTLE_ENDIAN_INT_KEYS -> {
                            intProperties[key] = Integer.reverseBytes(rawInt)
                        }
                        else -> {
                            intProperties[key] = rawInt
                        }
                    }
                }
                SoftEtherConstants.VALUE_INT64 -> {
                    if (buffer.remaining() < 8) break
                    longProperties[key] = buffer.long
                }
                SoftEtherConstants.VALUE_DATA -> {
                    if (buffer.remaining() < 4) break
                    val dataLen = buffer.int
                    if (dataLen in 0..buffer.remaining()) {
                        val data = ByteArray(dataLen)
                        buffer.get(data)
                        bytesProperties[key] = data
                    }
                }
                SoftEtherConstants.VALUE_STR, SoftEtherConstants.VALUE_UNISTR -> {
                    if (buffer.remaining() < 4) break
                    val strLen = buffer.int
                    if (strLen in 0..buffer.remaining()) {
                        val strBytes = ByteArray(strLen)
                        buffer.get(strBytes)
                        stringProperties[key] = String(strBytes, Charsets.UTF_8)
                    }
                }
                else -> {
                    // Unknown type: if count or data length present, try to safely skip
                    break
                }
            }
        }
    }
}

