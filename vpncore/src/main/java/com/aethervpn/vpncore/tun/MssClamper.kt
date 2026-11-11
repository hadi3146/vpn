package com.aethervpn.vpncore.tun

import java.nio.ByteBuffer
import java.nio.ByteOrder

object MssClamper {

    /**
     * Checks if the given IPv4 packet is a TCP SYN packet.
     * If so, and if MSS option is present and > maxMss, clamps it down to maxMss
     * and updates the TCP checksum.
     */
    fun clampMss(packet: ByteArray, length: Int, maxMss: Int) {
        if (length < 40) return
        val versionAndIhl = packet[0].toInt() and 0xFF
        if ((versionAndIhl ushr 4) != 4) return // Not IPv4
        val ihl = (versionAndIhl and 0x0F) * 4
        if (length < ihl + 20) return
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 6) return // Not TCP

        val tcpOffset = ihl
        val flags = packet[tcpOffset + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0
        if (!isSyn) return

        val dataOffset = ((packet[tcpOffset + 12].toInt() and 0xF0) ushr 4) * 4
        if (dataOffset <= 20 || length < tcpOffset + dataOffset) return

        // Scan TCP options for MSS (kind = 2, length = 4)
        var optIdx = tcpOffset + 20
        val optEnd = tcpOffset + dataOffset
        while (optIdx < optEnd) {
            val kind = packet[optIdx].toInt() and 0xFF
            if (kind == 0) break // End of option list
            if (kind == 1) { // NOP
                optIdx++
                continue
            }
            if (optIdx + 1 >= optEnd) break
            val optLen = packet[optIdx + 1].toInt() and 0xFF
            if (optLen < 2 || optIdx + optLen > optEnd) break

            if (kind == 2 && optLen == 4) {
                // MSS option found
                val currentMss = ((packet[optIdx + 2].toInt() and 0xFF) shl 8) or (packet[optIdx + 3].toInt() and 0xFF)
                if (currentMss > maxMss) {
                    val oldVal = currentMss
                    val newVal = maxMss
                    packet[optIdx + 2] = ((newVal ushr 8) and 0xFF).toByte()
                    packet[optIdx + 3] = (newVal and 0xFF).toByte()

                    // Update TCP Checksum incrementally (RFC 1624: ~C' = ~(~C + ~m + m'))
                    updateTcpChecksum(packet, tcpOffset, oldVal, newVal)
                }
                break
            }
            optIdx += optLen
        }
    }

    private fun updateTcpChecksum(packet: ByteArray, tcpOffset: Int, oldWord: Int, newWord: Int) {
        val oldChecksum = ((packet[tcpOffset + 16].toInt() and 0xFF) shl 8) or (packet[tcpOffset + 17].toInt() and 0xFF)
        var sum = oldChecksum xor 0xFFFF
        sum += (oldWord xor 0xFFFF)
        sum += newWord
        while (sum shr 16 != 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val newChecksum = (sum xor 0xFFFF) and 0xFFFF
        packet[tcpOffset + 16] = ((newChecksum ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 17] = (newChecksum and 0xFF).toByte()
    }
}

