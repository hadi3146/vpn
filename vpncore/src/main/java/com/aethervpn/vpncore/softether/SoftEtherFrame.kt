package com.aethervpn.vpncore.softether

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * Handles Layer-2 Ethernet frame encapsulation and decapsulation for SoftEther VPN.
 * Translates between Android TUN Layer-3 IP packets and SoftEther Layer-2 Ethernet frames.
 */
object SoftEtherFrame {

    const val ETHERNET_HEADER_SIZE: Int = 14
    const val ETHER_TYPE_IPV4: Short = 0x0800.toShort()
    const val ETHER_TYPE_ARP: Short = 0x0806.toShort()

    val BROADCAST_MAC: ByteArray = byteArrayOf(
        0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(),
        0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()
    )

    /**
     * Generate a pseudo-random locally administered MAC address (00:AC:xx:xx:xx:xx).
     */
    fun generateClientMac(): ByteArray {
        val random = SecureRandom()
        val mac = ByteArray(6)
        mac[0] = 0x00.toByte()
        mac[1] = 0xAC.toByte() // Locally administered identifier
        random.nextBytes(mac)
        mac[0] = 0x00.toByte()
        mac[1] = 0xAC.toByte()
        return mac
    }

    /**
     * Encapsulates an IPv4 packet into an Ethernet frame.
     */
    fun wrapIpv4Packet(
        srcMac: ByteArray,
        dstMac: ByteArray,
        ipPacket: ByteArray,
        offset: Int,
        length: Int
    ): ByteArray {
        val frame = ByteArray(ETHERNET_HEADER_SIZE + length)
        // Dest MAC (6B)
        System.arraycopy(dstMac, 0, frame, 0, 6)
        // Src MAC (6B)
        System.arraycopy(srcMac, 0, frame, 6, 6)
        // EtherType IPv4 (0x0800) (2B)
        frame[12] = 0x08.toByte()
        frame[13] = 0x00.toByte()
        // IP Payload
        System.arraycopy(ipPacket, offset, frame, ETHERNET_HEADER_SIZE, length)
        return frame
    }

    /**
     * Checks if an incoming frame is an IPv4 frame and returns its payload length, trimming
     * Ethernet trailer padding if IPv4 Total Length is less than the Ethernet payload.
     * Returns -1 if frame is not IPv4 or malformed.
     */
    fun getIpv4PayloadLength(frame: ByteArray, offset: Int, length: Int): Int {
        if (length < ETHERNET_HEADER_SIZE + 20) return -1
        val etherType = (((frame[offset + 12].toInt() and 0xFF) shl 8) or (frame[offset + 13].toInt() and 0xFF)).toShort()
        if (etherType != ETHER_TYPE_IPV4) return -1

        val ipPayloadLen = length - ETHERNET_HEADER_SIZE
        if (ipPayloadLen < 20) return -1

        val ipOffset = offset + ETHERNET_HEADER_SIZE
        val ipTotalLen = (((frame[ipOffset + 2].toInt() and 0xFF) shl 8) or
                (frame[ipOffset + 3].toInt() and 0xFF))
        return if (ipTotalLen in 20..ipPayloadLen) ipTotalLen else ipPayloadLen
    }

    /**
     * Checks if an incoming frame is an IPv4 frame and returns its payload offset and length.
     * Trims any Ethernet trailer padding if IPv4 Total Length is less than the Ethernet payload.
     * Returns null if frame is not IPv4 (e.g. ARP or malformed).
     */
    fun unwrapIpv4Payload(frame: ByteArray, length: Int): ByteArray? {
        val actualLen = getIpv4PayloadLength(frame, 0, length)
        if (actualLen < 0) return null
        val ipPacket = ByteArray(actualLen)
        System.arraycopy(frame, ETHERNET_HEADER_SIZE, ipPacket, 0, actualLen)
        return ipPacket
    }

    /**
     * Check if the Ethernet destination MAC matches our client MAC, broadcast, or multicast.
     * Drops unicast frames addressed to other virtual machines/clients on the virtual switch.
     */
    fun isMatchingDestinationMac(frame: ByteArray, offset: Int, myMac: ByteArray): Boolean {
        // 1. Broadcast FF:FF:FF:FF:FF:FF
        if (frame[offset] == 0xFF.toByte() && frame[offset + 1] == 0xFF.toByte() &&
            frame[offset + 2] == 0xFF.toByte() && frame[offset + 3] == 0xFF.toByte() &&
            frame[offset + 4] == 0xFF.toByte() && frame[offset + 5] == 0xFF.toByte()
        ) {
            return true
        }
        // 2. Multicast (least significant bit of first octet is 1)
        if ((frame[offset].toInt() and 0x01) != 0) {
            return true
        }
        // 3. Unicast matching my client MAC
        for (i in 0 until 6) {
            if (frame[offset + i] != myMac[i]) return false
        }
        return true
    }

    fun isMatchingDestinationMac(frame: ByteArray, myMac: ByteArray): Boolean {
        if (frame.size < 6) return false
        return isMatchingDestinationMac(frame, 0, myMac)
    }

    /**
     * Compute a 5-tuple flow hash for an IPv4 packet to ensure packets belonging to the
     * same TCP/UDP connection are pinned to the same channel, avoiding TCP packet reordering.
     */
    fun computeFlowHash(ipPacket: ByteArray, offset: Int, length: Int): Int {
        if (length < 20) return 0
        val version = (ipPacket[offset].toInt() and 0xF0) ushr 4
        if (version != 4) return 0

        val proto = ipPacket[offset + 9].toInt() and 0xFF
        val srcIp = (((ipPacket[offset + 12].toInt() and 0xFF) shl 24) or
                ((ipPacket[offset + 13].toInt() and 0xFF) shl 16) or
                ((ipPacket[offset + 14].toInt() and 0xFF) shl 8) or
                (ipPacket[offset + 15].toInt() and 0xFF))
        val dstIp = (((ipPacket[offset + 16].toInt() and 0xFF) shl 24) or
                ((ipPacket[offset + 17].toInt() and 0xFF) shl 16) or
                ((ipPacket[offset + 18].toInt() and 0xFF) shl 8) or
                (ipPacket[offset + 19].toInt() and 0xFF))

        var hash = (srcIp * 31 + dstIp) * 31 + proto
        val ihl = (ipPacket[offset].toInt() and 0x0F) * 4
        if ((proto == 6 || proto == 17) && length >= ihl + 4) { // TCP or UDP
            val srcPort = (((ipPacket[offset + ihl].toInt() and 0xFF) shl 8) or (ipPacket[offset + ihl + 1].toInt() and 0xFF))
            val dstPort = (((ipPacket[offset + ihl + 2].toInt() and 0xFF) shl 8) or (ipPacket[offset + ihl + 3].toInt() and 0xFF))
            hash = (hash * 31 + srcPort) * 31 + dstPort
        }
        hash = hash xor (hash ushr 16)
        return hash
    }

    fun computeFlowHash(ipPacket: ByteArray, length: Int): Int = computeFlowHash(ipPacket, 0, length)
}

