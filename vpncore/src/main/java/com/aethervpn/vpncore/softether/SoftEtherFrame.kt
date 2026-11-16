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
     * Checks if an incoming frame is an IPv4 frame and returns its payload offset and length.
     * Returns null if frame is not IPv4 (e.g. ARP or malformed).
     */
    fun unwrapIpv4Payload(frame: ByteArray, length: Int): ByteArray? {
        if (length < ETHERNET_HEADER_SIZE + 20) return null
        val etherType = (((frame[12].toInt() and 0xFF) shl 8) or (frame[13].toInt() and 0xFF)).toShort()
        if (etherType != ETHER_TYPE_IPV4) return null

        val ipPayloadLen = length - ETHERNET_HEADER_SIZE
        val ipPacket = ByteArray(ipPayloadLen)
        System.arraycopy(frame, ETHERNET_HEADER_SIZE, ipPacket, 0, ipPayloadLen)
        return ipPacket
    }
}

