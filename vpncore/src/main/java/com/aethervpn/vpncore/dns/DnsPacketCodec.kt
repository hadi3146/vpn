package com.aethervpn.vpncore.dns

data class ParsedUdpDnsPacket(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val dnsPayload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ParsedUdpDnsPacket) return false
        return srcIp.contentEquals(other.srcIp) &&
            dstIp.contentEquals(other.dstIp) &&
            srcPort == other.srcPort &&
            dstPort == other.dstPort &&
            dnsPayload.contentEquals(other.dnsPayload)
    }

    override fun hashCode(): Int {
        var result = srcIp.contentHashCode()
        result = 31 * result + dstIp.contentHashCode()
        result = 31 * result + srcPort
        result = 31 * result + dstPort
        result = 31 * result + dnsPayload.contentHashCode()
        return result
    }
}

object DnsPacketCodec {
    private const val IP_PROTO_UDP = 17
    private const val DNS_PORT = 53

    fun extractUdpDnsQuery(packet: ByteArray, length: Int = packet.size): ParsedUdpDnsPacket? {
        if (length < 28 || length > packet.size) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != IP_PROTO_UDP) return null

        // Ignore fragmented UDP packets (MF flag or non-zero fragment offset)
        val fragFlagsAndOffset = ((packet[6].toInt() and 0x3F) shl 8) or (packet[7].toInt() and 0xFF)
        if (fragFlagsAndOffset != 0) return null

        val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        if (dstPort != DNS_PORT) return null

        val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
        val udpLen = ((packet[ihl + 4].toInt() and 0xFF) shl 8) or (packet[ihl + 5].toInt() and 0xFF)
        val payloadEnd = minOf(length, ihl + udpLen)
        if (payloadEnd - (ihl + 8) < 12) return null

        val srcIp = packet.copyOfRange(12, 16)
        val dstIp = packet.copyOfRange(16, 20)
        val dnsPayload = packet.copyOfRange(ihl + 8, payloadEnd)

        return ParsedUdpDnsPacket(srcIp, dstIp, srcPort, dstPort, dnsPayload)
    }

    fun buildUdpDnsResponse(request: ParsedUdpDnsPacket, dnsResponse: ByteArray): ByteArray {
        val udpLen = 8 + dnsResponse.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        out[0] = 0x45.toByte() // Version 4, IHL 5 (20 bytes)
        out[1] = 0x00 // TOS
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[4] = 0x00
        out[5] = 0x01
        out[6] = 0x40.toByte() // Don't Fragment
        out[7] = 0x00
        out[8] = 64.toByte() // TTL
        out[9] = IP_PROTO_UDP.toByte()
        out[10] = 0x00 // IP Checksum placeholder
        out[11] = 0x00

        // Swap src and dst IP (response comes from original dstIp -> original srcIp)
        System.arraycopy(request.dstIp, 0, out, 12, 4)
        System.arraycopy(request.srcIp, 0, out, 16, 4)

        val ipChecksum = onesComplementChecksum(out, 0, 20)
        out[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        out[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header (8 bytes) at offset 20 (swap srcPort <-> dstPort)
        out[20] = ((request.dstPort ushr 8) and 0xFF).toByte()
        out[21] = (request.dstPort and 0xFF).toByte()
        out[22] = ((request.srcPort ushr 8) and 0xFF).toByte()
        out[23] = (request.srcPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        out[26] = 0x00 // UDP Checksum placeholder
        out[27] = 0x00

        System.arraycopy(dnsResponse, 0, out, 28, dnsResponse.size)

        val udpChecksum = computeUdpChecksum(out, 20, udpLen, request.dstIp, request.srcIp)
        val finalUdpChecksum = if (udpChecksum == 0) 0xFFFF else udpChecksum
        out[26] = ((finalUdpChecksum ushr 8) and 0xFF).toByte()
        out[27] = (finalUdpChecksum and 0xFF).toByte()

        return out
    }

    private fun onesComplementChecksum(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            val word = ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }

    private fun computeUdpChecksum(
        packet: ByteArray,
        udpOffset: Int,
        udpLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ): Int {
        var sum = 0
        // Pseudo-header: srcIp (4) + dstIp (4) + zero/proto (2) + udpLen (2)
        for (i in 0 until 4 step 2) {
            sum += ((srcIp[i].toInt() and 0xFF) shl 8) or (srcIp[i + 1].toInt() and 0xFF)
            sum += ((dstIp[i].toInt() and 0xFF) shl 8) or (dstIp[i + 1].toInt() and 0xFF)
        }
        sum += IP_PROTO_UDP
        sum += udpLen

        var i = udpOffset
        val end = udpOffset + udpLen
        while (i + 1 < end) {
            val word = ((packet[i].toInt() and 0xFF) shl 8) or (packet[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            sum += (packet[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}

