package com.aethervpn.vpncore.tun

import java.net.Inet4Address
import java.net.InetAddress

data class DnsQueryKey(
    val domain: String,
    val qType: Int,
    val qClass: Int
)

data class UdpPacketHeader(
    val srcIp: ByteArray,
    val dstIp: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val ipHeaderLen: Int,
    val udpLength: Int,
    val payloadOffset: Int,
    val payloadLength: Int
)

/**
 * Stateless IPv4 / IPv6 / UDP / ICMP / DNS wire-packet helpers shared across TUN handling,
 * in-tunnel connectivity probing, IPv6 leak blocking, QUIC fallback, and DoT/DoH resolution.
 */
object TunnelPackets {
    private const val IP_PROTO_ICMP = 1
    private const val IP_PROTO_UDP = 17
    private const val IP_PROTO_ICMPV6 = 58
    private const val QUIC_PORT = 443
    private const val ICMPV6_MAX_QUOTED_BYTES = 1232

    fun isBroadcastOrMulticastIpv4(packet: ByteArray, length: Int = packet.size): Boolean =
        isBroadcastOrMulticastIpv4(packet, 0, length)

    fun isBroadcastOrMulticastIpv4(packet: ByteArray, offset: Int, length: Int): Boolean {
        if (length < 20 || packet.size < offset + length) return false
        val version = (packet[offset].toInt() ushr 4) and 0x0F
        if (version != 4) return false

        val d0 = packet[offset + 16].toInt() and 0xFF
        val d1 = packet[offset + 17].toInt() and 0xFF
        val d2 = packet[offset + 18].toInt() and 0xFF
        val d3 = packet[offset + 19].toInt() and 0xFF

        if (d0 in 224..239) return true
        if (d0 == 255 && d1 == 255 && d2 == 255 && d3 == 255) return true
        // SoftEther hubs frequently broadcast DHCP / NetBIOS chatter to subnet .255
        if (d3 == 255 && (packet[offset + 9].toInt() and 0xFF) == IP_PROTO_UDP) {
            val udp = extractUdpHeader(packet, offset, length) ?: return false
            if (udp.srcPort in setOf(67, 68, 137, 138) || udp.dstPort in setOf(67, 68, 137, 138)) {
                return true
            }
        }
        return false
    }

    fun extractUdpHeader(packet: ByteArray, length: Int = packet.size): UdpPacketHeader? =
        extractUdpHeader(packet, 0, length)

    fun extractUdpHeader(packet: ByteArray, offset: Int, length: Int): UdpPacketHeader? {
        if (length < 28 || packet.size < offset + length) return null
        val version = (packet[offset].toInt() ushr 4) and 0x0F
        if (version != 4) return null

        val ihl = (packet[offset].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl + 8) return null
        if ((packet[offset + 9].toInt() and 0xFF) != IP_PROTO_UDP) return null

        // Skip non-initial IP fragments
        val fragFlagsAndOffset = ((packet[offset + 6].toInt() and 0x3F) shl 8) or (packet[offset + 7].toInt() and 0xFF)
        if (fragFlagsAndOffset != 0) return null

        val srcPort = ((packet[offset + ihl].toInt() and 0xFF) shl 8) or (packet[offset + ihl + 1].toInt() and 0xFF)
        val dstPort = ((packet[offset + ihl + 2].toInt() and 0xFF) shl 8) or (packet[offset + ihl + 3].toInt() and 0xFF)
        val udpLen = ((packet[offset + ihl + 4].toInt() and 0xFF) shl 8) or (packet[offset + ihl + 5].toInt() and 0xFF)
        val payloadEnd = minOf(length, ihl + udpLen)
        val payloadOffset = offset + ihl + 8
        if (payloadEnd < ihl + 8) return null

        return UdpPacketHeader(
            srcIp = packet.copyOfRange(offset + 12, offset + 16),
            dstIp = packet.copyOfRange(offset + 16, offset + 20),
            srcPort = srcPort,
            dstPort = dstPort,
            ipHeaderLen = ihl,
            udpLength = udpLen,
            payloadOffset = payloadOffset,
            payloadLength = payloadEnd - (ihl + 8)
        )
    }

    fun isQuicUdp443(packet: ByteArray, length: Int = packet.size): Boolean {
        val udp = extractUdpHeader(packet, 0, length) ?: return false
        return udp.dstPort == QUIC_PORT
    }

    fun isUdpPort53(packet: ByteArray, length: Int = packet.size): Boolean {
        val udp = extractUdpHeader(packet, 0, length) ?: return false
        return udp.dstPort == 53 && udp.payloadLength >= 12
    }

    /**
     * Extracts the canonical DNS question key (lowercase domain, QTYPE, QCLASS) from a wire DNS packet.
     */
    fun extractDnsQueryKey(dnsPacket: ByteArray): DnsQueryKey? {
        if (dnsPacket.size < 18) return null
        val qdCount = ((dnsPacket[4].toInt() and 0xFF) shl 8) or (dnsPacket[5].toInt() and 0xFF)
        if (qdCount < 1) return null

        var pos = 12
        val sb = StringBuilder()
        var labels = 0
        while (pos < dnsPacket.size && labels < 64) {
            val len = dnsPacket[pos++].toInt() and 0xFF
            if (len == 0) {
                if (sb.isEmpty() || pos + 4 > dnsPacket.size) return null
                val qType = ((dnsPacket[pos].toInt() and 0xFF) shl 8) or (dnsPacket[pos + 1].toInt() and 0xFF)
                val qClass = ((dnsPacket[pos + 2].toInt() and 0xFF) shl 8) or (dnsPacket[pos + 3].toInt() and 0xFF)
                return DnsQueryKey(sb.toString().lowercase(), qType, qClass)
            }
            if ((len and 0xC0) != 0 || pos + len > dnsPacket.size) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until len) {
                sb.append((dnsPacket[pos + i].toInt() and 0xFF).toChar())
            }
            pos += len
            labels++
        }
        return null
    }

    /**
     * Extracts the lowercase query domain name (without trailing dot) from a wire-format DNS packet.
     */
    fun extractDnsQueryDomain(dnsPacket: ByteArray): String? = extractDnsQueryKey(dnsPacket)?.domain

    /**
     * Returns the minimum TTL across answer RRs in a wire DNS response, or null when unparseable/no answers.
     */
    fun extractDnsMinTtlSec(dnsResponse: ByteArray): Int? {
        if (dnsResponse.size < 12) return null
        val rcode = dnsResponse[3].toInt() and 0x0F
        if (rcode != 0) return null
        val qdCount = ((dnsResponse[4].toInt() and 0xFF) shl 8) or (dnsResponse[5].toInt() and 0xFF)
        val anCount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        if (anCount <= 0) return null

        var offset = 12
        repeat(qdCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return null
            if (offset + 4 > dnsResponse.size) return null
            offset += 4
        }

        var minTtl = Int.MAX_VALUE
        repeat(anCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return null
            if (offset + 10 > dnsResponse.size) return null
            val ttl = ((dnsResponse[offset + 4].toInt() and 0xFF) shl 24) or
                ((dnsResponse[offset + 5].toInt() and 0xFF) shl 16) or
                ((dnsResponse[offset + 6].toInt() and 0xFF) shl 8) or
                (dnsResponse[offset + 7].toInt() and 0xFF)
            val rdLength = ((dnsResponse[offset + 8].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 9].toInt() and 0xFF)
            offset += 10
            if (offset + rdLength > dnsResponse.size) return null
            if (ttl >= 0 && ttl < minTtl) minTtl = ttl
            offset += rdLength
        }
        return if (minTtl == Int.MAX_VALUE) null else minTtl
    }

    /**
     * Returns true if a wire-format DNS response contains any private/bogon/CGNAT IPv4 A record
     * (such as ISP DNS censorship sinkholes like 10.10.34.35).
     */
    fun containsNonPublicARecord(dnsResponse: ByteArray): Boolean {
        if (dnsResponse.size < 12) return false
        val qdCount = ((dnsResponse[4].toInt() and 0xFF) shl 8) or (dnsResponse[5].toInt() and 0xFF)
        val anCount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        if (anCount <= 0) return false

        var offset = 12
        repeat(qdCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return false
            if (offset + 4 > dnsResponse.size) return false
            offset += 4
        }

        repeat(anCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return false
            if (offset + 10 > dnsResponse.size) return false
            val type = ((dnsResponse[offset].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 1].toInt() and 0xFF)
            val clazz = ((dnsResponse[offset + 2].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 3].toInt() and 0xFF)
            val rdLength = ((dnsResponse[offset + 8].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 9].toInt() and 0xFF)
            offset += 10
            if (offset + rdLength > dnsResponse.size) return false

            if (type == 1 && clazz == 1 && rdLength == 4) {
                val addr = InetAddress.getByAddress(dnsResponse.copyOfRange(offset, offset + 4))
                if (!isPublicRoutableIpv4(addr)) return true
            }
            offset += rdLength
        }
        return false
    }

    /**
     * Synthesizes an RFC 792 ICMP Destination/Port Unreachable (Type 3, Code 3) packet
     * for a blocked outbound IPv4 packet so apps fall back immediately from QUIC UDP:443
     * to TCP TLS:443 instead of stalling on UDP handshake timeouts.
     */
    fun buildIcmpPortUnreachable(ipv4Packet: ByteArray, length: Int = ipv4Packet.size): ByteArray? {
        if (length < 28 || ipv4Packet.size < length) return null
        val version = (ipv4Packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val origIhl = (ipv4Packet[0].toInt() and 0x0F) * 4
        if (origIhl < 20 || length < origIhl + 8) return null

        val quotedLen = minOf(length, origIhl + 8)
        val icmpLen = 8 + quotedLen
        val totalLen = 20 + icmpLen
        val out = ByteArray(totalLen)

        out[0] = 0x45.toByte()
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[5] = 0x02
        out[6] = 0x40.toByte()
        out[8] = 64.toByte()
        out[9] = IP_PROTO_ICMP.toByte()

        // Swap src and dst IP so local app socket receives ICMP error from target server IP
        System.arraycopy(ipv4Packet, 16, out, 12, 4)
        System.arraycopy(ipv4Packet, 12, out, 16, 4)

        val ipCsum = onesComplementChecksum(out, 0, 20)
        out[10] = ((ipCsum ushr 8) and 0xFF).toByte()
        out[11] = (ipCsum and 0xFF).toByte()

        // ICMP Type 3 (Destination Unreachable), Code 3 (Port Unreachable)
        out[20] = 3.toByte()
        out[21] = 3.toByte()
        System.arraycopy(ipv4Packet, 0, out, 28, quotedLen)

        val icmpCsum = onesComplementChecksum(out, 20, icmpLen)
        out[22] = ((icmpCsum ushr 8) and 0xFF).toByte()
        out[23] = (icmpCsum and 0xFF).toByte()
        return out
    }

    fun buildDnsARecordQuery(domain: String, transactionId: Int): ByteArray {
        val labels = domain.trim().trimEnd('.').split('.').filter { it.isNotEmpty() }
        val qnameLen = labels.sumOf { 1 + it.length } + 1
        val out = ByteArray(12 + qnameLen + 4)
        out[0] = ((transactionId ushr 8) and 0xFF).toByte()
        out[1] = (transactionId and 0xFF).toByte()
        out[2] = 0x01 // Standard recursive query
        out[5] = 0x01 // QDCOUNT = 1

        var pos = 12
        for (label in labels) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out[pos++] = (bytes.size and 0x3F).toByte()
            System.arraycopy(bytes, 0, out, pos, bytes.size)
            pos += bytes.size
        }
        out[pos++] = 0x00 // Root label
        out[pos++] = 0x00; out[pos++] = 0x01 // QTYPE = A (1)
        out[pos++] = 0x00; out[pos] = 0x01   // QCLASS = IN (1)
        return out
    }

    fun buildUdpIpv4Packet(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4) { "IPv4 addresses must be 4 bytes" }
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)

        out[0] = 0x45.toByte()
        out[2] = ((totalLen ushr 8) and 0xFF).toByte()
        out[3] = (totalLen and 0xFF).toByte()
        out[5] = 0x03
        out[6] = 0x40.toByte()
        out[8] = 64.toByte()
        out[9] = IP_PROTO_UDP.toByte()
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)

        val ipCsum = onesComplementChecksum(out, 0, 20)
        out[10] = ((ipCsum ushr 8) and 0xFF).toByte()
        out[11] = (ipCsum and 0xFF).toByte()

        out[20] = ((srcPort ushr 8) and 0xFF).toByte()
        out[21] = (srcPort and 0xFF).toByte()
        out[22] = ((dstPort ushr 8) and 0xFF).toByte()
        out[23] = (dstPort and 0xFF).toByte()
        out[24] = ((udpLen ushr 8) and 0xFF).toByte()
        out[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(payload, 0, out, 28, payload.size)

        val udpCsum = computeUdpChecksum(out, 20, udpLen, srcIp, dstIp)
        val finalUdpCsum = if (udpCsum == 0) 0xFFFF else udpCsum
        out[26] = ((finalUdpCsum ushr 8) and 0xFF).toByte()
        out[27] = (finalUdpCsum and 0xFF).toByte()
        return out
    }

    /**
     * Parses a wire-format DNS response and returns the first non-reserved public IPv4 A record,
     * ignoring any bogon/private sinkhole IP addresses.
     */
    fun parseDnsARecordFirstPublicIpv4(dnsResponse: ByteArray): Inet4Address? {
        if (dnsResponse.size < 12) return null
        val rcode = dnsResponse[3].toInt() and 0x0F
        if (rcode != 0) return null

        val qdCount = ((dnsResponse[4].toInt() and 0xFF) shl 8) or (dnsResponse[5].toInt() and 0xFF)
        val anCount = ((dnsResponse[6].toInt() and 0xFF) shl 8) or (dnsResponse[7].toInt() and 0xFF)
        if (anCount <= 0) return null

        var offset = 12
        repeat(qdCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return null
            if (offset + 4 > dnsResponse.size) return null
            offset += 4
        }

        repeat(anCount) {
            offset = skipDnsName(dnsResponse, offset) ?: return null
            if (offset + 10 > dnsResponse.size) return null
            val type = ((dnsResponse[offset].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 1].toInt() and 0xFF)
            val clazz = ((dnsResponse[offset + 2].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 3].toInt() and 0xFF)
            val rdLength = ((dnsResponse[offset + 8].toInt() and 0xFF) shl 8) or (dnsResponse[offset + 9].toInt() and 0xFF)
            offset += 10
            if (offset + rdLength > dnsResponse.size) return null

            if (type == 1 && clazz == 1 && rdLength == 4) {
                val addr = InetAddress.getByAddress(dnsResponse.copyOfRange(offset, offset + 4))
                if (addr is Inet4Address && isPublicRoutableIpv4(addr)) {
                    return addr
                }
            }
            offset += rdLength
        }
        return null
    }

    fun isPublicRoutableIpv4(addr: InetAddress): Boolean {
        if (addr !is Inet4Address) return false
        if (addr.isAnyLocalAddress || addr.isLoopbackAddress || addr.isSiteLocalAddress ||
            addr.isLinkLocalAddress || addr.isMulticastAddress
        ) {
            return false
        }
        val b = addr.address
        val first = b[0].toInt() and 0xFF
        val second = b[1].toInt() and 0xFF
        // Filter CGNAT 100.64.0.0/10 and 0.0.0.0/8 as non-public
        if (first == 0) return false
        if (first == 100 && second in 64..127) return false
        return true
    }

    fun isPublicRoutableIpv4(ipStr: String?): Boolean {
        if (ipStr.isNullOrBlank()) return false
        return try {
            val addr = InetAddress.getByName(ipStr.trim())
            isPublicRoutableIpv4(addr)
        } catch (_: Exception) {
            false
        }
    }

    private fun skipDnsName(buf: ByteArray, start: Int): Int? {
        var pos = start
        var jumps = 0
        while (pos < buf.size && jumps < 16) {
            val len = buf[pos].toInt() and 0xFF
            if (len == 0) return pos + 1
            if ((len and 0xC0) == 0xC0) {
                return if (pos + 2 <= buf.size) pos + 2 else null
            }
            pos += 1 + len
            jumps++
        }
        return null
    }

    /**
     * Synthesizes an RFC 4443 ICMPv6 Destination Unreachable (Type 1, Code 1: communication
     * administratively prohibited) packet so apps fail fast from IPv6 to tunneled IPv4.
     */
    fun buildIcmpv6AdminProhibited(ipv6Packet: ByteArray, length: Int = ipv6Packet.size): ByteArray? {
        if (length < 40 || ipv6Packet.size < length) return null
        val version = (ipv6Packet[0].toInt() ushr 4) and 0x0F
        if (version != 6) return null
        // Skip replying to ICMPv6 errors or multicast destinations to avoid loops
        if ((ipv6Packet[6].toInt() and 0xFF) == IP_PROTO_ICMPV6 || (ipv6Packet[24].toInt() and 0xFF) == 0xFF) {
            return null
        }

        val quotedLen = minOf(length, ICMPV6_MAX_QUOTED_BYTES)
        val icmpv6Len = 8 + quotedLen
        val out = ByteArray(40 + icmpv6Len)

        // IPv6 Header: Version 6, Next Header = ICMPv6 (58), Hop Limit = 64
        out[0] = 0x60.toByte()
        out[4] = ((icmpv6Len ushr 8) and 0xFF).toByte()
        out[5] = (icmpv6Len and 0xFF).toByte()
        out[6] = IP_PROTO_ICMPV6.toByte()
        out[7] = 64.toByte()

        // Swap 16-byte src/dst IPv6 addresses
        System.arraycopy(ipv6Packet, 24, out, 8, 16)
        System.arraycopy(ipv6Packet, 8, out, 24, 16)

        // ICMPv6 Type 1 (Destination Unreachable), Code 1 (Administratively Prohibited), 4 bytes unused
        out[40] = 1.toByte()
        out[41] = 1.toByte()
        System.arraycopy(ipv6Packet, 0, out, 48, quotedLen)

        val csum = computeIpv6UpperChecksum(out, 40, icmpv6Len, out, 8, out, 24, IP_PROTO_ICMPV6)
        out[42] = ((csum ushr 8) and 0xFF).toByte()
        out[43] = (csum and 0xFF).toByte()
        return out
    }

    fun onesComplementChecksum(buf: ByteArray, offset: Int, len: Int): Int {
        return foldOnesComplement(sumBytes16(buf, offset, len))
    }

    private fun computeUdpChecksum(
        packet: ByteArray,
        udpOffset: Int,
        udpLen: Int,
        srcIp: ByteArray,
        dstIp: ByteArray
    ): Int {
        var sum = sumBytes16(srcIp, 0, 4) + sumBytes16(dstIp, 0, 4)
        sum += IP_PROTO_UDP
        sum += udpLen
        sum += sumBytes16(packet, udpOffset, udpLen)
        return foldOnesComplement(sum)
    }

    internal fun computeIpv6UpperChecksum(
        packet: ByteArray,
        payloadOffset: Int,
        payloadLen: Int,
        srcBuf: ByteArray,
        srcOffset: Int,
        dstBuf: ByteArray,
        dstOffset: Int,
        nextHeader: Int
    ): Int {
        var sum = sumBytes16(srcBuf, srcOffset, 16) + sumBytes16(dstBuf, dstOffset, 16)
        sum += (payloadLen ushr 16) and 0xFFFF
        sum += payloadLen and 0xFFFF
        sum += nextHeader
        sum += sumBytes16(packet, payloadOffset, payloadLen)
        return foldOnesComplement(sum)
    }

    private fun sumBytes16(buf: ByteArray, offset: Int, len: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + len
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        return sum
    }

    private fun foldOnesComplement(initialSum: Int): Int {
        var sum = initialSum
        while ((sum ushr 16) != 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}

