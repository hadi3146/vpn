package com.aethervpn.vpncore.tun

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class TunnelPacketsTest {

    @Test
    fun testBroadcastAndMulticastFiltering() {
        val dhcpBroadcast = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 211.toByte(), 254.toByte(), 254.toByte()),
            dstIp = byteArrayOf(255.toByte(), 255.toByte(), 255.toByte(), 255.toByte()),
            srcPort = 67,
            dstPort = 68,
            payload = ByteArray(16)
        )
        assertTrue(TunnelPackets.isBroadcastOrMulticastIpv4(dhcpBroadcast))

        val subnetBroadcast = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 211.toByte(), 0, 1),
            dstIp = byteArrayOf(10, 211.toByte(), 255.toByte(), 255.toByte()),
            srcPort = 138,
            dstPort = 138,
            payload = ByteArray(8)
        )
        assertTrue(TunnelPackets.isBroadcastOrMulticastIpv4(subnetBroadcast))

        val multicastPkt = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(224.toByte(), 0, 0, 251.toByte()),
            srcPort = 5353,
            dstPort = 5353,
            payload = ByteArray(8)
        )
        assertTrue(TunnelPackets.isBroadcastOrMulticastIpv4(multicastPkt))

        val unicastDns = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 41234,
            dstPort = 53,
            payload = ByteArray(12)
        )
        assertFalse(TunnelPackets.isBroadcastOrMulticastIpv4(unicastDns))
    }

    @Test
    fun testQuicUdp443DetectionAndIcmpPortUnreachable() {
        val srcIp = byteArrayOf(10, 0, 0, 2)
        val dstIp = byteArrayOf(142.toByte(), 250.toByte(), 1, 1)
        val quicPkt = TunnelPackets.buildUdpIpv4Packet(
            srcIp = srcIp,
            dstIp = dstIp,
            srcPort = 50000,
            dstPort = 443,
            payload = byteArrayOf(0xC0.toByte(), 0x00, 0x00, 0x01)
        )
        assertTrue(TunnelPackets.isQuicUdp443(quicPkt))

        val dnsPkt = TunnelPackets.buildUdpIpv4Packet(
            srcIp = srcIp,
            dstIp = byteArrayOf(8, 8, 8, 8),
            srcPort = 50001,
            dstPort = 53,
            payload = byteArrayOf(0x01, 0x02)
        )
        assertFalse(TunnelPackets.isQuicUdp443(dnsPkt))

        // Mutate protocol to TCP (6) and confirm it's not treated as QUIC UDP
        val tcpLike = quicPkt.clone().apply { this[9] = 6 }
        assertFalse(TunnelPackets.isQuicUdp443(tcpLike))

        val icmp = TunnelPackets.buildIcmpPortUnreachable(quicPkt)
        assertNotNull(icmp)
        icmp!!
        assertEquals(1, icmp[9].toInt() and 0xFF) // ICMP
        assertArrayEquals(dstIp, icmp.copyOfRange(12, 16))
        assertArrayEquals(srcIp, icmp.copyOfRange(16, 20))
        assertEquals(3, icmp[20].toInt() and 0xFF) // Type 3: Destination Unreachable
        assertEquals(3, icmp[21].toInt() and 0xFF) // Code 3: Port Unreachable
        assertEquals(0, TunnelPackets.onesComplementChecksum(icmp, 0, 20))
        assertEquals(0, TunnelPackets.onesComplementChecksum(icmp, 20, icmp.size - 20))
    }

    @Test
    fun testDnsQueryBuildWrapAndExtract() {
        val query = TunnelPackets.buildDnsARecordQuery("cloudflare.com", 0xABCD)
        assertEquals(0xAB.toByte(), query[0])
        assertEquals(0xCD.toByte(), query[1])
        assertEquals(0x01.toByte(), query[5]) // QDCOUNT = 1

        val udpPacket = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 59853,
            dstPort = 53,
            payload = query
        )
        val header = TunnelPackets.extractUdpHeader(udpPacket)
        assertNotNull(header)
        header!!
        assertEquals(59853, header.srcPort)
        assertEquals(53, header.dstPort)
        assertEquals(query.size, header.payloadLength)
        assertArrayEquals(
            query,
            udpPacket.copyOfRange(header.payloadOffset, header.payloadOffset + header.payloadLength)
        )
    }

    @Test
    fun testParseDnsResponseSkipsSinkholeAndNonPublicIps() {
        // Response for "a.com" returning first 10.10.34.35 (censorship sinkhole), then 104.16.132.229
        val responseWithFallbackPublic = byteArrayOf(
            0x12, 0x34, // ID
            0x81.toByte(), 0x80.toByte(), // Standard response, no error
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, 0x00, 0x00,
            // Question: 1 'a' 3 'com' 0 + QTYPE=A + QCLASS=IN
            0x01, 'a'.code.toByte(), 0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
            // Answer 1: compressed ptr 0xC00C, Type A, Class IN, TTL 60, RDLEN 4, 10.10.34.35
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            10, 10, 34, 35,
            // Answer 2: compressed ptr 0xC00C, Type A, Class IN, TTL 60, RDLEN 4, 104.16.132.229
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            104, 16, 132.toByte(), 229.toByte()
        )
        val parsed = TunnelPackets.parseDnsARecordFirstPublicIpv4(responseWithFallbackPublic)
        assertEquals("104.16.132.229", parsed?.hostAddress)

        // Sinkhole-only response (10.10.34.35) must return null
        val sinkholeOnly = byteArrayOf(
            0x12, 0x34,
            0x81.toByte(), 0x80.toByte(),
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, 'a'.code.toByte(), 0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            10, 10, 34, 35
        )
        assertNull(TunnelPackets.parseDnsARecordFirstPublicIpv4(sinkholeOnly))

        // CGNAT 100.64.0.1 is non-public
        assertFalse(TunnelPackets.isPublicRoutableIpv4(InetAddress.getByAddress(byteArrayOf(100, 64, 0, 1))))
        assertTrue(TunnelPackets.isPublicRoutableIpv4(InetAddress.getByAddress(byteArrayOf(1, 1, 1, 1))))
    }

    @Test
    fun testExtractDnsQueryDomainAndSinkholeDetection() {
        val dnsQuery = TunnelPackets.buildDnsARecordQuery("Portal.Shaparak.IR", 0x4242)
        assertEquals("portal.shaparak.ir", TunnelPackets.extractDnsQueryDomain(dnsQuery))

        val udpPacket = TunnelPackets.buildUdpIpv4Packet(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 51000,
            dstPort = 53,
            payload = dnsQuery
        )
        assertTrue(TunnelPackets.isUdpPort53(udpPacket))

        val poisoned = byteArrayOf(
            0x42, 0x42, 0x81.toByte(), 0x80.toByte(),
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, 'a'.code.toByte(), 0x02, 'i'.code.toByte(), 'r'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            10, 10, 34, 35
        )
        assertTrue(TunnelPackets.containsNonPublicARecord(poisoned))

        val cleanIranResp = byteArrayOf(
            0x42, 0x42, 0x81.toByte(), 0x80.toByte(),
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x01, 'a'.code.toByte(), 0x02, 'i'.code.toByte(), 'r'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01,
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            185.toByte(), 167.toByte(), 73, 34
        )
        assertFalse(TunnelPackets.containsNonPublicARecord(cleanIranResp))
        assertEquals(60, TunnelPackets.extractDnsMinTtlSec(cleanIranResp))

        val qKey = TunnelPackets.extractDnsQueryKey(dnsQuery)
        assertNotNull(qKey)
        assertEquals("portal.shaparak.ir", qKey!!.domain)
        assertEquals(1, qKey.qType)
        assertEquals(1, qKey.qClass)
    }

    @Test
    fun testBuildIcmpv6AdminProhibitedBuildsValidPseudoHeaderChecksum() {
        val srcV6 = InetAddress.getByName("fd00:ae7:3::2").address
        val dstV6 = InetAddress.getByName("2606:4700:4700::1111").address
        val tcpSyncV6 = ByteArray(60).apply {
            this[0] = 0x60.toByte()
            this[4] = 0x00
            this[5] = 20 // payload len
            this[6] = 6  // TCP Next Header
            this[7] = 64
            System.arraycopy(srcV6, 0, this, 8, 16)
            System.arraycopy(dstV6, 0, this, 24, 16)
        }

        val icmpV6 = TunnelPackets.buildIcmpv6AdminProhibited(tcpSyncV6)
        assertNotNull(icmpV6)
        icmpV6!!
        assertEquals(6, (icmpV6[0].toInt() ushr 4) and 0x0F)
        assertEquals(58, icmpV6[6].toInt() and 0xFF) // ICMPv6
        assertArrayEquals(dstV6, icmpV6.copyOfRange(8, 24))
        assertArrayEquals(srcV6, icmpV6.copyOfRange(24, 40))
        assertEquals(1, icmpV6[40].toInt() and 0xFF) // Destination Unreachable
        assertEquals(1, icmpV6[41].toInt() and 0xFF) // Communication administratively prohibited
        val icmpLen = ((icmpV6[4].toInt() and 0xFF) shl 8) or (icmpV6[5].toInt() and 0xFF)
        assertEquals(68, icmpLen) // 8 byte ICMPv6 header + 60 byte quoted packet
        assertEquals(
            0,
            TunnelPackets.computeIpv6UpperChecksum(icmpV6, 40, icmpLen, icmpV6, 8, icmpV6, 24, 58)
        )

        // Multicast or ICMPv6 packets must not synthesize loops
        assertNull(TunnelPackets.buildIcmpv6AdminProhibited(icmpV6))
        val mcastV6 = tcpSyncV6.clone().apply { this[24] = 0xFF.toByte() }
        assertNull(TunnelPackets.buildIcmpv6AdminProhibited(mcastV6))
    }
}

