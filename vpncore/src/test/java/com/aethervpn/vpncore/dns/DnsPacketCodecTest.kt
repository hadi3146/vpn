package com.aethervpn.vpncore.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

class DnsPacketCodecTest {

    @Test
    fun testExtractAndBuildUdpDnsPacket() {
        val dnsQuery = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 'w'.code.toByte(), 'w'.code.toByte(), 'w'.code.toByte(), 0x00,
            0x00, 0x01, 0x00, 0x01
        )
        val udpLen = 8 + dnsQuery.size
        val totalLen = 20 + udpLen
        val packet = ByteArray(totalLen)
        packet[0] = 0x45.toByte()
        packet[2] = ((totalLen ushr 8) and 0xFF).toByte()
        packet[3] = (totalLen and 0xFF).toByte()
        packet[8] = 64
        packet[9] = 17 // UDP
        // src 10.211.1.12 -> dst 1.1.1.1
        packet[12] = 10; packet[13] = 211.toByte(); packet[14] = 1; packet[15] = 12
        packet[16] = 1; packet[17] = 1; packet[18] = 1; packet[19] = 1
        // srcPort 54321 -> dstPort 53
        packet[20] = (54321 ushr 8).toByte(); packet[21] = (54321 and 0xFF).toByte()
        packet[22] = 0; packet[23] = 53
        packet[24] = (udpLen ushr 8).toByte(); packet[25] = (udpLen and 0xFF).toByte()
        System.arraycopy(dnsQuery, 0, packet, 28, dnsQuery.size)

        val parsed = DnsPacketCodec.extractUdpDnsQuery(packet, totalLen)
        assertNotNull(parsed)
        assertEquals(54321, parsed!!.srcPort)
        assertEquals(53, parsed.dstPort)
        assertArrayEquals(dnsQuery, parsed.dnsPayload)

        val fakeResponse = dnsQuery.clone()
        fakeResponse[2] = 0x81.toByte()
        fakeResponse[3] = 0x80.toByte()

        val respPacket = DnsPacketCodec.buildUdpDnsResponse(parsed, fakeResponse)
        assertEquals(20 + 8 + fakeResponse.size, respPacket.size)
        assertEquals(17, respPacket[9].toInt() and 0xFF)
        // Verify swapped IP src=1.1.1.1, dst=10.211.1.12
        assertEquals(1, respPacket[12].toInt() and 0xFF)
        assertEquals(10, respPacket[16].toInt() and 0xFF)
        // Verify swapped ports src=53, dst=54321
        assertEquals(53, ((respPacket[20].toInt() and 0xFF) shl 8) or (respPacket[21].toInt() and 0xFF))
        assertEquals(54321, ((respPacket[22].toInt() and 0xFF) shl 8) or (respPacket[23].toInt() and 0xFF))
    }

    @Test
    fun testNonDnsPortReturnsNull() {
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte()
        packet[9] = 17
        packet[22] = 0x01; packet[23] = 0xBB.toByte() // Port 443
        assertNull(DnsPacketCodec.extractUdpDnsQuery(packet, 40))
    }
}

