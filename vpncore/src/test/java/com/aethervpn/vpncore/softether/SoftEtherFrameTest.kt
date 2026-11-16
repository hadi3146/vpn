package com.aethervpn.vpncore.softether

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.nio.ByteBuffer

class SoftEtherFrameTest {

    @Test
    fun testGenerateClientMac() {
        val mac = SoftEtherFrame.generateClientMac()
        assertEquals(6, mac.size)
        assertEquals(0x00.toByte(), mac[0])
        assertEquals(0xAC.toByte(), mac[1])
    }

    @Test
    fun testWrapAndUnwrapIpv4Packet() {
        val srcMac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x44)
        val dstMac = byteArrayOf(0x00, 0xAC.toByte(), 0x55, 0x66, 0x77, 0x88.toByte())

        // Sample dummy IPv4 packet (20 bytes header + 10 bytes payload)
        val dummyIp = ByteArray(30) { it.toByte() }
        dummyIp[0] = 0x45.toByte() // IPv4

        val frame = SoftEtherFrame.wrapIpv4Packet(srcMac, dstMac, dummyIp, 0, dummyIp.size)
        assertEquals(14 + 30, frame.size)

        // Verify MACs and EtherType
        assertArrayEquals(dstMac, frame.sliceArray(0..5))
        assertArrayEquals(srcMac, frame.sliceArray(6..11))
        assertEquals(0x08.toByte(), frame[12])
        assertEquals(0x00.toByte(), frame[13])

        // Unwrap
        val unwrapped = SoftEtherFrame.unwrapIpv4Payload(frame, frame.size)
        assertNotNull(unwrapped)
        assertArrayEquals(dummyIp, unwrapped)
    }

    @Test
    fun testUnwrapNonIpv4FrameReturnsNull() {
        val nonIpFrame = ByteArray(40)
        nonIpFrame[12] = 0x08.toByte()
        nonIpFrame[13] = 0x06.toByte() // ARP
        assertNull(SoftEtherFrame.unwrapIpv4Payload(nonIpFrame, nonIpFrame.size))
    }

    @Test
    fun testBuildDhcpDiscoverFrame() {
        val mac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x44)
        val discoverFrame = SoftEtherDhcp.buildDiscoverFrame(mac, 0x12345678)
        assertTrue(discoverFrame.size >= 300)

        // Check broadcast destination MAC
        assertArrayEquals(SoftEtherFrame.BROADCAST_MAC, discoverFrame.sliceArray(0..5))
        // Check source MAC
        assertArrayEquals(mac, discoverFrame.sliceArray(6..11))
        // Check EtherType IPv4
        assertEquals(0x08.toByte(), discoverFrame[12])
        assertEquals(0x00.toByte(), discoverFrame[13])
    }

    @Test
    fun testDefaultFallbackConfig() {
        val mac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x44)
        val fallback = SoftEtherDhcp.defaultFallbackConfig(mac)
        assertEquals("192.168.30.15", fallback.clientIp)
        assertEquals("255.255.255.0", fallback.netmask)
        assertEquals("192.168.30.1", fallback.gateway)
        assertTrue(fallback.dnsServers.contains("8.8.8.8"))
    }

    @Test
    fun testDestinationMacMatching() {
        val myMac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x44)
        val otherMac = byteArrayOf(0x00, 0xAC.toByte(), 0x55, 0x66, 0x77, 0x88.toByte())
        val broadcastMac = SoftEtherFrame.BROADCAST_MAC
        val multicastMac = byteArrayOf(0x01, 0x00, 0x5E.toByte(), 0x00, 0x00, 0x01)

        val frameUnicastToMe = ByteArray(20).apply { System.arraycopy(myMac, 0, this, 0, 6) }
        val frameUnicastToOther = ByteArray(20).apply { System.arraycopy(otherMac, 0, this, 0, 6) }
        val frameBroadcast = ByteArray(20).apply { System.arraycopy(broadcastMac, 0, this, 0, 6) }
        val frameMulticast = ByteArray(20).apply { System.arraycopy(multicastMac, 0, this, 0, 6) }

        assertTrue(SoftEtherFrame.isMatchingDestinationMac(frameUnicastToMe, myMac))
        assertTrue(SoftEtherFrame.isMatchingDestinationMac(frameBroadcast, myMac))
        assertTrue(SoftEtherFrame.isMatchingDestinationMac(frameMulticast, myMac))
        org.junit.Assert.assertFalse(SoftEtherFrame.isMatchingDestinationMac(frameUnicastToOther, myMac))
    }

    @Test
    fun testUnwrapTrimsEthernetPadding() {
        val myMac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x44)
        val routerMac = byteArrayOf(0x00, 0xAC.toByte(), 0x01, 0x02, 0x03, 0x04)

        // 28-byte IP packet (e.g. TCP ACK) padded to 60 bytes on Ethernet wire
        val rawIp = ByteArray(28) { 0 }
        rawIp[0] = 0x45.toByte()
        rawIp[2] = 0x00 // Total length = 28
        rawIp[3] = 28

        val paddedFrame = ByteArray(14 + 60)
        System.arraycopy(myMac, 0, paddedFrame, 0, 6)
        System.arraycopy(routerMac, 0, paddedFrame, 6, 6)
        paddedFrame[12] = 0x08.toByte()
        paddedFrame[13] = 0x00.toByte()
        System.arraycopy(rawIp, 0, paddedFrame, 14, 28) // Remaining 32 bytes are 0x00 padding

        val extracted = SoftEtherFrame.unwrapIpv4Payload(paddedFrame, paddedFrame.size)
        assertNotNull(extracted)
        assertEquals(28, extracted!!.size)
        assertEquals(28, extracted[3].toInt())
    }
}

