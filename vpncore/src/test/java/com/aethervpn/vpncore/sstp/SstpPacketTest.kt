package com.aethervpn.vpncore.sstp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class SstpPacketTest {

    @Test
    fun testClientSnapshotTrafficStartsZeroAndAcceptsInterceptor() {
        val listener = object : SstpEventListener {
            override fun onStateChanged(state: SstpState, message: String?) {}
            override fun onParametersEstablished(params: VpnParameters) {}
            override fun onDataPacketReceived(packet: ByteArray) {}
            override fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {}
            override fun onError(t: Throwable) {}
        }
        val client = SstpClient(
            config = SstpConfig(host = "vpn.example.com", ipAddress = InetAddress.getByAddress(byteArrayOf(1, 2, 3, 4))),
            socketProtector = null,
            listener = listener
        )
        val snap = client.snapshotTraffic()
        assertEquals(0L, snap.txPackets)
        assertEquals(0L, snap.rxUnicastPackets)
        assertEquals(0L, snap.lastAnyRxMs)
        assertEquals(0L, snap.lastUnicastIpRxMs)

        client.setProbeInterceptor { true }
        client.setProbeInterceptor(null)
    }

    @Test
    fun testDataPacketEncodeDecode() {
        val payload = byteArrayOf(0x00, 0x21, 0x45, 0x00, 0x00, 0x54)
        val dataPacket = SstpPacket.DataPacket(payload)
        val encoded = dataPacket.encode()

        assertEquals(4 + payload.size, encoded.size)
        assertEquals(SstpPacket.VERSION_1_0, encoded[0])
        assertEquals(SstpPacket.FLAG_DATA, encoded[1])

        val decoded = SstpPacket.decode(encoded)
        assertTrue(decoded is SstpPacket.DataPacket)
        val decodedData = decoded as SstpPacket.DataPacket
        assertArrayEquals(payload, decodedData.payload)
    }

    @Test
    fun testDirectFramingMatchesLegacyPppAndSstpEncoding() {
        val sampleIpPacket = byteArrayOf(
            0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x02,
            0x08, 0x08, 0x08, 0x08
        )
        // Legacy multi-allocation framing
        val pppFrame = com.aethervpn.vpncore.ppp.PppFrame(com.aethervpn.vpncore.ppp.PppFrame.PROTO_IP, sampleIpPacket)
        val legacySstp = SstpPacket.DataPacket(pppFrame.encode()).encode()

        // Direct fast framing
        val totalLen = 8 + sampleIpPacket.size
        val fastHeader = byteArrayOf(
            SstpPacket.VERSION_1_0,
            SstpPacket.FLAG_DATA,
            ((totalLen ushr 8) and 0x0F).toByte(),
            (totalLen and 0xFF).toByte(),
            0xFF.toByte(),
            0x03.toByte(),
            0x00,
            0x21
        )
        val directFraming = fastHeader + sampleIpPacket

        assertArrayEquals(legacySstp, directFraming)
    }

    @Test
    fun testControlPacketEncodeDecode() {
        val attr = SstpAttribute.encapsulatedPpp()
        val ctrlPacket = SstpPacket.ControlPacket(
            messageType = SstpPacket.MSG_CALL_CONNECT_REQUEST,
            attributes = listOf(attr)
        )
        val encoded = ctrlPacket.encode()

        assertEquals(SstpPacket.VERSION_1_0, encoded[0])
        assertEquals(SstpPacket.FLAG_CONTROL, encoded[1])

        val decoded = SstpPacket.decode(encoded)
        assertTrue(decoded is SstpPacket.ControlPacket)
        val decodedCtrl = decoded as SstpPacket.ControlPacket
        assertEquals(SstpPacket.MSG_CALL_CONNECT_REQUEST, decodedCtrl.messageType)
        assertEquals(1, decodedCtrl.attributes.size)
        assertEquals(SstpAttribute.ATTRIB_ENCAPSULATED_PROTOCOL_ID, decodedCtrl.attributes[0].id)
        assertArrayEquals(byteArrayOf(0x00, 0x01), decodedCtrl.attributes[0].value)
    }

    @Test
    fun testEchoRequestEncodeDecode() {
        val echo = SstpPacket.ControlPacket(messageType = SstpPacket.MSG_ECHO_REQUEST)
        val encoded = echo.encode()
        val decoded = SstpPacket.decode(encoded) as SstpPacket.ControlPacket
        assertEquals(SstpPacket.MSG_ECHO_REQUEST, decoded.messageType)
        assertEquals(0, decoded.attributes.size)
    }
}

