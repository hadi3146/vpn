package com.aethervpn.vpncore.sstp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class SstpPacketTest {

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

