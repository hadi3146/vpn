package com.aethervpn.vpncore.ppp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class PppProtocolTest {

    @Test
    fun testPppFrameEncodeDecode() {
        val payload = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val frame = PppFrame(PppFrame.PROTO_IP, payload)
        val encoded = frame.encode()

        val decoded = PppFrame.decode(encoded)
        assertEquals(PppFrame.PROTO_IP, decoded.protocol)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun testLcpPacketEncodeDecode() {
        val req = LcpPacket(
            code = LcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 42,
            options = listOf(
                LcpOption.mru(1400),
                LcpOption.magicNumber(0x12345678),
                LcpOption.authMsChapV2()
            )
        )
        val encoded = req.encode()
        val decoded = LcpPacket.decode(encoded)

        assertEquals(LcpPacket.CODE_CONFIGURE_REQUEST, decoded.code)
        assertEquals(42.toByte(), decoded.identifier)
        assertEquals(3, decoded.options.size)
        assertEquals(LcpOption.OPTION_MRU, decoded.options[0].type)
        assertEquals(LcpOption.OPTION_MAGIC_NUMBER, decoded.options[1].type)
        assertEquals(LcpOption.OPTION_AUTH_PROTOCOL, decoded.options[2].type)
    }

    @Test
    fun testIpcpPacketEncodeDecode() {
        val ipBytes = byteArrayOf(10, 0, 0, 2)
        val dnsBytes = byteArrayOf(8, 8, 8, 8)
        val ipcp = IpcpPacket(
            code = IpcpPacket.CODE_CONFIGURE_REQUEST,
            identifier = 1,
            options = listOf(
                IpcpOption.ipAddress(ipBytes),
                IpcpOption.primaryDns(dnsBytes)
            )
        )
        val encoded = ipcp.encode()
        val decoded = IpcpPacket.decode(encoded)

        assertEquals(IpcpPacket.CODE_CONFIGURE_REQUEST, decoded.code)
        assertEquals(2, decoded.options.size)
        assertArrayEquals(ipBytes, decoded.options[0].value)
        assertArrayEquals(dnsBytes, decoded.options[1].value)
    }

    @Test
    fun testChapPacketEncodeDecode() {
        val challenge = byteArrayOf(16) + ByteArray(16) { 0xAA.toByte() }
        val chap = ChapPacket(ChapPacket.CODE_CHALLENGE, 1, challenge)
        val encoded = chap.encode()
        val decoded = ChapPacket.decode(encoded)

        assertEquals(ChapPacket.CODE_CHALLENGE, decoded.code)
        assertEquals(1.toByte(), decoded.identifier)
        assertArrayEquals(challenge, decoded.data)
    }
}

