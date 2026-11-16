package com.aethervpn.vpncore.softether

import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Lightweight DHCP client for SoftEther Virtual Hub (Virtual NAT / SecureNAT).
 * Acquires client IP, gateway, netmask, and DNS servers over Layer-2 Ethernet frames.
 */
object SoftEtherDhcp {

    private const val DHCP_OP_BOOTREQUEST: Byte = 1
    private const val DHCP_OP_BOOTREPLY: Byte = 2
    private const val DHCP_HTYPE_ETHERNET: Byte = 1
    private const val DHCP_HLEN_ETHERNET: Byte = 6

    private const val MAGIC_COOKIE: Int = 0x63825363

    private const val OPT_SUBNET_MASK: Byte = 1
    private const val OPT_ROUTER: Byte = 3
    private const val OPT_DNS_SERVERS: Byte = 6
    private const val OPT_REQUESTED_IP: Byte = 50
    private const val OPT_LEASE_TIME: Byte = 51
    private const val OPT_MESSAGE_TYPE: Byte = 53
    private const val OPT_SERVER_ID: Byte = 54
    private const val OPT_PARAMETER_REQUEST_LIST: Byte = 55
    private const val OPT_END: Byte = -1 // 255 / 0xFF

    const val DHCP_DISCOVER: Byte = 1
    const val DHCP_OFFER: Byte = 2
    const val DHCP_REQUEST: Byte = 3
    const val DHCP_ACK: Byte = 5

    data class DhcpConfig(
        val clientIp: String,
        val netmask: String,
        val gateway: String,
        val dnsServers: List<String>,
        val serverMac: ByteArray
    )

    data class DhcpOffer(
        val offeredIp: ByteArray,
        val serverIp: ByteArray,
        val netmask: String,
        val gateway: String,
        val dnsServers: List<String>,
        val serverMac: ByteArray
    )

    fun defaultFallbackConfig(clientMac: ByteArray): DhcpConfig {
        return DhcpConfig(
            clientIp = "192.168.30.15",
            netmask = "255.255.255.0",
            gateway = "192.168.30.1",
            dnsServers = listOf("8.8.8.8", "8.8.4.4"),
            serverMac = byteArrayOf(0x00, 0xAC.toByte(), 0x11, 0x22, 0x33, 0x01)
        )
    }

    /**
     * Builds a full Layer-2 Ethernet + IPv4 + UDP + DHCP DISCOVER frame.
     */
    fun buildDiscoverFrame(clientMac: ByteArray, xid: Int): ByteArray {
        val dhcpPayload = buildDhcpPayload(
            op = DHCP_OP_BOOTREQUEST,
            xid = xid,
            clientMac = clientMac,
            options = { buf ->
                // Option 53: DHCP Discover
                buf.put(OPT_MESSAGE_TYPE).put(1).put(DHCP_DISCOVER)
                // Option 55: Parameter Request List (Subnet, Router, DNS)
                buf.put(OPT_PARAMETER_REQUEST_LIST).put(3)
                buf.put(OPT_SUBNET_MASK).put(OPT_ROUTER).put(OPT_DNS_SERVERS)
                // Option 255: End
                buf.put(OPT_END)
            }
        )
        return wrapUdpInEthernet(
            srcMac = clientMac,
            dstMac = SoftEtherFrame.BROADCAST_MAC,
            srcIp = byteArrayOf(0, 0, 0, 0),
            dstIp = byteArrayOf(-1, -1, -1, -1),
            srcPort = 68,
            dstPort = 67,
            payload = dhcpPayload
        )
    }

    /**
     * Builds a full Layer-2 Ethernet + IPv4 + UDP + DHCP REQUEST frame.
     */
    fun buildRequestFrame(
        clientMac: ByteArray,
        xid: Int,
        requestedIp: ByteArray,
        serverIp: ByteArray,
        serverMac: ByteArray
    ): ByteArray {
        val dhcpPayload = buildDhcpPayload(
            op = DHCP_OP_BOOTREQUEST,
            xid = xid,
            clientMac = clientMac,
            options = { buf ->
                // Option 53: DHCP Request
                buf.put(OPT_MESSAGE_TYPE).put(1).put(DHCP_REQUEST)
                // Option 50: Requested IP
                buf.put(OPT_REQUESTED_IP).put(4).put(requestedIp)
                // Option 54: Server Identifier
                buf.put(OPT_SERVER_ID).put(4).put(serverIp)
                // Option 55: Parameter Request List
                buf.put(OPT_PARAMETER_REQUEST_LIST).put(3)
                buf.put(OPT_SUBNET_MASK).put(OPT_ROUTER).put(OPT_DNS_SERVERS)
                buf.put(OPT_END)
            }
        )
        return wrapUdpInEthernet(
            srcMac = clientMac,
            dstMac = SoftEtherFrame.BROADCAST_MAC,
            srcIp = byteArrayOf(0, 0, 0, 0),
            dstIp = byteArrayOf(-1, -1, -1, -1),
            srcPort = 68,
            dstPort = 67,
            payload = dhcpPayload
        )
    }

    private fun buildDhcpPayload(
        op: Byte,
        xid: Int,
        clientMac: ByteArray,
        options: (ByteBuffer) -> Unit
    ): ByteArray {
        val buf = ByteBuffer.allocate(548)
        buf.order(ByteOrder.BIG_ENDIAN)
        buf.put(op)
        buf.put(DHCP_HTYPE_ETHERNET)
        buf.put(DHCP_HLEN_ETHERNET)
        buf.put(0) // hops
        buf.putInt(xid)
        buf.putShort(0) // secs
        buf.putShort(0x8000.toShort()) // flags (broadcast)
        buf.put(ByteArray(16)) // ciaddr (4), yiaddr (4), siaddr (4), giaddr (4)
        buf.put(clientMac)
        buf.put(ByteArray(10)) // chaddr padding to 16B
        buf.put(ByteArray(64)) // sname (64B)
        buf.put(ByteArray(128)) // file (128B)
        buf.putInt(MAGIC_COOKIE)

        options(buf)

        // Pad to at least 300 bytes if needed
        while (buf.position() < 300) {
            buf.put(0.toByte())
        }

        buf.flip()
        val result = ByteArray(buf.remaining())
        buf.get(result)
        return result
    }

    private fun wrapUdpInEthernet(
        srcMac: ByteArray,
        dstMac: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipTotalLen = 20 + 8 + payload.size
        val ipBuf = ByteBuffer.allocate(ipTotalLen)
        ipBuf.order(ByteOrder.BIG_ENDIAN)

        // IPv4 Header (20B)
        ipBuf.put(0x45.toByte()) // Ver=4, IHL=5
        ipBuf.put(0x00.toByte()) // DSCP/ECN
        ipBuf.putShort(ipTotalLen.toShort())
        ipBuf.putShort(0.toShort()) // ID
        ipBuf.putShort(0x4000.toShort()) // Flags (DF)
        ipBuf.put(64.toByte()) // TTL
        ipBuf.put(17.toByte()) // Protocol (UDP)
        ipBuf.putShort(0.toShort()) // Checksum placeholder
        ipBuf.put(srcIp)
        ipBuf.put(dstIp)

        // Calculate IPv4 Header Checksum
        val ipHeaderBytes = ipBuf.array()
        val chk = calculateChecksum(ipHeaderBytes, 0, 20)
        ipBuf.putShort(10, chk.toShort())

        // UDP Header (8B)
        ipBuf.position(20)
        ipBuf.putShort(srcPort.toShort())
        ipBuf.putShort(dstPort.toShort())
        ipBuf.putShort((8 + payload.size).toShort())
        ipBuf.putShort(0.toShort()) // UDP checksum optional in IPv4

        // Payload
        ipBuf.put(payload)

        return SoftEtherFrame.wrapIpv4Packet(
            srcMac = srcMac,
            dstMac = dstMac,
            ipPacket = ipBuf.array(),
            offset = 0,
            length = ipTotalLen
        )
    }

    /**
     * Parses an incoming Ethernet frame for DHCP OFFER or ACK.
     */
    fun parseDhcpResponse(
        frame: ByteArray,
        length: Int,
        expectedXid: Int
    ): Pair<Byte, DhcpOffer>? {
        if (length < SoftEtherFrame.ETHERNET_HEADER_SIZE + 20 + 8 + 240) return null

        val serverMac = ByteArray(6)
        System.arraycopy(frame, 6, serverMac, 0, 6)

        val ipPacket = SoftEtherFrame.unwrapIpv4Payload(frame, length) ?: return null
        if (ipPacket.size < 28) return null
        val protocol = ipPacket[9].toInt() and 0xFF
        if (protocol != 17) return null // Must be UDP

        val ipHeaderLen = (ipPacket[0].toInt() and 0x0F) * 4
        if (ipPacket.size < ipHeaderLen + 8 + 240) return null

        val dstPort = (((ipPacket[ipHeaderLen + 2].toInt() and 0xFF) shl 8) or
                (ipPacket[ipHeaderLen + 3].toInt() and 0xFF))
        if (dstPort != 68) return null // Must be directed to DHCP Client port 68

        val dhcpStart = ipHeaderLen + 8
        val buf = ByteBuffer.wrap(ipPacket, dhcpStart, ipPacket.size - dhcpStart)
        buf.order(ByteOrder.BIG_ENDIAN)

        val op = buf.get()
        if (op != DHCP_OP_BOOTREPLY) return null

        buf.position(buf.position() + 3) // htype, hlen, hops
        val xid = buf.int
        if (xid != expectedXid) return null

        buf.position(buf.position() + 8) // secs, flags, ciaddr
        val yiaddr = ByteArray(4)
        buf.get(yiaddr) // Your Client IP

        buf.position(buf.position() + 216) // siaddr (4), giaddr (4), chaddr (16), sname (64), file (128)
        val cookie = buf.int
        if (cookie != MAGIC_COOKIE) return null

        var msgType: Byte = 0
        var netmask = "255.255.255.0"
        var gateway = ""
        val dnsList = mutableListOf<String>()
        val serverIp = ByteArray(4)

        // Parse options TLV
        while (buf.hasRemaining()) {
            val opt = buf.get()
            if (opt == OPT_END) break
            if (opt == 0.toByte()) continue // PAD
            if (!buf.hasRemaining()) break
            val optLen = buf.get().toInt() and 0xFF
            if (buf.remaining() < optLen) break

            when (opt) {
                OPT_MESSAGE_TYPE -> {
                    if (optLen >= 1) msgType = buf.get()
                }
                OPT_SUBNET_MASK -> {
                    if (optLen == 4) {
                        val b = ByteArray(4)
                        buf.get(b)
                        netmask = InetAddress.getByAddress(b).hostAddress ?: "255.255.255.0"
                    } else buf.position(buf.position() + optLen)
                }
                OPT_ROUTER -> {
                    if (optLen >= 4) {
                        val b = ByteArray(4)
                        buf.get(b)
                        gateway = InetAddress.getByAddress(b).hostAddress ?: ""
                        if (optLen > 4) buf.position(buf.position() + (optLen - 4))
                    } else buf.position(buf.position() + optLen)
                }
                OPT_DNS_SERVERS -> {
                    var remaining = optLen
                    while (remaining >= 4) {
                        val b = ByteArray(4)
                        buf.get(b)
                        InetAddress.getByAddress(b).hostAddress?.let { dnsList.add(it) }
                        remaining -= 4
                    }
                    if (remaining > 0) buf.position(buf.position() + remaining)
                }
                OPT_SERVER_ID -> {
                    if (optLen == 4) buf.get(serverIp) else buf.position(buf.position() + optLen)
                }
                else -> {
                    buf.position(buf.position() + optLen)
                }
            }
        }

        if (gateway.isBlank()) {
            gateway = InetAddress.getByAddress(serverIp).hostAddress ?: "192.168.30.1"
        }
        if (dnsList.isEmpty()) {
            dnsList.add("8.8.8.8")
            dnsList.add("8.8.4.4")
        }

        val offer = DhcpOffer(
            offeredIp = yiaddr,
            serverIp = serverIp,
            netmask = netmask,
            gateway = gateway,
            dnsServers = dnsList,
            serverMac = serverMac
        )

        return Pair(msgType, offer)
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        return sum.inv() and 0xFFFF
    }
}

