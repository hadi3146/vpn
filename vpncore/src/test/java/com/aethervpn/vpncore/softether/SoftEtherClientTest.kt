package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.transport.SniStrategy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SoftEtherClientTest {

    @Test
    fun testConfigDefaults() {
        val config = SoftEtherConfig(
            host = "vpn123.opengw.net",
            ipAddress = "1.2.3.4",
            port = 443
        )

        assertEquals("vpn123.opengw.net", config.host)
        assertEquals("1.2.3.4", config.ipAddress)
        assertEquals(443, config.port)
        assertEquals("vpn", config.username)
        assertEquals("vpn", config.password)
        assertEquals("VPNGATE", config.hubName)
        assertEquals(8, config.targetConnections)
        assertEquals(SniStrategy.AUTO_SMART, config.sniStrategy)
        assertFalse(config.strictCert)
    }

    @Test
    fun testVpnParametersConstruction() {
        val params = SoftEtherVpnParameters(
            clientIp = "192.168.30.15",
            netmask = "255.255.255.0",
            gateway = "192.168.30.1",
            dnsServers = listOf("8.8.8.8", "8.8.4.4"),
            mtu = 1400,
            activeChannels = 8
        )

        assertEquals("192.168.30.15", params.clientIp)
        assertEquals(8, params.activeChannels)
        assertEquals(1400, params.mtu)
        assertEquals(2, params.dnsServers.size)
    }

    @Test
    fun testClientInstantiation() {
        val config = SoftEtherConfig(
            host = "test.opengw.net",
            ipAddress = "1.2.3.4",
            port = 443,
            targetConnections = 4
        )

        val client = SoftEtherClient(
            config = config,
            socketProtector = null,
            listener = object : SoftEtherEventListener {
                override fun onStateChanged(state: SoftEtherState, message: String) {}
                override fun onConnected(params: SoftEtherVpnParameters) {}
                override fun onDisconnected(reason: String) {}
                override fun onError(e: Exception) {}
                override fun onIpPacketReceived(packet: ByteArray, length: Int) {}
            }
        )

        assertNotNull(client.clientMac)
        assertEquals(6, client.clientMac.size)
        assertEquals(0x00.toByte(), client.clientMac[0])
        assertEquals(0xAC.toByte(), client.clientMac[1])

        val snap = client.snapshotTraffic()
        assertEquals(0L, snap.txPackets)
        assertEquals(0L, snap.rxUnicastPackets)
        assertTrue(snap.lastAnyRxMs > 0L)

        client.setProbeInterceptor { true }
        client.close()
    }
}
