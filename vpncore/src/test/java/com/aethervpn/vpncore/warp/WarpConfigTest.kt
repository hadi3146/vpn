package com.aethervpn.vpncore.warp

import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.wireguard.crypto.KeyPair
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test
import java.net.InetAddress

class WarpConfigTest {

    @Test
    fun testGenerateKeyPairAndBuildConfig() {
        val keyPair = KeyPair()
        assertNotNull(keyPair.privateKey.toBase64())
        assertNotNull(keyPair.publicKey.toBase64())

        val iface = Interface.Builder()
            .parsePrivateKey(keyPair.privateKey.toBase64())
            .addAddress(InetNetwork.parse("172.16.0.2/32"))
            .addDnsServer(InetAddress.getByName("1.1.1.1"))
            .build()

        val peer = Peer.Builder()
            .parsePublicKey("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
            .parseEndpoint("188.114.97.1:2408")
            .parseAllowedIPs("0.0.0.0/0")
            .build()

        val config = Config.Builder()
            .setInterface(iface)
            .addPeer(peer)
            .build()

        assertNotNull(config)
        assertEquals(1, config.peers.size)
        assertEquals("188.114.97.1:2408", config.peers[0].endpoint.get().toString())

        // Test WarpConfigBuilder helper
        val account = WarpAccount(
            id = "test-id",
            privateKey = keyPair.privateKey.toBase64(),
            publicKey = keyPair.publicKey.toBase64(),
            token = "test-token"
        )
        val endpoint = CleanEndpoint(ip = "188.114.97.1", port = 2408, pingMs = 45)
        val built = WarpConfigBuilder.buildConfig(account, endpoint)
        assertNotNull(built)
        assertEquals("188.114.97.1:2408", built.peers[0].endpoint.get().toString())
    }
}
