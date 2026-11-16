package com.aethervpn.vpncore.softether

import com.aethervpn.vpncore.sstp.SstpTrafficSnapshot
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.transport.TunnelClient
import java.net.InetAddress
import java.security.SecureRandom
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

enum class SoftEtherState {
    DISCONNECTED,
    CONNECTING_PRIMARY,
    AUTHENTICATING,
    ESTABLISHING_CHANNELS,
    NEGOTIATING_DHCP,
    CONNECTED,
    DISCONNECTING
}

data class SoftEtherConfig(
    val host: String,
    val ipAddress: String,
    val port: Int = 443,
    val username: String = "vpn",
    val password: String = "vpn",
    val hubName: String = "VPNGATE",
    val targetConnections: Int = 8,
    val sniStrategy: SniStrategy = SniStrategy.AUTO_SMART,
    val customSni: String? = null,
    val strictCert: Boolean = false,
    val connectTimeoutMs: Int = 10000
)

data class SoftEtherVpnParameters(
    val clientIp: String,
    val netmask: String,
    val gateway: String,
    val dnsServers: List<String>,
    val mtu: Int = 1400,
    val activeChannels: Int = 1
)

interface SoftEtherEventListener {
    fun onStateChanged(state: SoftEtherState, message: String)
    fun onConnected(params: SoftEtherVpnParameters)
    fun onDisconnected(reason: String)
    fun onError(e: Exception)
    fun onIpPacketReceived(packet: ByteArray, length: Int)
    fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {}
}

/**
 * SoftEther VPN Native Protocol Client with Multi-Connection TCP channel bonding.
 */
class SoftEtherClient(
    private val config: SoftEtherConfig,
    private val socketProtector: SocketProtector?,
    private val listener: SoftEtherEventListener
) : TunnelClient {
    private val isRunning = AtomicBoolean(false)
    private var clientJob: Job? = null
    private var probeInterceptor: ((ByteArray) -> Boolean)? = null

    private val channels = CopyOnWriteArrayList<SoftEtherChannel>()
    private val txChannelIndex = AtomicInteger(0)

    val clientMac: ByteArray = SoftEtherFrame.generateClientMac()
    @Volatile
    private var gatewayMac: ByteArray = SoftEtherFrame.BROADCAST_MAC

    private var sessionKey: ByteArray? = null
    private var acquiredDhcp: SoftEtherDhcp.DhcpConfig? = null

    private var pendingDhcpXid: Int = 0
    private var dhcpChannel: Channel<Pair<Byte, SoftEtherDhcp.DhcpOffer>>? = null

    val totalTxBytes = AtomicLong(0)
    val totalRxBytes = AtomicLong(0)
    val txPackets = AtomicLong(0)
    val rxPackets = AtomicLong(0)
    val lastAnyRxMs = AtomicLong(System.currentTimeMillis())
    val lastUnicastIpRxMs = AtomicLong(System.currentTimeMillis())

    override fun setProbeInterceptor(interceptor: ((ByteArray) -> Boolean)?) {
        this.probeInterceptor = interceptor
    }

    override fun snapshotTraffic(): SstpTrafficSnapshot = SstpTrafficSnapshot(
        txPackets = txPackets.get(),
        rxUnicastPackets = rxPackets.get(),
        lastAnyRxMs = lastAnyRxMs.get(),
        lastUnicastIpRxMs = lastUnicastIpRxMs.get()
    )

    suspend fun start(scope: CoroutineScope) = withContext(Dispatchers.IO) {
        if (!isRunning.compareAndSet(false, true)) return@withContext
        var wasConnected = false
        try {
            listener.onStateChanged(SoftEtherState.CONNECTING_PRIMARY, "Connecting primary channel to ${config.host}:${config.port}...")

            // 1. Establish Primary Channel (Channel 0)
            val primaryChannel = SoftEtherChannel(
                channelId = 0,
                host = config.host,
                ipAddress = config.ipAddress,
                port = config.port,
                isPrimary = true,
                sniStrategy = config.sniStrategy,
                customSni = config.customSni,
                strictCert = config.strictCert,
                socketProtector = socketProtector,
                connectTimeoutMs = config.connectTimeoutMs
            )

            listener.onStateChanged(SoftEtherState.AUTHENTICATING, "Authenticating with Virtual Hub '${config.hubName}'...")
            val sessionInfo = primaryChannel.connectAndHandshake(
                username = config.username,
                password = config.password,
                hubName = config.hubName,
                targetConnections = config.targetConnections
            )

            sessionKey = sessionInfo.sessionKey
            channels.add(primaryChannel)

            // Start reading on primary channel
            scope.launch(Dispatchers.IO) {
                primaryChannel.readLoop { frame -> handleIncomingEthernetFrame(frame) }
            }

            // 2. Establish Secondary Channels (Multi-TCP bonding) in Parallel
            val effectiveTarget = minOf(config.targetConnections, sessionInfo.maxConnections)
                .coerceIn(1, SoftEtherConstants.MAX_SUPPORTED_CONNECTIONS)

            if (effectiveTarget > 1) {
                listener.onStateChanged(
                    SoftEtherState.ESTABLISHING_CHANNELS,
                    "Multiplexing tunnel over $effectiveTarget parallel TCP connections..."
                )

                coroutineScope {
                    (1 until effectiveTarget).map { id ->
                        async(Dispatchers.IO) {
                            if (!scope.isActive || !isRunning.get()) return@async
                            try {
                                val ch = SoftEtherChannel(
                                    channelId = id,
                                    host = config.host,
                                    ipAddress = config.ipAddress,
                                    port = config.port,
                                    isPrimary = false,
                                    sniStrategy = config.sniStrategy,
                                    customSni = config.customSni,
                                    strictCert = config.strictCert,
                                    socketProtector = socketProtector,
                                    connectTimeoutMs = config.connectTimeoutMs
                                )
                                ch.connectAndHandshake(
                                    username = config.username,
                                    password = config.password,
                                    hubName = config.hubName,
                                    targetConnections = effectiveTarget,
                                    existingSessionKey = sessionKey
                                )
                                channels.add(ch)

                                scope.launch(Dispatchers.IO) {
                                    ch.readLoop { frame -> handleIncomingEthernetFrame(frame) }
                                }
                            } catch (_: Exception) {
                                // If an additional channel fails, continue with established channels
                            }
                        }
                    }.awaitAll()
                }
            }

            // 3. Negotiate Virtual DHCP
            listener.onStateChanged(SoftEtherState.NEGOTIATING_DHCP, "Negotiating IP configuration with Virtual NAT...")
            val dhcpConfig = negotiateDhcp()
            acquiredDhcp = dhcpConfig

            val vpnParams = SoftEtherVpnParameters(
                clientIp = dhcpConfig.clientIp,
                netmask = dhcpConfig.netmask,
                gateway = dhcpConfig.gateway,
                dnsServers = dhcpConfig.dnsServers,
                mtu = 1400,
                activeChannels = channels.count { it.isConnected.get() }
            )

            // Actively discover Gateway MAC via ARP
            sendArpDiscovery(dhcpConfig.gateway, dhcpConfig.clientIp)

            listener.onStateChanged(
                SoftEtherState.CONNECTED,
                "Connected via SoftEther Native Protocol (${vpnParams.activeChannels} TCP channels active)"
            )
            listener.onConnected(vpnParams)
            wasConnected = true

            // 4. Supervision loop
            while (scope.isActive && isRunning.get()) {
                delay(5000)
                cleanupDeadChannels()
                ensureChannelsCount(scope, effectiveTarget)
                for (ch in channels) {
                    ch.sendKeepalive()
                }
                if (gatewayMac.contentEquals(SoftEtherFrame.BROADCAST_MAC)) {
                    val assigned = acquiredDhcp
                    if (assigned != null) {
                        sendArpDiscovery(assigned.gateway, assigned.clientIp)
                    }
                }
            }
        } catch (e: CancellationException) {
            listener.onDisconnected("Cancelled")
            throw e
        } catch (e: Exception) {
            if (wasConnected) {
                listener.onError(e)
            } else {
                throw e
            }
        } finally {
            close()
        }
    }

    private suspend fun negotiateDhcp(): SoftEtherDhcp.DhcpConfig = withContext(Dispatchers.IO) {
        val xid = SecureRandom().nextInt()
        pendingDhcpXid = xid
        val ch = Channel<Pair<Byte, SoftEtherDhcp.DhcpOffer>>(capacity = 8)
        dhcpChannel = ch

        try {
            val discoverFrame = SoftEtherDhcp.buildDiscoverFrame(clientMac, xid)
            sendFrameBroadcast(discoverFrame)

            // Wait for DHCP Offer
            val offer = withTimeoutOrNull(1500L) {
                while (true) {
                    val (msgType, offerData) = ch.receive()
                    if (msgType == SoftEtherDhcp.DHCP_OFFER) {
                        return@withTimeoutOrNull offerData
                    }
                }
                null
            }

            if (offer != null) {
                gatewayMac = offer.serverMac
                val requestFrame = SoftEtherDhcp.buildRequestFrame(
                    clientMac = clientMac,
                    xid = xid,
                    requestedIp = offer.offeredIp,
                    serverIp = offer.serverIp,
                    serverMac = offer.serverMac
                )
                sendFrameBroadcast(requestFrame)

                // Wait for DHCP Ack
                val ack = withTimeoutOrNull(1500L) {
                    while (true) {
                        val (msgType, ackData) = ch.receive()
                        if (msgType == SoftEtherDhcp.DHCP_ACK) {
                            return@withTimeoutOrNull ackData
                        }
                    }
                    null
                }

                if (ack != null) {
                    gatewayMac = ack.serverMac
                    val clientIpStr = InetAddress.getByAddress(ack.offeredIp).hostAddress ?: "192.168.30.15"
                    return@withContext SoftEtherDhcp.DhcpConfig(
                        clientIp = clientIpStr,
                        netmask = ack.netmask,
                        gateway = ack.gateway,
                        dnsServers = ack.dnsServers.ifEmpty { listOf("8.8.8.8", "8.8.4.4") },
                        serverMac = ack.serverMac
                    )
                }
            }
        } catch (_: Exception) {
            // DHCP timed out or failed, fall through to static fallback
        } finally {
            pendingDhcpXid = 0
            dhcpChannel = null
        }

        // Fallback: Virtual NAT standard configuration
        val fallback = SoftEtherDhcp.defaultFallbackConfig(clientMac)
        sendArpDiscovery(fallback.gateway, fallback.clientIp)
        fallback
    }

    private fun handleIncomingEthernetFrame(frame: ByteArray) {
        totalRxBytes.addAndGet(frame.size.toLong())

        // Check for ARP packet (EtherType 0x0806)
        if (frame.size >= 42) {
            val etherType = (((frame[12].toInt() and 0xFF) shl 8) or (frame[13].toInt() and 0xFF)).toShort()
            if (etherType == SoftEtherFrame.ETHER_TYPE_ARP) {
                handleArpPacket(frame)
                return
            }
        }

        // Check for DHCP packet during negotiation
        if (pendingDhcpXid != 0 && frame.size >= 282) {
            val etherType = (((frame[12].toInt() and 0xFF) shl 8) or (frame[13].toInt() and 0xFF)).toShort()
            if (etherType == SoftEtherFrame.ETHER_TYPE_IPV4) {
                val resp = SoftEtherDhcp.parseDhcpResponse(frame, frame.size, pendingDhcpXid)
                if (resp != null) {
                    dhcpChannel?.trySend(resp)
                    return
                }
            }
        }

        // Check if it's an IPv4 packet
        val ipPacket = SoftEtherFrame.unwrapIpv4Payload(frame, frame.size)
        if (ipPacket != null) {
            rxPackets.incrementAndGet()
            val now = System.currentTimeMillis()
            lastAnyRxMs.set(now)
            lastUnicastIpRxMs.set(now)

            if (probeInterceptor?.invoke(ipPacket) == true) {
                return
            }
            listener.onIpPacketReceived(ipPacket, ipPacket.size)
            listener.onBytesTransferred(0, ipPacket.size.toLong())
        }
    }

    private fun handleArpPacket(frame: ByteArray) {
        if (frame.size < 42) return
        val hwType = ((frame[14].toInt() and 0xFF) shl 8) or (frame[15].toInt() and 0xFF)
        val protoType = ((frame[16].toInt() and 0xFF) shl 8) or (frame[17].toInt() and 0xFF)
        val opcode = ((frame[20].toInt() and 0xFF) shl 8) or (frame[21].toInt() and 0xFF)
        if (hwType != 1 || protoType != 0x0800) return

        val senderMac = ByteArray(6)
        System.arraycopy(frame, 22, senderMac, 0, 6)
        gatewayMac = senderMac

        // If opcode == 1 (ARP Request), answer with our client MAC
        if (opcode == 1) {
            val reply = ByteArray(42)
            // Ethernet header: Dst MAC (senderMac), Src MAC (clientMac), EtherType (0x0806)
            System.arraycopy(senderMac, 0, reply, 0, 6)
            System.arraycopy(clientMac, 0, reply, 6, 6)
            reply[12] = 0x08.toByte()
            reply[13] = 0x06.toByte()

            // ARP header: hwType=1, proto=0x0800, hwSize=6, protoSize=4, opcode=2 (Reply)
            reply[14] = 0x00; reply[15] = 0x01
            reply[16] = 0x08; reply[17] = 0x00
            reply[18] = 0x06; reply[19] = 0x04
            reply[20] = 0x00; reply[21] = 0x02

            // Sender MAC: clientMac
            System.arraycopy(clientMac, 0, reply, 22, 6)
            // Sender IP: target IP from request (frame[38..41])
            System.arraycopy(frame, 38, reply, 28, 4)

            // Target MAC: senderMac
            System.arraycopy(senderMac, 0, reply, 32, 6)
            // Target IP: sender IP from request (frame[28..31])
            System.arraycopy(frame, 28, reply, 38, 4)

            sendFrameBroadcast(reply)
        }
    }

    private fun sendArpDiscovery(gatewayIpStr: String, clientIpStr: String) {
        try {
            val gatewayIp = InetAddress.getByName(gatewayIpStr).address
            val clientIp = InetAddress.getByName(clientIpStr).address
            val req = buildArpRequest(clientMac, clientIp, gatewayIp)
            sendFrameBroadcast(req)
        } catch (_: Exception) {}
    }

    private fun buildArpRequest(srcMac: ByteArray, srcIp: ByteArray, targetIp: ByteArray): ByteArray {
        val frame = ByteArray(42)
        // Dst MAC: Broadcast FF:FF:FF:FF:FF:FF
        for (i in 0 until 6) frame[i] = 0xFF.toByte()
        // Src MAC: srcMac
        System.arraycopy(srcMac, 0, frame, 6, 6)
        // EtherType: 0x0806 (ARP)
        frame[12] = 0x08.toByte()
        frame[13] = 0x06.toByte()
        // Hardware type: Ethernet (1)
        frame[14] = 0x00; frame[15] = 0x01
        // Protocol type: IPv4 (0x0800)
        frame[16] = 0x08; frame[17] = 0x00
        // HLEN: 6, PLEN: 4
        frame[18] = 0x06; frame[19] = 0x04
        // Opcode: 1 (Request)
        frame[20] = 0x00; frame[21] = 0x01
        // Sender MAC: srcMac
        System.arraycopy(srcMac, 0, frame, 22, 6)
        // Sender IP: srcIp
        System.arraycopy(srcIp, 0, frame, 28, 4)
        // Target MAC: 00:00:00:00:00:00
        for (i in 32 until 38) frame[i] = 0x00
        // Target IP: targetIp
        System.arraycopy(targetIp, 0, frame, 38, 4)
        return frame
    }

    /**
     * Send an IP packet received from Android TUN interface.
     * Encapsulates it into an Ethernet frame and distributes across active TCP channels.
     */
    override fun sendIpPacket(packet: ByteArray, length: Int) {
        if (!isRunning.get() || length <= 0) return
        val activeList = channels.filter { it.isConnected.get() }
        if (activeList.isEmpty()) return

        val frame = SoftEtherFrame.wrapIpv4Packet(
            srcMac = clientMac,
            dstMac = gatewayMac,
            ipPacket = packet,
            offset = 0,
            length = length
        )

        val idx = Math.abs(txChannelIndex.getAndIncrement()) % activeList.size
        activeList[idx].sendEthernetFrame(frame)
        txPackets.incrementAndGet()
        totalTxBytes.addAndGet(length.toLong())
        listener.onBytesTransferred(length.toLong(), 0)
    }

    private fun sendFrameBroadcast(frame: ByteArray) {
        val activeList = channels.filter { it.isConnected.get() }
        if (activeList.isNotEmpty()) {
            activeList[0].sendEthernetFrame(frame)
        }
    }

    private fun cleanupDeadChannels() {
        val dead = channels.filter { !it.isConnected.get() }
        for (ch in dead) {
            ch.close()
            channels.remove(ch)
        }
    }

    private fun ensureChannelsCount(scope: CoroutineScope, target: Int) {
        val key = sessionKey ?: return
        val currentCount = channels.count { it.isConnected.get() }
        if (currentCount in 1 until target && isRunning.get()) {
            scope.launch(Dispatchers.IO) {
                try {
                    val nextId = channels.size + 1
                    val ch = SoftEtherChannel(
                        channelId = nextId,
                        host = config.host,
                        ipAddress = config.ipAddress,
                        port = config.port,
                        isPrimary = false,
                        sniStrategy = config.sniStrategy,
                        customSni = config.customSni,
                        strictCert = config.strictCert,
                        socketProtector = socketProtector,
                        connectTimeoutMs = config.connectTimeoutMs
                    )
                    ch.connectAndHandshake(
                        username = config.username,
                        password = config.password,
                        hubName = config.hubName,
                        targetConnections = target,
                        existingSessionKey = key
                    )
                    channels.add(ch)
                    ch.readLoop { frame -> handleIncomingEthernetFrame(frame) }
                } catch (_: Exception) {}
            }
        }
    }

    override fun close() {
        if (!isRunning.compareAndSet(true, false)) return
        clientJob?.cancel()
        for (ch in channels) {
            ch.close()
        }
        channels.clear()
        listener.onStateChanged(SoftEtherState.DISCONNECTED, "Disconnected")
    }
}
