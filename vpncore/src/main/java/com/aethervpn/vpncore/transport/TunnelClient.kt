package com.aethervpn.vpncore.transport

import com.aethervpn.vpncore.sstp.SstpTrafficSnapshot

/**
 * Common interface for VPN tunnel protocol clients (SSTP, SoftEther Native, etc.)
 */
interface TunnelClient {
    /**
     * Transmit an IPv4/IPv6 packet from the TUN interface through the tunnel.
     */
    fun sendIpPacket(packet: ByteArray, length: Int)

    /**
     * Intercept raw packets received from the tunnel before they are written to TUN (e.g. for DNS health checks).
     */
    fun setProbeInterceptor(interceptor: ((ByteArray) -> Boolean)?)

    /**
     * Retrieve a point-in-time snapshot of tunnel packet counters and timestamps.
     */
    fun snapshotTraffic(): SstpTrafficSnapshot

    /**
     * Close the tunnel and release all resources.
     */
    fun close()
}

