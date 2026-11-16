package com.aethervpn.vpncore.transport

import java.io.IOException
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

fun interface SocketProtector {
    fun protect(socket: Socket): Boolean
}

fun interface DatagramSocketProtector {
    fun protect(socket: DatagramSocket): Boolean
}

/**
 * Opens a TCP socket bound to a matching wildcard ephemeral port before invoking
 * [SocketProtector.protect], ensuring the native file descriptor exists so
 * VpnService bypass marks take effect before SYN and persist across tunnel bring-up.
 */
fun openProtectedTcpSocket(
    ipAddress: InetAddress,
    port: Int,
    connectTimeoutMs: Int,
    readTimeoutMs: Int,
    socketProtector: SocketProtector?,
    receiveBufferSizeBytes: Int? = null,
    trafficClass: Int? = null
): Socket {
    val rawSocket = Socket()
    try {
        val bindAddress = if (ipAddress is Inet4Address) {
            InetSocketAddress(InetAddress.getByAddress(ByteArray(4)), 0)
        } else {
            null
        }
        rawSocket.bind(bindAddress)
        val rcvBuf = receiveBufferSizeBytes ?: (8 * 1024 * 1024)
        runCatching { rawSocket.receiveBufferSize = rcvBuf }
        runCatching { rawSocket.sendBufferSize = 2 * 1024 * 1024 }
        val effTrafficClass = trafficClass ?: 0x08 // IPTOS_THROUGHPUT (low delay + high bandwidth)
        runCatching { rawSocket.trafficClass = effTrafficClass }
        rawSocket.tcpNoDelay = true
        rawSocket.keepAlive = true
        rawSocket.reuseAddress = true
        runCatching { rawSocket.setPerformancePreferences(0, 1, 2) }
        rawSocket.soTimeout = readTimeoutMs

        val preProtected = socketProtector?.protect(rawSocket) ?: true
        rawSocket.connect(InetSocketAddress(ipAddress, port), connectTimeoutMs)
        val postProtected = socketProtector?.protect(rawSocket) ?: true
        if (socketProtector != null && !preProtected && !postProtected) {
            throw IOException("Failed to protect transport socket from VPN routing loop")
        }
        return rawSocket
    } catch (e: Exception) {
        try {
            rawSocket.close()
        } catch (_: Exception) {}
        throw e
    }
}


