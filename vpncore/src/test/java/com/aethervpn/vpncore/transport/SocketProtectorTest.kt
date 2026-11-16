package com.aethervpn.vpncore.transport

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket

class SocketProtectorTest {

    @Test
    fun `openProtectedTcpSocket binds before pre-connect protect and re-protects after connect`() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val callStates = mutableListOf<Pair<Boolean, Boolean>>() // (isBound, isConnected)
            val protector = SocketProtector { sock ->
                callStates.add(sock.isBound to sock.isConnected)
                true
            }

            val sock = openProtectedTcpSocket(
                ipAddress = InetAddress.getLoopbackAddress(),
                port = server.localPort,
                connectTimeoutMs = 2000,
                readTimeoutMs = 2000,
                socketProtector = protector
            )
            try {
                assertEquals(2, callStates.size)
                // Pre-connect protect: bound so native fd exists, not yet connected
                assertEquals(true to false, callStates[0])
                // Post-connect protect: bound and connected
                assertEquals(true to true, callStates[1])
                assertTrue(sock.isConnected)
            } finally {
                sock.close()
            }
        }
    }

    @Test
    fun `openProtectedTcpSocket throws when protector fails both pre and post connect`() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val protector = SocketProtector { false }
            try {
                openProtectedTcpSocket(
                    ipAddress = InetAddress.getLoopbackAddress(),
                    port = server.localPort,
                    connectTimeoutMs = 2000,
                    readTimeoutMs = 2000,
                    socketProtector = protector
                )
                fail("Expected IOException when socket protection returns false")
            } catch (expected: IOException) {
                assertTrue(expected.message?.contains("protect", ignoreCase = true) == true)
            }
        }
    }

    @Test
    fun `openProtectedTcpSocket connects cleanly without protector`() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { server ->
            val sock = openProtectedTcpSocket(
                ipAddress = InetAddress.getLoopbackAddress(),
                port = server.localPort,
                connectTimeoutMs = 2000,
                readTimeoutMs = 2000,
                socketProtector = null
            )
            try {
                assertTrue(sock.isConnected)
                assertTrue(sock.isBound)
            } finally {
                sock.close()
            }
        }
    }
}

