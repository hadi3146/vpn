package com.aethervpn.vpncore.transport

import java.net.DatagramSocket
import java.net.Socket

fun interface SocketProtector {
    fun protect(socket: Socket): Boolean
}

fun interface DatagramSocketProtector {
    fun protect(socket: DatagramSocket): Boolean
}

