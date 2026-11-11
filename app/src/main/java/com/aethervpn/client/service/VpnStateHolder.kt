package com.aethervpn.client.service

import com.aethervpn.client.data.model.VpnServer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class VpnStatus {
    DISCONNECTED,
    CONNECTING,
    AUTHENTICATING,
    CONNECTED,
    DISCONNECTING,
    RECONNECTING,
    ERROR
}

data class VpnSessionState(
    val status: VpnStatus = VpnStatus.DISCONNECTED,
    val currentServer: VpnServer? = null,
    val clientIp: String = "",
    val durationSeconds: Long = 0,
    val bytesIn: Long = 0,
    val bytesOut: Long = 0,
    val speedInBps: Long = 0,
    val speedOutBps: Long = 0,
    val publicIp: String = "",
    val errorMessage: String? = null,
    val appliedSniStrategy: String = ""
)

object VpnStateHolder {
    private val _state = MutableStateFlow(VpnSessionState())
    val state: StateFlow<VpnSessionState> = _state.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(listOf("Aether VPN ready"))
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    fun log(message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        val sanitized = message.replace(Regex("(?i)(password|pass)=([^&\\s]+)"), "$1=***")
        _logs.value = (_logs.value + "[$time] $sanitized").takeLast(500)
    }

    fun clearLogs() {
        _logs.value = emptyList()
    }

    fun updateStatus(status: VpnStatus, message: String? = null) {
        _state.value = _state.value.copy(status = status, errorMessage = message)
        if (message != null) {
            log(message)
        }
    }

    fun updateConnected(server: VpnServer, clientIp: String, strategy: String) {
        _state.value = _state.value.copy(
            status = VpnStatus.CONNECTED,
            currentServer = server,
            clientIp = clientIp,
            appliedSniStrategy = strategy,
            errorMessage = null
        )
        log("Tunnel active. Assigned IP: $clientIp (Strategy: $strategy)")
    }

    fun updateMetrics(bytesIn: Long, bytesOut: Long, speedIn: Long, speedOut: Long, duration: Long) {
        _state.value = _state.value.copy(
            bytesIn = bytesIn,
            bytesOut = bytesOut,
            speedInBps = speedIn,
            speedOutBps = speedOut,
            durationSeconds = duration
        )
    }

    fun updatePublicIp(ip: String) {
        _state.value = _state.value.copy(publicIp = ip)
        log("Public IP verified through tunnel: $ip")
    }

    fun reset() {
        _state.value = VpnSessionState()
        log("VPN session closed.")
    }
}

