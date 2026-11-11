package com.aethervpn.client.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.aethervpn.client.data.datastore.DnsMode
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.UserSettings
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.repository.ServerRepository
import com.aethervpn.client.service.AetherVpnService
import com.aethervpn.client.service.VpnSessionState
import com.aethervpn.client.service.VpnStateHolder
import com.aethervpn.client.service.VpnStatus
import com.aethervpn.vpncore.transport.SniStrategy
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class MainViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val serverRepository: ServerRepository,
    private val preferencesManager: PreferencesManager
) : ViewModel() {

    val vpnState: StateFlow<VpnSessionState> = VpnStateHolder.state
    val servers: StateFlow<List<VpnServer>> = serverRepository.allServers
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())
    val settings: StateFlow<UserSettings> = preferencesManager.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), UserSettings())

    private val _isRefreshing = MutableStateFlow(false)
    val isRefreshing: StateFlow<Boolean> = _isRefreshing.asStateFlow()

    private val _selectedServer = MutableStateFlow<VpnServer?>(null)
    val selectedServer: StateFlow<VpnServer?> = _selectedServer.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    val logs: StateFlow<List<String>> = VpnStateHolder.logs

    init {
        viewModelScope.launch {
            serverRepository.ensureInitialized()
            servers.collect { list ->
                if (_selectedServer.value == null && list.isNotEmpty()) {
                    _selectedServer.value = list.first()
                }
            }
        }
        refreshServers()
    }

    fun selectServer(server: VpnServer) {
        _selectedServer.value = server
        VpnStateHolder.log("Selected server: ${server.countryLong.ifBlank { server.hostName }} (${server.ip}:${server.customPort})")
    }

    fun setSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun refreshServers() {
        viewModelScope.launch {
            _isRefreshing.value = true
            val currentSettings = settings.value
            serverRepository.refreshServers(currentSettings.mirrorUrls)
            _isRefreshing.value = false
        }
    }

    fun connectSelectedServer() {
        val server = _selectedServer.value ?: servers.value.firstOrNull()
        if (server == null) {
            addLog("No server selected. Initializing server list...")
            viewModelScope.launch {
                serverRepository.ensureInitialized()
            }
            return
        }
        connect(server)
    }

    fun quickConnect() {
        val best = servers.value.maxByOrNull { it.score } ?: servers.value.firstOrNull()
        if (best != null) {
            _selectedServer.value = best
            connect(best)
        } else {
            addLog("No server available for Quick Connect. Prepopulating...")
            viewModelScope.launch {
                serverRepository.ensureInitialized()
            }
        }
    }

    private fun connect(server: VpnServer) {
        _selectedServer.value = server
        val intent = Intent(context, AetherVpnService::class.java).apply {
            action = AetherVpnService.ACTION_CONNECT
            putExtra(AetherVpnService.EXTRA_SERVER_HOST, server.hostName)
            putExtra(AetherVpnService.EXTRA_SERVER_IP, server.ip)
            putExtra(AetherVpnService.EXTRA_SERVER_PORT, server.customPort)
            putExtra(AetherVpnService.EXTRA_SERVER_USER, server.customUsername)
            putExtra(AetherVpnService.EXTRA_SERVER_PASS, server.customPassword)
            putExtra(AetherVpnService.EXTRA_SERVER_COUNTRY, server.countryLong)
        }
        try {
            ContextCompat.startForegroundService(context, intent)
            addLog("Connecting to ${server.countryLong.ifBlank { server.hostName }} (${server.ip}:${server.customPort})...")
        } catch (e: Exception) {
            addLog("Failed to start VPN service: ${e.message}")
        }
    }

    fun disconnect() {
        val intent = Intent(context, AetherVpnService::class.java).apply {
            action = AetherVpnService.ACTION_DISCONNECT
        }
        try {
            ContextCompat.startForegroundService(context, intent)
        } catch (_: Exception) {
            context.stopService(intent)
        }
        addLog("Disconnected by user.")
    }

    fun toggleFavorite(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.toggleFavorite(server)
        }
    }

    fun addCustomServer(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.addCustomServer(server)
        }
    }

    fun deleteServer(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.deleteServer(server)
        }
    }

    fun testServerPing(server: VpnServer) {
        viewModelScope.launch {
            serverRepository.testServerPing(server)
        }
    }

    fun updateStrictCert(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateStrictCert(enabled)
    }

    fun updateDnsMode(mode: DnsMode) = viewModelScope.launch {
        preferencesManager.updateDnsMode(mode)
    }

    fun updateSelectedDnsId(id: String) = viewModelScope.launch {
        preferencesManager.updateSelectedDnsId(id)
    }

    fun updateSniStrategy(strategy: SniStrategy) = viewModelScope.launch {
        preferencesManager.updateSniStrategy(strategy)
    }

    fun updateCustomSni(sni: String) = viewModelScope.launch {
        preferencesManager.updateCustomSni(sni)
    }

    fun updateMtu(mtu: Int) = viewModelScope.launch {
        preferencesManager.updateMtu(mtu)
    }

    fun updateKeepalive(sec: Int) = viewModelScope.launch {
        preferencesManager.updateKeepalive(sec)
    }

    fun updateKillSwitch(enabled: Boolean) = viewModelScope.launch {
        preferencesManager.updateKillSwitch(enabled)
    }

    fun updateSplitTunnelMode(mode: SplitTunnelMode) = viewModelScope.launch {
        preferencesManager.updateSplitTunnelMode(mode)
    }

    fun updateAllowedPackages(pkgs: Set<String>) = viewModelScope.launch {
        preferencesManager.updateAllowedPackages(pkgs)
    }

    fun updateDisallowedPackages(pkgs: Set<String>) = viewModelScope.launch {
        preferencesManager.updateDisallowedPackages(pkgs)
    }

    fun updateMirrorUrls(urls: String) = viewModelScope.launch {
        preferencesManager.updateMirrorUrls(urls)
    }

    fun updateLanguage(lang: String) = viewModelScope.launch {
        preferencesManager.updateLanguage(lang)
    }

    fun addLog(entry: String) {
        VpnStateHolder.log(entry)
    }

    fun clearLogs() {
        VpnStateHolder.clearLogs()
    }
}

