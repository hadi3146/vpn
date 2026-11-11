package com.aethervpn.client.ui

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.aethervpn.client.ui.components.DisclaimerDialog
import com.aethervpn.client.ui.navigation.BottomNavScreens
import com.aethervpn.client.ui.navigation.Screen
import com.aethervpn.client.ui.screens.DnsScreen
import com.aethervpn.client.ui.screens.HomeScreen
import com.aethervpn.client.ui.screens.LogsScreen
import com.aethervpn.client.ui.screens.PerAppFilterScreen
import com.aethervpn.client.ui.screens.ServersScreen
import com.aethervpn.client.ui.screens.SettingsScreen
import com.aethervpn.client.ui.theme.AetherVpnTheme
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    private val viewModel: MainViewModel by viewModels()

    private val vpnConsentLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.connectSelectedServer()
        } else {
            viewModel.addLog("VPN permission was denied by user.")
        }
    }

    private fun checkAndConnectVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            vpnConsentLauncher.launch(intent)
        } else {
            viewModel.connectSelectedServer()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            AetherVpnTheme {
                MainAppContent(
                    viewModel = viewModel,
                    onConnectRequest = { checkAndConnectVpn() }
                )
            }
        }
    }
}

@Composable
fun MainAppContent(
    viewModel: MainViewModel,
    onConnectRequest: () -> Unit
) {
    val navController = rememberNavController()
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route

    val vpnState by viewModel.vpnState.collectAsState()
    val servers by viewModel.servers.collectAsState()
    val selectedServer by viewModel.selectedServer.collectAsState()
    val isRefreshing by viewModel.isRefreshing.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()
    val settings by viewModel.settings.collectAsState()
    val logs by viewModel.logs.collectAsState()

    var showDisclaimer by remember { mutableStateOf(false) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        bottomBar = {
            NavigationBar {
                BottomNavScreens.forEach { screen ->
                    NavigationBarItem(
                        icon = { Icon(screen.icon, contentDescription = null) },
                        label = { Text(stringResource(screen.titleResId)) },
                        selected = currentRoute == screen.route,
                        onClick = {
                            if (currentRoute != screen.route) {
                                navController.navigate(screen.route) {
                                    popUpTo(Screen.Home.route) { saveState = true }
                                    launchSingleTop = true
                                    restoreState = true
                                }
                            }
                        }
                    )
                }
            }
        }
    ) { paddingValues ->
        NavHost(
            navController = navController,
            startDestination = Screen.Home.route,
            modifier = Modifier.padding(paddingValues)
        ) {
            composable(Screen.Home.route) {
                HomeScreen(
                    vpnState = vpnState,
                    selectedServer = selectedServer,
                    onConnectClick = onConnectRequest,
                    onDisconnectClick = { viewModel.disconnect() },
                    onQuickConnectClick = {
                        viewModel.quickConnect()
                        onConnectRequest()
                    },
                    onSelectServerClick = {
                        navController.navigate(Screen.Servers.route)
                    }
                )
            }
            composable(Screen.Servers.route) {
                ServersScreen(
                    servers = servers,
                    isRefreshing = isRefreshing,
                    searchQuery = searchQuery,
                    onSearchQueryChange = { viewModel.setSearchQuery(it) },
                    onRefresh = { viewModel.refreshServers() },
                    onServerSelect = { server ->
                        viewModel.selectServer(server)
                        navController.navigate(Screen.Home.route)
                    },
                    onToggleFavorite = { viewModel.toggleFavorite(it) },
                    onAddCustomServer = { viewModel.addCustomServer(it) },
                    onPingTest = { viewModel.testServerPing(it) }
                )
            }
            composable(Screen.Dns.route) {
                DnsScreen(
                    settings = settings,
                    onDnsModeChange = { viewModel.updateDnsMode(it) },
                    onResolverSelect = { viewModel.updateSelectedDnsId(it) }
                )
            }
            composable(Screen.PerApp.route) {
                PerAppFilterScreen(
                    settings = settings,
                    onModeChange = { viewModel.updateSplitTunnelMode(it) },
                    onAllowedPackagesChange = { viewModel.updateAllowedPackages(it) },
                    onDisallowedPackagesChange = { viewModel.updateDisallowedPackages(it) }
                )
            }
            composable(Screen.Settings.route) {
                SettingsScreen(
                    settings = settings,
                    onStrictCertChange = { viewModel.updateStrictCert(it) },
                    onSniStrategyChange = { viewModel.updateSniStrategy(it) },
                    onCustomSniChange = { viewModel.updateCustomSni(it) },
                    onMtuChange = { viewModel.updateMtu(it) },
                    onKeepaliveChange = { viewModel.updateKeepalive(it) },
                    onKillSwitchChange = { viewModel.updateKillSwitch(it) },
                    onMirrorUrlsChange = { viewModel.updateMirrorUrls(it) },
                    onLanguageChange = { viewModel.updateLanguage(it) },
                    onOpenDisclaimer = { showDisclaimer = true }
                )
            }
            composable(Screen.Logs.route) {
                LogsScreen(
                    logs = logs,
                    onClearLogs = { viewModel.clearLogs() }
                )
            }
        }
    }

    if (showDisclaimer) {
        DisclaimerDialog(onDismiss = { showDisclaimer = false })
    }
}

