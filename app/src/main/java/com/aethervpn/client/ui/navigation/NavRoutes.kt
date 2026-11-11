package com.aethervpn.client.ui.navigation

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Settings
import androidx.compose.ui.graphics.vector.ImageVector

sealed class Screen(val route: String, val titleResId: Int, val icon: ImageVector) {
    data object Home : Screen("home", com.aethervpn.client.R.string.nav_home, Icons.Default.Home)
    data object Servers : Screen("servers", com.aethervpn.client.R.string.nav_servers, Icons.Default.Public)
    data object Dns : Screen("dns", com.aethervpn.client.R.string.nav_dns, Icons.Default.Dns)
    data object PerApp : Screen("per_app", com.aethervpn.client.R.string.nav_apps, Icons.Default.Apps)
    data object Settings : Screen("settings", com.aethervpn.client.R.string.nav_settings, Icons.Default.Settings)
    data object Logs : Screen("logs", com.aethervpn.client.R.string.nav_logs, Icons.AutoMirrored.Filled.List)
}

val BottomNavScreens = listOf(
    Screen.Home,
    Screen.Servers,
    Screen.Dns,
    Screen.PerApp,
    Screen.Settings,
    Screen.Logs
)

