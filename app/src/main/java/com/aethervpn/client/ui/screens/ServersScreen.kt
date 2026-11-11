package com.aethervpn.client.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aethervpn.client.R
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.ui.theme.AccentAmber
import com.aethervpn.client.ui.theme.AccentGreen
import com.aethervpn.client.ui.theme.AccentRed
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServersScreen(
    servers: List<VpnServer>,
    isRefreshing: Boolean,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onRefresh: () -> Unit,
    onServerSelect: (VpnServer) -> Unit,
    onToggleFavorite: (VpnServer) -> Unit,
    onAddCustomServer: (VpnServer) -> Unit,
    onPingTest: (VpnServer) -> Unit
) {
    var selectedFilter by remember { mutableStateOf(0) } // 0: All, 1: Favorites, 2: Custom
    var showAddDialog by remember { mutableStateOf(false) }

    val filteredServers = servers.filter { server ->
        val matchesSearch = searchQuery.isBlank() ||
                server.countryLong.contains(searchQuery, ignoreCase = true) ||
                server.hostName.contains(searchQuery, ignoreCase = true)
        val matchesFilter = when (selectedFilter) {
            1 -> server.isFavorite
            2 -> server.isCustom
            else -> true
        }
        matchesSearch && matchesFilter
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_servers)) },
                actions = {
                    IconButton(onClick = onRefresh) {
                        if (isRefreshing) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(Icons.Default.Refresh, contentDescription = "Refresh")
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddDialog = true },
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Add Custom Server")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            // Search field
            OutlinedTextField(
                value = searchQuery,
                onValueChange = onSearchQueryChange,
                modifier = Modifier.fillMaxWidth(),
                placeholder = { Text(stringResource(R.string.search_servers)) },
                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )

            Spacer(modifier = Modifier.height(10.dp))

            // Filter Chips
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                FilterChip(
                    selected = selectedFilter == 0,
                    onClick = { selectedFilter = 0 },
                    label = { Text("All (${servers.size})") }
                )
                FilterChip(
                    selected = selectedFilter == 1,
                    onClick = { selectedFilter = 1 },
                    label = { Text("Favorites") }
                )
                FilterChip(
                    selected = selectedFilter == 2,
                    onClick = { selectedFilter = 2 },
                    label = { Text("Custom") }
                )
            }

            Spacer(modifier = Modifier.height(10.dp))

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(filteredServers, key = { it.hostName }) { server ->
                    ServerListItem(
                        server = server,
                        onClick = { onServerSelect(server) },
                        onFavoriteClick = { onToggleFavorite(server) },
                        onPingClick = { onPingTest(server) }
                    )
                }
            }
        }
    }

    if (showAddDialog) {
        AddCustomServerDialog(
            onDismiss = { showAddDialog = false },
            onSave = { customServer ->
                onAddCustomServer(customServer)
                showAddDialog = false
            }
        )
    }
}

@Composable
fun ServerListItem(
    server: VpnServer,
    onClick: () -> Unit,
    onFavoriteClick: () -> Unit,
    onPingClick: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() },
        shape = RoundedCornerShape(14.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = server.countryLong.ifBlank { "Custom Server" },
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    if (server.countryShort.isNotBlank()) {
                        Text(
                            text = " (${server.countryShort})",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "${server.ip}:${server.customPort}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        text = if (server.ping > 0) "${server.ping} ms" else "Ping test",
                        style = MaterialTheme.typography.labelSmall,
                        color = when {
                            server.ping in 1..100 -> AccentGreen
                            server.ping > 100 -> AccentAmber
                            else -> MaterialTheme.colorScheme.primary
                        },
                        fontWeight = FontWeight.SemiBold,
                        modifier = Modifier.clickable { onPingClick() }
                    )
                    if (server.speed > 0) {
                        Text(
                            text = String.format(Locale.US, "%.1f Mbps", server.speed / 1_000_000.0),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            IconButton(onClick = onFavoriteClick) {
                Icon(
                    imageVector = if (server.isFavorite) Icons.Default.Star else Icons.Default.StarBorder,
                    contentDescription = "Favorite",
                    tint = if (server.isFavorite) AccentAmber else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
fun AddCustomServerDialog(
    onDismiss: () -> Unit,
    onSave: (VpnServer) -> Unit
) {
    var host by remember { mutableStateOf("") }
    var port by remember { mutableStateOf("443") }
    var username by remember { mutableStateOf("vpn") }
    var password by remember { mutableStateOf("vpn") }
    var customSni by remember { mutableStateOf("") }
    var strictCert by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.add_custom_server)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text(stringResource(R.string.host)) },
                    singleLine = true
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it },
                    label = { Text(stringResource(R.string.port)) },
                    singleLine = true
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text(stringResource(R.string.username)) },
                    singleLine = true
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.password)) },
                    singleLine = true
                )
                OutlinedTextField(
                    value = customSni,
                    onValueChange = { customSni = it },
                    label = { Text(stringResource(R.string.custom_sni)) },
                    singleLine = true
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(stringResource(R.string.strict_cert_title), style = MaterialTheme.typography.bodySmall)
                    Switch(checked = strictCert, onCheckedChange = { strictCert = it })
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    if (host.isNotBlank()) {
                        val parsedPort = port.toIntOrNull() ?: 443
                        onSave(
                            VpnServer(
                                hostName = host.trim(),
                                ip = host.trim(),
                                customPort = parsedPort,
                                customUsername = username.trim(),
                                customPassword = password.trim(),
                                customSni = customSni.trim().ifBlank { null },
                                isCustom = true
                            )
                        )
                    }
                }
            ) {
                Text(stringResource(R.string.save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.cancel))
            }
        }
    )
}

