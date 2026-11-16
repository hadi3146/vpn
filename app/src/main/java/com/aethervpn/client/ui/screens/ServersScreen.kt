package com.aethervpn.client.ui.screens

import android.widget.Toast
import androidx.activity.compose.BackHandler
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
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
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aethervpn.client.R
import com.aethervpn.client.data.model.SstpUriCodec
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.repository.ServerRepository
import com.aethervpn.client.ui.theme.AccentAmber
import com.aethervpn.client.ui.theme.AccentGreen
import com.aethervpn.client.ui.theme.AccentRed
import java.util.Locale

enum class ServerSortOption {
    DEFAULT,
    PING,
    SPEED,
    SCORE,
    SESSIONS
}

private sealed interface ServerFilter {
    data object All : ServerFilter
    data object Europe : ServerFilter
    data object Healthy : ServerFilter
    data object Favorites : ServerFilter
    data object Custom : ServerFilter
    data class Country(val code: String) : ServerFilter
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ServersScreen(
    servers: List<VpnServer>,
    isRefreshing: Boolean,
    isBatchPinging: Boolean = false,
    batchPingProgress: Pair<Int, Int>? = null,
    searchQuery: String,
    onSearchQueryChange: (String) -> Unit,
    onRefresh: () -> Unit,
    onBatchPing: () -> Unit = {},
    onServerSelect: (VpnServer) -> Unit,
    onToggleFavorite: (VpnServer) -> Unit,
    onSaveCustomServer: (VpnServer, String?) -> Unit,
    onDeleteServer: (VpnServer) -> Unit = {},
    onClearCooldowns: () -> Unit = {},
    onPingTest: (VpnServer) -> Unit,
    onBackClick: () -> Unit = {}
) {
    BackHandler { onBackClick() }
    var selectedFilter by remember { mutableStateOf<ServerFilter>(ServerFilter.All) }
    var selectedSort by remember { mutableStateOf(ServerSortOption.DEFAULT) }
    var showAddDialog by remember { mutableStateOf(false) }
    var editingServer by remember { mutableStateOf<VpnServer?>(null) }
    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current
    val copiedMessage = stringResource(R.string.link_copied)

    val nowMs = System.currentTimeMillis()
    val cooldownCount = servers.count { it.cooldownUntil > nowMs }
    val europeCount = servers.count { ServerRepository.isEuropeanServer(it.countryShort) }
    val healthyCount = servers.count { it.cooldownUntil <= nowMs && (it.successCount > it.failureCount || it.ping > 0) }
    val topCountries = remember(servers) {
        servers.mapNotNull { it.countryShort.trim().uppercase().takeIf(String::isNotEmpty) }
            .groupingBy { it }
            .eachCount()
            .entries
            .sortedByDescending { it.value }
            .take(6)
    }

    val filteredServers = servers.filter { server ->
        val matchesSearch = searchQuery.isBlank() ||
                server.countryLong.contains(searchQuery, ignoreCase = true) ||
                server.countryShort.contains(searchQuery, ignoreCase = true) ||
                server.hostName.contains(searchQuery, ignoreCase = true)
        val matchesFilter = when (val filter = selectedFilter) {
            ServerFilter.All -> true
            ServerFilter.Europe -> ServerRepository.isEuropeanServer(server.countryShort)
            ServerFilter.Healthy -> server.cooldownUntil <= nowMs && (server.successCount > server.failureCount || server.ping > 0)
            ServerFilter.Favorites -> server.isFavorite
            ServerFilter.Custom -> server.isCustom
            is ServerFilter.Country -> server.countryShort.equals(filter.code, ignoreCase = true)
        }
        matchesSearch && matchesFilter
    }

    val sortedServers = remember(filteredServers, selectedSort) {
        when (selectedSort) {
            ServerSortOption.DEFAULT -> filteredServers
            ServerSortOption.PING -> filteredServers.sortedWith(
                compareBy<VpnServer> { it.ping <= 0 }
                    .thenBy { it.ping }
                    .thenByDescending { it.score }
            )
            ServerSortOption.SPEED -> filteredServers.sortedByDescending { it.speed }
            ServerSortOption.SCORE -> filteredServers.sortedByDescending { it.score }
            ServerSortOption.SESSIONS -> filteredServers.sortedBy { it.numVpnSessions }
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.nav_servers)) },
                navigationIcon = {
                    IconButton(onClick = onBackClick) {
                        Icon(
                            imageVector = Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back"
                        )
                    }
                },
                actions = {
                    IconButton(
                        onClick = onBatchPing,
                        enabled = !isBatchPinging && !isRefreshing && servers.isNotEmpty()
                    ) {
                        if (isBatchPinging) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        } else {
                            Icon(
                                Icons.Default.Speed,
                                contentDescription = stringResource(R.string.batch_ping_title)
                            )
                        }
                    }
                    IconButton(onClick = onRefresh, enabled = !isRefreshing && !isBatchPinging) {
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
            // Batch ping progress banner
            if (isBatchPinging && batchPingProgress != null) {
                val (current, total) = batchPingProgress
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 10.dp),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)
                ) {
                    Column(modifier = Modifier.padding(12.dp)) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = stringResource(R.string.batch_pinging_format, current, total),
                                style = MaterialTheme.typography.bodyMedium,
                                fontWeight = FontWeight.SemiBold,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                            Text(
                                text = "${if (total > 0) (current * 100) / total else 0}%",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onPrimaryContainer
                            )
                        }
                        Spacer(modifier = Modifier.height(6.dp))
                        LinearProgressIndicator(
                            progress = { if (total > 0) current.toFloat() / total.toFloat() else 0f },
                            modifier = Modifier
                                .fillMaxWidth()
                                .height(6.dp),
                            color = MaterialTheme.colorScheme.primary,
                            trackColor = MaterialTheme.colorScheme.onPrimaryContainer.copy(alpha = 0.25f)
                        )
                    }
                }
            }

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

            // Filter & Country Chips
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    FilterChip(
                        selected = selectedFilter == ServerFilter.All,
                        onClick = { selectedFilter = ServerFilter.All },
                        label = { Text("${stringResource(R.string.filter_all)} (${servers.size})") }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedFilter == ServerFilter.Europe,
                        onClick = { selectedFilter = ServerFilter.Europe },
                        label = { Text("${stringResource(R.string.filter_europe)} ($europeCount)") }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedFilter == ServerFilter.Healthy,
                        onClick = { selectedFilter = ServerFilter.Healthy },
                        label = { Text("${stringResource(R.string.filter_healthy)} ($healthyCount)") }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedFilter == ServerFilter.Favorites,
                        onClick = { selectedFilter = ServerFilter.Favorites },
                        label = { Text(stringResource(R.string.filter_favorites)) }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedFilter == ServerFilter.Custom,
                        onClick = { selectedFilter = ServerFilter.Custom },
                        label = { Text(stringResource(R.string.filter_custom)) }
                    )
                }
                items(topCountries, key = { it.key }) { (code, count) ->
                    FilterChip(
                        selected = (selectedFilter as? ServerFilter.Country)?.code == code,
                        onClick = { selectedFilter = ServerFilter.Country(code) },
                        label = { Text("$code ($count)") }
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Sort Option Chips
            LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                item {
                    FilterChip(
                        selected = selectedSort == ServerSortOption.DEFAULT,
                        onClick = { selectedSort = ServerSortOption.DEFAULT },
                        label = { Text(stringResource(R.string.sort_default)) }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedSort == ServerSortOption.PING,
                        onClick = { selectedSort = ServerSortOption.PING },
                        label = { Text(stringResource(R.string.sort_ping)) }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedSort == ServerSortOption.SPEED,
                        onClick = { selectedSort = ServerSortOption.SPEED },
                        label = { Text(stringResource(R.string.sort_speed)) }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedSort == ServerSortOption.SCORE,
                        onClick = { selectedSort = ServerSortOption.SCORE },
                        label = { Text(stringResource(R.string.sort_score)) }
                    )
                }
                item {
                    FilterChip(
                        selected = selectedSort == ServerSortOption.SESSIONS,
                        onClick = { selectedSort = ServerSortOption.SESSIONS },
                        label = { Text(stringResource(R.string.sort_sessions)) }
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            if (isRefreshing) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.verifying_servers),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            if (cooldownCount > 0) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = AccentAmber.copy(alpha = 0.14f))
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = stringResource(R.string.cooldown_banner_format, cooldownCount),
                            style = MaterialTheme.typography.bodySmall,
                            color = AccentAmber,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.weight(1f)
                        )
                        TextButton(onClick = onClearCooldowns) {
                            Text(
                                text = stringResource(R.string.reset_cooldowns),
                                color = AccentAmber,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                items(sortedServers, key = { it.hostName }) { server ->
                    ServerListItem(
                        server = server,
                        nowMs = nowMs,
                        onClick = { onServerSelect(server) },
                        onFavoriteClick = { onToggleFavorite(server) },
                        onEditClick = { editingServer = server },
                        onDeleteClick = { onDeleteServer(server) },
                        onShareClick = {
                            val link = SstpUriCodec.encode(server)
                            clipboardManager.setText(AnnotatedString(link))
                            Toast.makeText(context, copiedMessage, Toast.LENGTH_SHORT).show()
                        },
                        onPingClick = { onPingTest(server) }
                    )
                }
            }
        }
    }

    val activeDialogServer = if (showAddDialog) null else editingServer
    if (showAddDialog || editingServer != null) {
        CustomServerDialog(
            initialServer = activeDialogServer,
            onDismiss = {
                showAddDialog = false
                editingServer = null
            },
            onSave = { customServer ->
                onSaveCustomServer(customServer, editingServer?.hostName)
                showAddDialog = false
                editingServer = null
            }
        )
    }
}

@Composable
fun ServerListItem(
    server: VpnServer,
    nowMs: Long = System.currentTimeMillis(),
    onClick: () -> Unit,
    onFavoriteClick: () -> Unit,
    onEditClick: () -> Unit = {},
    onDeleteClick: () -> Unit = {},
    onShareClick: () -> Unit = {},
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
                val protoTag = if (server.isCustom && server.logType.isNotBlank()) "[${server.logType}] " else ""
                Text(
                    text = "$protoTag${server.ip}:${server.customPort}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(modifier = Modifier.height(6.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
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
                    if (server.cooldownUntil > nowMs) {
                        Text(
                            text = stringResource(R.string.cooldown_badge),
                            style = MaterialTheme.typography.labelSmall,
                            color = AccentAmber,
                            fontWeight = FontWeight.SemiBold
                        )
                    } else if (server.successCount > server.failureCount && server.lastVerifiedAt > 0L) {
                        Text(
                            text = "✓ ${stringResource(R.string.verified_badge)}",
                            style = MaterialTheme.typography.labelSmall,
                            color = AccentGreen,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }

            if (server.isCustom) {
                IconButton(onClick = onShareClick) {
                    Icon(
                        imageVector = Icons.Default.Share,
                        contentDescription = stringResource(R.string.share_server_link),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = onEditClick) {
                    Icon(
                        imageVector = Icons.Default.Edit,
                        contentDescription = stringResource(R.string.edit_custom_server),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                IconButton(onClick = onDeleteClick) {
                    Icon(
                        imageVector = Icons.Default.Delete,
                        contentDescription = stringResource(R.string.delete_server),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
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
fun CustomServerDialog(
    initialServer: VpnServer? = null,
    onDismiss: () -> Unit,
    onSave: (VpnServer) -> Unit
) {
    var host by remember(initialServer) { mutableStateOf(initialServer?.hostName.orEmpty()) }
    var port by remember(initialServer) { mutableStateOf((initialServer?.customPort ?: 443).toString()) }
    var username by remember(initialServer) { mutableStateOf(initialServer?.customUsername ?: "vpn") }
    var password by remember(initialServer) { mutableStateOf(initialServer?.customPassword ?: "vpn") }
    var customSni by remember(initialServer) { mutableStateOf(initialServer?.customSni.orEmpty()) }
    var serverName by remember(initialServer) { mutableStateOf(initialServer?.countryLong.orEmpty()) }
    var protocolType by remember(initialServer) { mutableStateOf(initialServer?.logType.orEmpty()) }
    var importLink by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                stringResource(
                    if (initialServer == null) R.string.add_custom_server else R.string.edit_custom_server
                )
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (initialServer == null) {
                    OutlinedTextField(
                        value = importLink,
                        onValueChange = { input ->
                            importLink = input
                            val parsed = SstpUriCodec.parse(input)
                            if (parsed != null) {
                                host = parsed.hostName
                                port = parsed.customPort.toString()
                                username = parsed.customUsername
                                password = parsed.customPassword
                                customSni = parsed.customSni.orEmpty()
                                serverName = parsed.countryLong
                                protocolType = parsed.logType
                            }
                        },
                        label = { Text(stringResource(R.string.paste_sstp_link)) },
                        placeholder = { Text(stringResource(R.string.paste_sstp_hint)) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                }
                OutlinedTextField(
                    value = host,
                    onValueChange = { host = it },
                    label = { Text(stringResource(R.string.host)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = port,
                    onValueChange = { port = it },
                    label = { Text(stringResource(R.string.port)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text(stringResource(R.string.username)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text(stringResource(R.string.password)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
                OutlinedTextField(
                    value = customSni,
                    onValueChange = { customSni = it },
                    label = { Text(stringResource(R.string.custom_sni)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val trimmedHost = host.trim()
                    if (trimmedHost.isNotEmpty()) {
                        val parsedPort = port.toIntOrNull() ?: 443
                        val displayName = serverName.ifBlank { "Custom Server" }
                        val proto = protocolType.ifBlank { "SSTP" }
                        val base = initialServer ?: VpnServer(
                            hostName = trimmedHost,
                            ip = trimmedHost,
                            countryLong = displayName,
                            countryShort = proto.take(4),
                            logType = proto
                        )
                        onSave(
                            base.copy(
                                hostName = trimmedHost,
                                ip = trimmedHost,
                                countryLong = displayName,
                                countryShort = proto.take(4),
                                customPort = parsedPort,
                                customUsername = username.trim(),
                                customPassword = password.trim(),
                                customSni = customSni.trim().ifBlank { null },
                                isCustom = true,
                                logType = proto
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

