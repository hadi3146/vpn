package com.aethervpn.client.ui.screens

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.UserSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class InstalledApp(
    val packageName: String,
    val appName: String,
    val isSystem: Boolean
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PerAppFilterScreen(
    settings: UserSettings,
    onModeChange: (SplitTunnelMode) -> Unit,
    onAllowedPackagesChange: (Set<String>) -> Unit,
    onDisallowedPackagesChange: (Set<String>) -> Unit
) {
    val context = LocalContext.current
    var showSystemApps by remember { mutableStateOf(false) }
    var appSearch by remember { mutableStateOf("") }
    var appList by remember { mutableStateOf<List<InstalledApp>>(emptyList()) }

    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            val list = packages.map { appInfo ->
                InstalledApp(
                    packageName = appInfo.packageName,
                    appName = appInfo.loadLabel(pm).toString(),
                    isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }.sortedBy { it.appName.lowercase() }
            withContext(Dispatchers.Main) {
                appList = list
            }
        }
    }

    val activeSelected = when (settings.splitTunnelMode) {
        SplitTunnelMode.ALLOWED_ONLY -> settings.allowedPackages
        SplitTunnelMode.DISALLOWED_ONLY -> settings.disallowedPackages
        else -> emptySet()
    }

    val filteredApps = appList.filter { app ->
        (showSystemApps || !app.isSystem) &&
                (appSearch.isBlank() || app.appName.contains(appSearch, ignoreCase = true) || app.packageName.contains(appSearch, ignoreCase = true))
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.split_tunnel_title)) })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
        ) {
            // Mode Selectors
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
            ) {
                Column(modifier = Modifier.padding(8.dp)) {
                    SplitModeOption(
                        label = stringResource(R.string.split_mode_all),
                        selected = settings.splitTunnelMode == SplitTunnelMode.ALL_APPS,
                        onClick = { onModeChange(SplitTunnelMode.ALL_APPS) }
                    )
                    SplitModeOption(
                        label = stringResource(R.string.split_mode_allowed),
                        selected = settings.splitTunnelMode == SplitTunnelMode.ALLOWED_ONLY,
                        onClick = { onModeChange(SplitTunnelMode.ALLOWED_ONLY) }
                    )
                    SplitModeOption(
                        label = stringResource(R.string.split_mode_disallowed),
                        selected = settings.splitTunnelMode == SplitTunnelMode.DISALLOWED_ONLY,
                        onClick = { onModeChange(SplitTunnelMode.DISALLOWED_ONLY) }
                    )
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (settings.splitTunnelMode != SplitTunnelMode.ALL_APPS) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(stringResource(R.string.show_system_apps), style = MaterialTheme.typography.bodySmall)
                    Switch(checked = showSystemApps, onCheckedChange = { showSystemApps = it })
                }

                Spacer(modifier = Modifier.height(8.dp))

                OutlinedTextField(
                    value = appSearch,
                    onValueChange = { appSearch = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text("Search installed applications…") },
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp)
                )

                Spacer(modifier = Modifier.height(8.dp))

                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    items(filteredApps, key = { it.packageName }) { app ->
                        val isChecked = activeSelected.contains(app.packageName)
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    val newSet = if (isChecked) activeSelected - app.packageName else activeSelected + app.packageName
                                    if (settings.splitTunnelMode == SplitTunnelMode.ALLOWED_ONLY) {
                                        onAllowedPackagesChange(newSet)
                                    } else {
                                        onDisallowedPackagesChange(newSet)
                                    }
                                },
                            shape = RoundedCornerShape(10.dp),
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(app.appName, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.SemiBold)
                                    Text(app.packageName, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                Checkbox(
                                    checked = isChecked,
                                    onCheckedChange = { checked ->
                                        val newSet = if (checked) activeSelected + app.packageName else activeSelected - app.packageName
                                        if (settings.splitTunnelMode == SplitTunnelMode.ALLOWED_ONLY) {
                                            onAllowedPackagesChange(newSet)
                                        } else {
                                            onDisallowedPackagesChange(newSet)
                                        }
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SplitModeOption(label: String, selected: Boolean, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onClick() }
            .padding(vertical = 6.dp, horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Text(text = label, modifier = Modifier.padding(start = 8.dp), style = MaterialTheme.typography.bodyMedium)
    }
}

