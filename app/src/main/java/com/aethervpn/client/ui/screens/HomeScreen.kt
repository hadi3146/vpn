package com.aethervpn.client.ui.screens

import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.FlashOn
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Timer
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.aethervpn.client.R
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.service.VpnSessionState
import com.aethervpn.client.service.VpnStatus
import com.aethervpn.client.ui.theme.AccentGreen
import com.aethervpn.client.ui.theme.AccentRed
import java.util.Locale

@Composable
fun HomeScreen(
    vpnState: VpnSessionState,
    selectedServer: VpnServer?,
    onConnectClick: () -> Unit,
    onDisconnectClick: () -> Unit,
    onQuickConnectClick: () -> Unit,
    onSelectServerClick: () -> Unit
) {
    val isConnected = vpnState.status == VpnStatus.CONNECTED
    val isConnecting = vpnState.status == VpnStatus.CONNECTING || vpnState.status == VpnStatus.AUTHENTICATING

    val infiniteTransition = rememberInfiniteTransition(label = "pulse")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isConnecting) 1.15f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(800, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "scale"
    )

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        // Status Badge
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(20.dp))
                .background(
                    when (vpnState.status) {
                        VpnStatus.CONNECTED -> AccentGreen.copy(alpha = 0.15f)
                        VpnStatus.ERROR -> AccentRed.copy(alpha = 0.15f)
                        VpnStatus.CONNECTING, VpnStatus.AUTHENTICATING -> MaterialTheme.colorScheme.primary.copy(alpha = 0.15f)
                        else -> MaterialTheme.colorScheme.surfaceVariant
                    }
                )
                .padding(horizontal = 16.dp, vertical = 8.dp)
        ) {
            Text(
                text = when (vpnState.status) {
                    VpnStatus.CONNECTED -> stringResource(R.string.status_connected)
                    VpnStatus.CONNECTING -> stringResource(R.string.status_connecting)
                    VpnStatus.AUTHENTICATING -> stringResource(R.string.status_authenticating)
                    VpnStatus.DISCONNECTING -> stringResource(R.string.status_disconnecting)
                    VpnStatus.ERROR -> vpnState.errorMessage ?: stringResource(R.string.status_error)
                    else -> stringResource(R.string.status_disconnected)
                },
                color = when (vpnState.status) {
                    VpnStatus.CONNECTED -> AccentGreen
                    VpnStatus.ERROR -> AccentRed
                    else -> MaterialTheme.colorScheme.onSurface
                },
                fontWeight = FontWeight.SemiBold
            )
        }

        Spacer(modifier = Modifier.height(30.dp))

        // Big Power / Connect Button
        Box(
            modifier = Modifier
                .size(170.dp)
                .scale(pulseScale)
                .clip(CircleShape)
                .background(
                    if (isConnected) AccentGreen else MaterialTheme.colorScheme.primary
                )
                .clickable {
                    if (isConnected || isConnecting) {
                        onDisconnectClick()
                    } else {
                        onConnectClick()
                    }
                },
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.PowerSettingsNew,
                contentDescription = "Power",
                tint = Color.White,
                modifier = Modifier.size(70.dp)
            )
        }

        Spacer(modifier = Modifier.height(20.dp))

        Text(
            text = if (isConnected) stringResource(R.string.disconnect) else stringResource(R.string.connect),
            style = MaterialTheme.typography.titleLarge,
            fontWeight = FontWeight.Bold
        )

        Spacer(modifier = Modifier.height(30.dp))

        // Real-time Metrics Card
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceAround
                ) {
                    // Download
                    MetricItem(
                        icon = Icons.Default.ArrowDownward,
                        label = stringResource(R.string.download_speed),
                        value = formatSpeed(vpnState.speedInBps),
                        color = AccentGreen
                    )
                    // Upload
                    MetricItem(
                        icon = Icons.Default.ArrowUpward,
                        label = stringResource(R.string.upload_speed),
                        value = formatSpeed(vpnState.speedOutBps),
                        color = MaterialTheme.colorScheme.primary
                    )
                    // Duration
                    MetricItem(
                        icon = Icons.Default.Timer,
                        label = stringResource(R.string.duration),
                        value = formatDuration(vpnState.durationSeconds),
                        color = MaterialTheme.colorScheme.secondary
                    )
                }

                Spacer(modifier = Modifier.height(12.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "${stringResource(R.string.data_transferred)}: ${formatBytes(vpnState.bytesIn + vpnState.bytesOut)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (vpnState.publicIp.isNotBlank()) {
                        Text(
                            text = "${stringResource(R.string.public_ip)}: ${vpnState.publicIp}",
                            style = MaterialTheme.typography.bodySmall,
                            color = AccentGreen,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Selected Server Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onSelectServerClick() },
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Default.Public,
                    contentDescription = "Server",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(36.dp)
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = selectedServer?.countryLong?.ifBlank { selectedServer.hostName } ?: "Select Server",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        text = selectedServer?.hostName ?: "Tap to choose a VPN server",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        // Quick Connect Button
        Button(
            onClick = onQuickConnectClick,
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(12.dp),
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary)
        ) {
            Icon(Icons.Default.FlashOn, contentDescription = null)
            Spacer(modifier = Modifier.width(8.dp))
            Text(stringResource(R.string.quick_connect), fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
fun MetricItem(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, value: String, color: Color) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(icon, contentDescription = label, tint = color, modifier = Modifier.size(22.dp))
        Spacer(modifier = Modifier.height(4.dp))
        Text(text = value, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
        Text(text = label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

private fun formatSpeed(bps: Long): String {
    return when {
        bps >= 1_000_000 -> String.format(Locale.US, "%.1f Mbps", bps / 1_000_000.0)
        bps >= 1_000 -> String.format(Locale.US, "%.0f kbps", bps / 1_000.0)
        else -> "$bps bps"
    }
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_073_741_824 -> String.format(Locale.US, "%.2f GB", bytes / 1_073_741_824.0)
        bytes >= 1_048_576 -> String.format(Locale.US, "%.1f MB", bytes / 1_048_576.0)
        bytes >= 1024 -> String.format(Locale.US, "%.0f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}

private fun formatDuration(seconds: Long): String {
    val hrs = seconds / 3600
    val mins = (seconds % 3600) / 60
    val secs = seconds % 60
    return if (hrs > 0) {
        String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    } else {
        String.format(Locale.US, "%02d:%02d", mins, secs)
    }
}

