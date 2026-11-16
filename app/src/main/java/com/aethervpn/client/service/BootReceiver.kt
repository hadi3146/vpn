package com.aethervpn.client.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import com.aethervpn.client.data.datastore.PreferencesManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

/**
 * Restores VPN protection automatically after device boot when enabled in settings
 * and system VPN consent is already granted.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                val settings = PreferencesManager(context).settingsFlow.first()
                if (!settings.autoConnectBoot) return@launch
                if (VpnService.prepare(context) != null) {
                    VpnStateHolder.log("Auto-connect on boot skipped: VPN permission not granted.")
                    return@launch
                }

                val bestServer = AetherVpnService.findBestStoredServer(context) ?: return@launch
                ContextCompat.startForegroundService(
                    context,
                    AetherVpnService.buildConnectIntent(context, bestServer)
                )
            } catch (e: Exception) {
                VpnStateHolder.log("Auto-connect on boot error: ${e.message}")
            } finally {
                pendingResult.finish()
            }
        }
    }
}
