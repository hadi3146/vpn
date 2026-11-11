package com.aethervpn.client.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import com.aethervpn.client.data.datastore.PreferencesManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action == Intent.ACTION_BOOT_COMPLETED) {
            CoroutineScope(Dispatchers.IO).launch {
                val pref = PreferencesManager(context)
                val settings = pref.settingsFlow.first()
                if (settings.autoConnectBoot) {
                    // Start VPN service with quick connect or last server
                }
            }
        }
    }
}

