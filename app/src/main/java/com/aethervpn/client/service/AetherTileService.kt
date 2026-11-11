package com.aethervpn.client.service

import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

@RequiresApi(Build.VERSION_CODES.N)
class AetherTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        val tile = qsTile ?: return
        val isConnected = VpnStateHolder.state.value.status == VpnStatus.CONNECTED
        tile.state = if (isConnected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.updateTile()
    }

    override fun onClick() {
        super.onClick()
        val isConnected = VpnStateHolder.state.value.status == VpnStatus.CONNECTED
        val intent = Intent(this, AetherVpnService::class.java).apply {
            action = if (isConnected) AetherVpnService.ACTION_DISCONNECT else AetherVpnService.ACTION_CONNECT
        }
        if (isConnected) {
            startService(intent)
        } else {
            // Launch main activity to trigger consent / server selection
            val appIntent = packageManager.getLaunchIntentForPackage(packageName)
            appIntent?.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(appIntent)
        }
    }
}
