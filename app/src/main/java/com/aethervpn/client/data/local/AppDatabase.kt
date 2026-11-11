package com.aethervpn.client.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import com.aethervpn.client.data.model.VpnServer

@Database(entities = [VpnServer::class], version = 1, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun vpnServerDao(): VpnServerDao
}

