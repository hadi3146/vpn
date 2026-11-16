package com.aethervpn.client.data.local

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.aethervpn.client.data.model.VpnServer

@Database(entities = [VpnServer::class], version = 3, exportSchema = false)
abstract class AppDatabase : RoomDatabase() {
    abstract fun vpnServerDao(): VpnServerDao

    companion object {
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_isFavorite ON vpn_servers(isFavorite)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_score ON vpn_servers(score)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_ping ON vpn_servers(ping)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_isCustom ON vpn_servers(isCustom)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_countryShort ON vpn_servers(countryShort)")
                db.execSQL("CREATE INDEX IF NOT EXISTS index_vpn_servers_cooldownUntil ON vpn_servers(cooldownUntil)")
            }
        }
    }
}

