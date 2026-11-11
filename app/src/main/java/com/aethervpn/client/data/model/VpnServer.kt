package com.aethervpn.client.data.model

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "vpn_servers")
data class VpnServer(
    @PrimaryKey
    val hostName: String,
    val ip: String,
    val score: Long = 0,
    val ping: Int = -1,
    val speed: Long = 0,
    val countryLong: String = "",
    val countryShort: String = "",
    val numVpnSessions: Long = 0,
    val uptime: Long = 0,
    val totalUsers: Long = 0,
    val totalTraffic: Long = 0,
    val logType: String = "",
    val operator: String = "",
    val message: String = "",
    val sstpSupported: Boolean = true,
    val isCustom: Boolean = false,
    val isFavorite: Boolean = false,
    val customPort: Int = 443,
    val customUsername: String = "vpn",
    val customPassword: String = "vpn",
    val customSni: String? = null
)

