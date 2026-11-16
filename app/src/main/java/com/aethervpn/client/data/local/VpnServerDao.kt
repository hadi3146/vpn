package com.aethervpn.client.data.local

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.aethervpn.client.data.model.VpnServer
import kotlinx.coroutines.flow.Flow

@Dao
interface VpnServerDao {

    @Query("SELECT COUNT(*) FROM vpn_servers")
    suspend fun getServerCount(): Int

    @Query("""
        SELECT * FROM vpn_servers 
        ORDER BY 
            isFavorite DESC, 
            CASE WHEN ip LIKE '219.100.37.%' THEN 1 ELSE 0 END ASC,
            CASE WHEN countryShort IN ('RU', 'IR', 'CN', 'BY', 'SY', 'CU', 'KP') THEN 1 ELSE 0 END ASC,
            score DESC, 
            ping ASC
    """)
    fun getAllServers(): Flow<List<VpnServer>>

    @Query("SELECT * FROM vpn_servers WHERE isFavorite = 1 ORDER BY score DESC")
    fun getFavorites(): Flow<List<VpnServer>>

    @Query("SELECT * FROM vpn_servers WHERE isCustom = 1")
    fun getCustomServers(): Flow<List<VpnServer>>

    @Query("SELECT * FROM vpn_servers WHERE hostName = :hostName LIMIT 1")
    suspend fun getServerByHost(hostName: String): VpnServer?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(servers: List<VpnServer>)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(server: VpnServer)

    @Update
    suspend fun update(server: VpnServer)

    @Query("UPDATE vpn_servers SET isFavorite = :isFavorite WHERE hostName = :hostName")
    suspend fun setFavorite(hostName: String, isFavorite: Boolean)

    @Query("UPDATE vpn_servers SET ping = :ping WHERE hostName = :hostName")
    suspend fun updatePing(hostName: String, ping: Int)

    @Query("UPDATE vpn_servers SET customPort = :port WHERE hostName = :hostName")
    suspend fun updatePort(hostName: String, port: Int)

    @Query("UPDATE vpn_servers SET successCount = successCount + 1, failureCount = 0, cooldownUntil = 0, lastVerifiedAt = :now WHERE hostName = :hostName")
    suspend fun recordSuccess(hostName: String, now: Long)

    @Query("UPDATE vpn_servers SET failureCount = failureCount + 1, cooldownUntil = :cooldownUntil WHERE hostName = :hostName")
    suspend fun recordFailure(hostName: String, cooldownUntil: Long)

    @Query("UPDATE vpn_servers SET cooldownUntil = 0, failureCount = 0")
    suspend fun clearCooldowns()

    @Query("DELETE FROM vpn_servers WHERE isCustom = 0")
    suspend fun clearVpnGateServers()

    @Query("DELETE FROM vpn_servers WHERE hostName = :hostName")
    suspend fun deleteByHost(hostName: String)
}

