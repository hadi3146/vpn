package com.aethervpn.client.data.repository

import android.content.Context
import com.aethervpn.client.data.local.VpnServerDao
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.source.VpnGateCsvParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ServerRepository @Inject constructor(
    private val context: Context,
    private val vpnServerDao: VpnServerDao,
    private val okHttpClient: OkHttpClient
) {
    val allServers: Flow<List<VpnServer>> = vpnServerDao.getAllServers()
    val favoriteServers: Flow<List<VpnServer>> = vpnServerDao.getFavorites()
    val customServers: Flow<List<VpnServer>> = vpnServerDao.getCustomServers()

    suspend fun refreshServers(mirrorUrl: String = "https://www.vpngate.net/api/iphone/"): Result<Int> = withContext(Dispatchers.IO) {
        try {
            var csvBytes: ByteArray? = null
            val urls = mirrorUrl.split("\n", ";", ",").map { it.trim() }.filter { it.isNotBlank() }

            for (url in urls) {
                try {
                    val request = Request.Builder().url(url).build()
                    val response = okHttpClient.newCall(request).execute()
                    if (response.isSuccessful) {
                        val body = response.body?.bytes()
                        if (body != null && body.isNotEmpty()) {
                            csvBytes = body
                            break
                        }
                    }
                } catch (_: Exception) {}
            }

            // Fallback to bundled snapshot if network failed
            if (csvBytes == null) {
                try {
                    context.assets.open("vpngate_fallback.csv").use {
                        csvBytes = it.readBytes()
                    }
                } catch (_: Exception) {}
            }

            if (csvBytes == null) {
                return@withContext Result.failure(Exception("Failed to fetch VPN Gate servers from network and fallback"))
            }

            val parsed = VpnGateCsvParser.parse(ByteArrayInputStream(csvBytes))
            if (parsed.isNotEmpty()) {
                vpnServerDao.clearVpnGateServers()
                vpnServerDao.insertAll(parsed)
                Result.success(parsed.size)
            } else {
                Result.failure(Exception("No valid SSTP servers parsed"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun testServerPing(server: VpnServer): Int = withContext(Dispatchers.IO) {
        val start = System.currentTimeMillis()
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(server.ip, server.customPort), 3000)
                val ping = (System.currentTimeMillis() - start).toInt()
                vpnServerDao.updatePing(server.hostName, ping)
                ping
            }
        } catch (_: Exception) {
            -1
        }
    }

    suspend fun toggleFavorite(server: VpnServer) {
        vpnServerDao.setFavorite(server.hostName, !server.isFavorite)
    }

    suspend fun addCustomServer(server: VpnServer) {
        vpnServerDao.insert(server.copy(isCustom = true))
    }

    suspend fun deleteServer(server: VpnServer) {
        vpnServerDao.deleteByHost(server.hostName)
    }

    suspend fun getBestServer(): VpnServer? = withContext(Dispatchers.IO) {
        // Find best server by score and responsiveness
        val favorites = vpnServerDao.getServerByHost("dummy") // or query top server
        null
    }
}
