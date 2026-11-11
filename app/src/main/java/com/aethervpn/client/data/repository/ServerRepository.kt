package com.aethervpn.client.data.repository

import android.content.Context
import com.aethervpn.client.data.local.VpnServerDao
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.data.source.VpnGateCsvParser
import dagger.hilt.android.qualifiers.ApplicationContext
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
    @ApplicationContext private val context: Context,
    private val vpnServerDao: VpnServerDao,
    private val okHttpClient: OkHttpClient
) {
    val allServers: Flow<List<VpnServer>> = vpnServerDao.getAllServers()
    val favoriteServers: Flow<List<VpnServer>> = vpnServerDao.getFavorites()
    val customServers: Flow<List<VpnServer>> = vpnServerDao.getCustomServers()

    suspend fun ensureInitialized(): Int = withContext(Dispatchers.IO) {
        val currentCount = vpnServerDao.getServerCount()
        if (currentCount == 0) {
            val loaded = loadBundledFallback()
            com.aethervpn.client.service.VpnStateHolder.log("Prepopulated $loaded servers from bundled cache.")
            loaded
        } else {
            currentCount
        }
    }

    private suspend fun loadBundledFallback(): Int = withContext(Dispatchers.IO) {
        try {
            context.assets.open("vpngate_fallback.csv").use { stream ->
                val parsed = VpnGateCsvParser.parse(stream)
                if (parsed.isNotEmpty()) {
                    vpnServerDao.insertAll(parsed)
                    return@withContext parsed.size
                }
            }
        } catch (e: Exception) {
            com.aethervpn.client.service.VpnStateHolder.log("Error loading fallback: ${e.message}")
        }
        0
    }

    suspend fun refreshServers(mirrorUrl: String = "https://www.vpngate.net/api/iphone/"): Result<Int> = withContext(Dispatchers.IO) {
        try {
            ensureInitialized()
            var csvBytes: ByteArray? = null
            val urls = mirrorUrl.split("\n", ";", ",").map { it.trim() }.filter { it.isNotBlank() }

            for (url in urls) {
                try {
                    com.aethervpn.client.service.VpnStateHolder.log("Fetching server list from $url...")
                    val request = Request.Builder().url(url).build()
                    val response = okHttpClient.newCall(request).execute()
                    if (response.isSuccessful) {
                        val body = response.body?.bytes()
                        if (body != null && body.isNotEmpty()) {
                            csvBytes = body
                            com.aethervpn.client.service.VpnStateHolder.log("Server list fetched (${body.size} bytes).")
                            break
                        }
                    }
                } catch (e: Exception) {
                    com.aethervpn.client.service.VpnStateHolder.log("Mirror $url unavailable: ${e.message}")
                }
            }

            // Fallback to bundled snapshot if network failed
            if (csvBytes == null) {
                com.aethervpn.client.service.VpnStateHolder.log("All network mirrors failed. Using bundled server cache.")
                val loaded = loadBundledFallback()
                return@withContext Result.success(loaded)
            }

            val parsed = VpnGateCsvParser.parse(ByteArrayInputStream(csvBytes))
            if (parsed.isNotEmpty()) {
                vpnServerDao.clearVpnGateServers()
                vpnServerDao.insertAll(parsed)
                com.aethervpn.client.service.VpnStateHolder.log("Successfully loaded ${parsed.size} VPN Gate servers.")
                Result.success(parsed.size)
            } else {
                loadBundledFallback()
                Result.success(vpnServerDao.getServerCount())
            }
        } catch (e: Exception) {
            com.aethervpn.client.service.VpnStateHolder.log("Refresh error: ${e.message}")
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
                com.aethervpn.client.service.VpnStateHolder.log("Ping to ${server.countryLong.ifBlank { server.hostName }}: ${ping}ms")
                ping
            }
        } catch (e: Exception) {
            com.aethervpn.client.service.VpnStateHolder.log("Ping to ${server.countryLong.ifBlank { server.hostName }} failed (${e.message ?: "timeout"})")
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

