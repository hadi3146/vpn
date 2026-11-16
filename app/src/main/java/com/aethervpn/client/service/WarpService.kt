package com.aethervpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.datastore.VpnProtocol
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.ui.MainActivity
import com.aethervpn.vpncore.warp.CleanEndpoint
import com.aethervpn.vpncore.warp.CloudflareCleanIpScanner
import com.aethervpn.vpncore.warp.WarpAccount
import com.aethervpn.vpncore.warp.WarpConfigBuilder
import com.aethervpn.vpncore.warp.WarpRegistrar
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

class WarpService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnelJob: Job? = null
    private var statsJob: Job? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    private lateinit var preferencesManager: PreferencesManager
    private var backend: GoBackend? = null
    private var activeCleanEndpoint: CleanEndpoint? = null
    private var activeAccount: WarpAccount? = null
    private var isConnected = false

    private val warpTunnel = object : Tunnel {
        override fun getName(): String = "radin-warp"
        override fun onStateChange(state: Tunnel.State) {
            VpnStateHolder.log("WARP WireGuard tunnel state: $state")
            if (state == Tunnel.State.DOWN && isConnected) {
                VpnStateHolder.updateStatus(VpnStatus.DISCONNECTED)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        preferencesManager = PreferencesManager(applicationContext)
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createNotificationChannel()
        backend = GoBackend(applicationContext)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notif = buildNotification(getString(R.string.status_connecting))
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, notif)
            }
        } catch (e: Exception) {
            VpnStateHolder.log("startForeground notice: ${e.message}")
        }

        when (intent?.action) {
            ACTION_CONNECT -> {
                startWarpTunnel()
            }
            ACTION_DISCONNECT -> {
                disconnectWarp()
            }
            ACTION_RESCAN -> {
                rescanAndReconnect()
            }
        }
        return START_NOT_STICKY
    }

    private fun startWarpTunnel() {
        tunnelJob?.cancel()
        tunnelJob = serviceScope.launch {
            try {
                VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "در حال اسکن آی‌پی تمیز کلودفلر...")
                VpnStateHolder.updateConnectPhase(ConnectPhase.CONNECTING_WITH_BYPASS, "اسکن Anycast Clean IP")
                updateNotification("در حال اسکن آی‌پی تمیز کلودفلر...")

                val settings = preferencesManager.settingsFlow.first()

                // Step 1: Discover top candidate clean Anycast IPs paired with diverse ports
                val candidateEndpoints = CloudflareCleanIpScanner.findTopCleanEndpoints(
                    targetPort = settings.warpPort.takeIf { it > 0 } ?: 2408,
                    timeoutMs = 950,
                    sampleSize = 24,
                    maxResults = 4
                ).ifEmpty {
                    listOf(
                        CleanEndpoint(ip = "188.114.97.1", port = settings.warpPort.takeIf { it > 0 } ?: 2408, pingMs = 45),
                        CleanEndpoint(ip = "162.159.192.1", port = 500, pingMs = 60),
                        CleanEndpoint(ip = "188.114.96.1", port = 1701, pingMs = 55)
                    )
                }

                // Step 2: Get or register WARP account
                var account = WarpAccount.fromJson(settings.warpAccountJson)
                if (account == null) {
                    VpnStateHolder.log("ثبت حساب کاربری رایگان WARP در کلودفلر...")
                    VpnStateHolder.updateStatus(VpnStatus.AUTHENTICATING, "ثبت نام حساب کاربری WARP...")
                    account = WarpRegistrar.registerAccount()
                    preferencesManager.updateWarpAccountJson(account.toJson())
                    VpnStateHolder.log("حساب WARP با موفقیت ایجاد شد: ID=${account.id.take(8)}... Warp+=${account.isWarpPlus}")
                }
                activeAccount = account

                // Step 3: Handle Split Tunneling
                val excludedPackages = when (settings.splitTunnelMode) {
                    SplitTunnelMode.DISALLOWED_ONLY -> settings.disallowedPackages
                    else -> emptySet()
                }
                val includedPackages = when (settings.splitTunnelMode) {
                    SplitTunnelMode.ALLOWED_ONLY -> settings.allowedPackages
                    else -> emptySet()
                }

                // Step 4: Multi-Endpoint & Port Rotation Probe Loop
                val backendInstance = backend ?: GoBackend(applicationContext).also { backend = it }
                var activeSuccessEndpoint: CleanEndpoint? = null

                for ((idx, endpoint) in candidateEndpoints.withIndex()) {
                    VpnStateHolder.log("🚀 آزمایش اتصال به گره کلودفلر [${idx + 1}/${candidateEndpoints.size}]: ${endpoint.ip}:${endpoint.port} (پینگ اولیه: ${endpoint.pingMs}ms)...")
                    updateNotification("آزمایش گره کلودفلر (${endpoint.ip}:${endpoint.port})...")

                    val config = WarpConfigBuilder.buildConfig(
                        account = account,
                        endpoint = endpoint,
                        mtu = if (settings.mtu in 1200..1420) settings.mtu else 1280,
                        keepaliveSec = if (settings.keepaliveSec > 0) settings.keepaliveSec else 25,
                        excludedApps = excludedPackages,
                        includedApps = includedPackages
                    )

                    try {
                        backendInstance.setState(warpTunnel, Tunnel.State.UP, config)
                        isConnected = true

                        VpnStateHolder.updateConnectPhase(ConnectPhase.VERIFYING_INTERNET, "بررسی تبادل داده UDP و دسترسی به تلگرام (${endpoint.port})")
                        val connectivityOk = verifyTunnelConnectivity(backendInstance)
                        if (connectivityOk) {
                            activeSuccessEndpoint = endpoint
                            VpnStateHolder.log("✅ گره کلودفلر ${endpoint.ip}:${endpoint.port} تایید شد (ترافیک داده و تلگرام متصل است).")
                            break
                        } else {
                            VpnStateHolder.log("⚠️ گره ${endpoint.ip}:${endpoint.port} پاسخ UDP دریافت نکرد؛ سوئیچ به گره بعدی...")
                            try { backendInstance.setState(warpTunnel, Tunnel.State.DOWN, null) } catch (_: Exception) {}
                            isConnected = false
                        }
                    } catch (e: Exception) {
                        VpnStateHolder.log("خطا در تست گره ${endpoint.ip}:${endpoint.port}: ${e.message}")
                    }
                }

                if (activeSuccessEndpoint == null) {
                    VpnStateHolder.log("⚠️ تمامی پورت‌ها و گره‌های Anycast کلودفلر توسط اپراتور مسدود شده‌اند.")
                    VpnStateHolder.log("🔄 اتصال هوشمند رادین: در حال جابجایی خودکار به پروتکل قدرتمند SoftEther SSTP (با دور زدن فیلترینگ Zapret)...")
                    VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "مسدودی UDP؛ جابجایی خودکار به SSTP ضد فیلتر...")
                    updateNotification("مسدودی UDP؛ اتصال به سرور ضد فیلتر...")

                    teardownWireGuardSilently()

                    // Automatically update preference to SSTP so future connections start directly with SSTP
                    preferencesManager.updateVpnProtocol(VpnProtocol.SSTP)

                    val fallbackServer = AetherVpnService.findBestStoredServer(applicationContext)
                    if (fallbackServer != null) {
                        VpnStateHolder.log("🚀 شروع اتصال خودکار به سرور ضد فیلتر: ${fallbackServer.countryLong.ifBlank { fallbackServer.hostName }} (${fallbackServer.ip})")
                        val sstpIntent = AetherVpnService.buildConnectIntent(applicationContext, fallbackServer)
                        ContextCompat.startForegroundService(applicationContext, sstpIntent)
                    } else {
                        VpnStateHolder.updateStatus(VpnStatus.ERROR, "پروتکل WARP مسدود است و سرور ضد فیلتر یافت نشد.")
                    }

                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                    return@launch
                }

                val cleanEndpoint = activeSuccessEndpoint
                activeCleanEndpoint = cleanEndpoint

                // Step 5: Update UI & Status upon verified connectivity
                val cfServer = VpnServer(
                    hostName = "Cloudflare WARP",
                    ip = cleanEndpoint.ip,
                    customPort = cleanEndpoint.port,
                    countryLong = "Cloudflare WARP (سریع و نامحدود)",
                    countryShort = "CF",
                    ping = cleanEndpoint.pingMs.toInt()
                )
                VpnStateHolder.updateConnected(
                    server = cfServer,
                    clientIp = account.assignedIpv4,
                    strategy = "Anycast Clean IP (${cleanEndpoint.ip}:${cleanEndpoint.port})",
                    physicalNetworkLabel = "WARP WireGuard"
                )

                updateNotification("WARP متصل شد • ${cleanEndpoint.ip}")
                registerNetworkCallback()
                startMetricsLoop()

            } catch (e: CancellationException) {
                // Cancelled
            } catch (e: Exception) {
                VpnStateHolder.log("WARP connection failed: ${e.message}")
                VpnStateHolder.updateStatus(VpnStatus.ERROR, e.message ?: "خطا در اتصال به WARP")
                updateNotification("خطا در اتصال به WARP")
            }
        }
    }

    private fun startMetricsLoop() {
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            var lastRx = 0L
            var lastTx = 0L
            var durationSec = 0L
            var lastTime = System.currentTimeMillis()

            while (isActive && isConnected) {
                delay(1000)
                durationSec++
                try {
                    val stats = backend?.getStatistics(warpTunnel)
                    if (stats != null) {
                        val currentRx = stats.totalRx()
                        val currentTx = stats.totalTx()
                        val now = System.currentTimeMillis()
                        val elapsedSec = ((now - lastTime) / 1000.0).coerceAtLeast(1.0)
                        val speedRx = (((currentRx - lastRx).toDouble() / elapsedSec).toLong()).coerceAtLeast(0L)
                        val speedTx = (((currentTx - lastTx).toDouble() / elapsedSec).toLong()).coerceAtLeast(0L)

                        lastRx = currentRx
                        lastTx = currentTx
                        lastTime = now

                        VpnStateHolder.updateMetrics(
                            bytesIn = currentRx,
                            bytesOut = currentTx,
                            speedIn = speedRx,
                            speedOut = speedTx,
                            duration = durationSec
                        )

                        val speedStr = formatSpeed(speedRx)
                        updateNotification("WARP متصل است • ↓ $speedStr")
                    }
                } catch (_: Exception) {}
            }
        }
    }

    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        val cm = connectivityManager ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network) ?: return
                val isCellular = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                val isWifi = caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                val label = if (isWifi) "Wi-Fi" else if (isCellular) "Cellular (موبایل)" else "Network"
                VpnStateHolder.log("Network changed to: $label. Roaming WireGuard connection...")
            }

            override fun onLost(network: Network) {
                VpnStateHolder.log("Previous network lost. WireGuard will roam automatically.")
            }
        }
        networkCallback = callback
        try {
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            cm.registerNetworkCallback(req, callback)
        } catch (e: Exception) {
            VpnStateHolder.log("NetworkCallback registration warning: ${e.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
            networkCallback = null
        }
    }

    private suspend fun verifyTunnelConnectivity(backendInstance: GoBackend): Boolean = withContext(Dispatchers.IO) {
        val startTime = System.currentTimeMillis()
        var rxSeen = false

        // Parallel probe: Telegram MTProto endpoints and Cloudflare HTTP
        val probeJob = async {
            val tgEndpoints = listOf(
                InetSocketAddress("149.154.167.50", 443),
                InetSocketAddress("149.154.167.91", 443),
                InetSocketAddress("149.154.167.92", 443),
                InetSocketAddress("91.108.56.165", 443)
            )
            for (ep in tgEndpoints) {
                try {
                    Socket().use { s ->
                        s.connect(ep, 2000)
                        return@async true
                    }
                } catch (_: Exception) {}
            }
            // Probe HTTP generate_204
            try {
                val url = URL("http://cp.cloudflare.com/generate_204")
                val conn = url.openConnection() as HttpURLConnection
                conn.connectTimeout = 2000
                conn.readTimeout = 2000
                conn.instanceFollowRedirects = false
                val code = conn.responseCode
                conn.disconnect()
                if (code in 200..399) return@async true
            } catch (_: Exception) {}
            false
        }

        // Wait up to 3.8s, checking backend statistics periodically
        while (System.currentTimeMillis() - startTime < 3800L) {
            delay(400)
            try {
                val stats = backendInstance.getStatistics(warpTunnel)
                if (stats != null && stats.totalRx() > 0) {
                    rxSeen = true
                    break
                }
            } catch (_: Exception) {}
            if (probeJob.isCompleted && probeJob.getCompleted()) {
                return@withContext true
            }
        }

        val probeResult = try {
            withTimeoutOrNull(600) { probeJob.await() } ?: false
        } catch (_: Exception) { false }

        VpnStateHolder.log("WARP tunnel connectivity probe: RxSeen=$rxSeen, RealProbe=$probeResult")
        return@withContext (rxSeen && probeResult) || probeResult
    }

    private suspend fun teardownWireGuardSilently() {
        isConnected = false
        statsJob?.cancel()
        unregisterNetworkCallback()
        try {
            backend?.setState(warpTunnel, Tunnel.State.DOWN, null)
        } catch (e: Exception) {
            VpnStateHolder.log("Notice tearing down WireGuard: ${e.message}")
        }
    }

    private fun rescanAndReconnect() {
        serviceScope.launch {
            VpnStateHolder.log("Rescanning clean Cloudflare IP for optimal routing...")
            startWarpTunnel()
        }
    }

    private fun disconnectWarp() {
        isConnected = false
        tunnelJob?.cancel()
        statsJob?.cancel()
        unregisterNetworkCallback()

        serviceScope.launch {
            try {
                backend?.setState(warpTunnel, Tunnel.State.DOWN, null)
            } catch (e: Exception) {
                VpnStateHolder.log("Error tearing down WireGuard tunnel: ${e.message}")
            } finally {
                withContext(Dispatchers.Main) {
                    VpnStateHolder.updateStatus(VpnStatus.DISCONNECTED)
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }
            }
        }
    }

    override fun onDestroy() {
        disconnectWarp()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Radin VPN - WARP",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live Cloudflare WARP connection status"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(statusText: String): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java)
        val pOpenIntent = PendingIntent.getActivity(
            this, 0, openAppIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = Intent(this, WarpService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pDisconnect = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val rescanIntent = Intent(this, WarpService::class.java).apply {
            action = ACTION_RESCAN
        }
        val pRescan = PendingIntent.getService(
            this, 2, rescanIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Radin VPN • Cloudflare WARP")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pOpenIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(0, "تغییر آی‌پی تمیز", pRescan)
            .addAction(0, getString(R.string.disconnect), pDisconnect)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    private fun formatSpeed(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB/s", bytesPerSec / (1024.0 * 1024.0))
            bytesPerSec >= 1024 -> String.format(java.util.Locale.US, "%.0f KB/s", bytesPerSec / 1024.0)
            else -> "$bytesPerSec B/s"
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.aethervpn.client.WARP_CONNECT"
        const val ACTION_DISCONNECT = "com.aethervpn.client.WARP_DISCONNECT"
        const val ACTION_RESCAN = "com.aethervpn.client.WARP_RESCAN"

        private const val CHANNEL_ID = "radin_warp_channel"
        private const val NOTIFICATION_ID = 2001

        fun buildConnectIntent(context: Context): Intent =
            Intent(context, WarpService::class.java).apply {
                action = ACTION_CONNECT
            }

        fun buildDisconnectIntent(context: Context): Intent =
            Intent(context, WarpService::class.java).apply {
                action = ACTION_DISCONNECT
            }
    }
}
