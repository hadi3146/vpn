package com.aethervpn.client.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.aethervpn.client.R
import com.aethervpn.client.data.datastore.DnsMode
import com.aethervpn.client.data.datastore.PreferencesManager
import com.aethervpn.client.data.datastore.SplitTunnelMode
import com.aethervpn.client.data.model.VpnServer
import com.aethervpn.client.ui.MainActivity
import com.aethervpn.vpncore.dns.DnsOverTlsClient
import com.aethervpn.vpncore.dns.DnsResolver
import com.aethervpn.vpncore.sstp.SstpClient
import com.aethervpn.vpncore.sstp.SstpConfig
import com.aethervpn.vpncore.sstp.SstpEventListener
import com.aethervpn.vpncore.sstp.SstpState
import com.aethervpn.vpncore.sstp.VpnParameters
import com.aethervpn.vpncore.transport.SniStrategy
import com.aethervpn.vpncore.transport.SocketProtector
import com.aethervpn.vpncore.tun.MssClamper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class AetherVpnService : VpnService(), SstpEventListener, SocketProtector {

    companion object {
        const val ACTION_CONNECT = "com.aethervpn.client.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.aethervpn.client.ACTION_DISCONNECT"
        const val EXTRA_SERVER_HOST = "extra_server_host"
        const val EXTRA_SERVER_IP = "extra_server_ip"
        const val EXTRA_SERVER_PORT = "extra_server_port"
        const val EXTRA_SERVER_USER = "extra_server_user"
        const val EXTRA_SERVER_PASS = "extra_server_pass"
        const val EXTRA_SERVER_COUNTRY = "extra_server_country"
        const val NOTIFICATION_ID = 1001
        const val CHANNEL_ID = "aether_vpn_channel"
    }

    private val serviceScope = CoroutineScope(Dispatchers.Default + Job())
    private var vpnInterface: ParcelFileDescriptor? = null
    private var sstpClient: SstpClient? = null
    private var dotClient: DnsOverTlsClient? = null
    private val isRunning = AtomicBoolean(false)

    private var currentServer: VpnServer? = null
    private var sessionStartTime = 0L
    private val totalTxBytes = AtomicLong(0)
    private val totalRxBytes = AtomicLong(0)
    private val prevTxBytes = AtomicLong(0)
    private val prevRxBytes = AtomicLong(0)

    private var metricsJob: Job? = null
    private var tunReaderJob: Job? = null
    private var tunWriterJob: Job? = null

    private lateinit var connectivityManager: ConnectivityManager
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            setUnderlyingNetworks(arrayOf(network))
        }

        override fun onLost(network: Network) {
            setUnderlyingNetworks(null)
        }
    }

    override fun onCreate() {
        super.onCreate()
        connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_SERVER_HOST) ?: return START_NOT_STICKY
                val ip = intent.getStringExtra(EXTRA_SERVER_IP) ?: host
                val port = intent.getIntExtra(EXTRA_SERVER_PORT, 443)
                val user = intent.getStringExtra(EXTRA_SERVER_USER) ?: "vpn"
                val pass = intent.getStringExtra(EXTRA_SERVER_PASS) ?: "vpn"
                val country = intent.getStringExtra(EXTRA_SERVER_COUNTRY) ?: ""

                val server = VpnServer(
                    hostName = host,
                    ip = ip,
                    customPort = port,
                    customUsername = user,
                    customPassword = pass,
                    countryLong = country
                )
                currentServer = server
                startVpn(server)
            }
            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(server: VpnServer) {
        if (!isRunning.compareAndSet(false, true)) return
        sessionStartTime = System.currentTimeMillis()
        totalTxBytes.set(0)
        totalRxBytes.set(0)
        prevTxBytes.set(0)
        prevRxBytes.set(0)

        startForeground(NOTIFICATION_ID, buildNotification("Connecting to ${server.hostName}..."))
        VpnStateHolder.updateStatus(VpnStatus.CONNECTING, "Resolving host...")

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, networkCallback)

        serviceScope.launch(Dispatchers.IO) {
            val prefManager = PreferencesManager(applicationContext)
            val settings = prefManager.settingsFlow.first()

            // Setup DoT client if enabled
            if (settings.dnsMode != DnsMode.VPN_DEFAULT) {
                val resolver = DnsResolver.findById(settings.selectedDnsId)
                dotClient = DnsOverTlsClient(resolver = resolver, socketProtector = this@AetherVpnService)
            }

            // SNI strategy auto-fallback list
            val strategies = if (settings.sniStrategy == SniStrategy.DISABLED) {
                listOf(SniStrategy.DISABLED)
            } else {
                listOf(
                    settings.sniStrategy,
                    SniStrategy.DIRECT_IP_NO_SNI,
                    SniStrategy.TCP_FRAGMENTATION,
                    SniStrategy.TLS_RECORD_FRAGMENTATION
                ).distinct()
            }

            var connected = false
            for (strategy in strategies) {
                if (!isRunning.get()) break
                try {
                    val inetAddr = InetAddress.getByName(server.ip)
                    val sstpConfig = SstpConfig(
                        host = server.hostName,
                        ipAddress = inetAddr,
                        port = server.customPort,
                        username = server.customUsername,
                        password = server.customPassword,
                        mtu = settings.mtu,
                        keepaliveIntervalSec = settings.keepaliveSec,
                        strictCert = settings.strictCert,
                        sniStrategy = strategy,
                        customSni = settings.customSni.ifBlank { null }
                    )

                    val client = SstpClient(
                        config = sstpConfig,
                        socketProtector = this@AetherVpnService,
                        listener = this@AetherVpnService
                    )
                    sstpClient = client
                    client.start(this)
                    connected = true
                    break
                } catch (e: Exception) {
                    if (isRunning.get()) {
                        delay(1000)
                    }
                }
            }

            if (!connected && isRunning.get()) {
                VpnStateHolder.updateStatus(VpnStatus.ERROR, "Failed to connect to server")
                stopVpn()
            }
        }

        startMetricsReporting()
    }

    override fun onStateChanged(state: SstpState, message: String?) {
        when (state) {
            SstpState.CONNECTING_TCP, SstpState.TLS_HANDSHAKE, SstpState.HTTP_HANDSHAKE -> {
                VpnStateHolder.updateStatus(VpnStatus.CONNECTING, message)
                updateNotification(message ?: "Connecting...")
            }
            SstpState.SSTP_CONNECTING, SstpState.PPP_LCP, SstpState.PPP_AUTH, SstpState.PPP_IPCP -> {
                VpnStateHolder.updateStatus(VpnStatus.AUTHENTICATING, message)
                updateNotification(message ?: "Authenticating...")
            }
            SstpState.CONNECTED -> {
                currentServer?.let { s ->
                    VpnStateHolder.updateConnected(s, message ?: "", sstpClient?.let { "Active" } ?: "")
                }
                updateNotification("Connected (${currentServer?.hostName})")
                fetchPublicIp()
            }
            SstpState.DISCONNECTING -> {
                VpnStateHolder.updateStatus(VpnStatus.DISCONNECTING)
            }
            SstpState.DISCONNECTED -> {
                VpnStateHolder.updateStatus(VpnStatus.DISCONNECTED)
            }
        }
    }

    override fun onParametersEstablished(params: VpnParameters) {
        serviceScope.launch(Dispatchers.IO) {
            establishTun(params)
        }
    }

    private suspend fun establishTun(params: VpnParameters) {
        val prefManager = PreferencesManager(applicationContext)
        val settings = prefManager.settingsFlow.first()

        val builder = Builder()
            .setSession("AetherVpn")
            .setMtu(params.mtu)
            .addAddress(params.clientIp, 32)

        if (settings.dnsMode == DnsMode.DNS_ONLY) {
            // DNS Only mode: route only DNS address
            builder.addDnsServer("10.254.254.254")
            builder.addRoute("10.254.254.254", 32)
        } else {
            // Normal VPN mode
            val primaryDns = if (settings.dnsMode == DnsMode.DOT_OVER_SSTP) "1.1.1.1" else params.primaryDns
            builder.addDnsServer(primaryDns)
            if (params.secondaryDns.isNotBlank() && params.secondaryDns != "0.0.0.0") {
                builder.addDnsServer(params.secondaryDns)
            }
            builder.addRoute("0.0.0.0", 0)
        }

        // Split tunneling application filters
        when (settings.splitTunnelMode) {
            SplitTunnelMode.ALLOWED_ONLY -> {
                for (pkg in settings.allowedPackages) {
                    try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
                }
            }
            SplitTunnelMode.DISALLOWED_ONLY -> {
                for (pkg in settings.disallowedPackages) {
                    try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                }
            }
            SplitTunnelMode.ALL_APPS -> {}
        }

        builder.setBlocking(true)
        val pfd = builder.establish() ?: throw IllegalStateException("Cannot establish TUN interface")
        vpnInterface = pfd

        // Start reading from TUN
        tunReaderJob = serviceScope.launch(Dispatchers.IO) {
            val fis = FileInputStream(pfd.fileDescriptor)
            val buffer = ByteArray(32768)
            val maxMss = params.mtu - 40
            while (isActive && isRunning.get()) {
                val length = fis.read(buffer)
                if (length > 0) {
                    // Apply MSS Clamping to prevent path MTU issues
                    MssClamper.clampMss(buffer, length, maxMss)
                    sstpClient?.sendIpPacket(buffer, length)
                }
            }
        }
    }

    override fun onDataPacketReceived(packet: ByteArray) {
        val pfd = vpnInterface ?: return
        try {
            val fos = FileOutputStream(pfd.fileDescriptor)
            fos.write(packet)
            fos.flush()
        } catch (_: Exception) {}
    }

    override fun onBytesTransferred(txBytesDelta: Long, rxBytesDelta: Long) {
        totalTxBytes.addAndGet(txBytesDelta)
        totalRxBytes.addAndGet(rxBytesDelta)
    }

    override fun onError(t: Throwable) {
        VpnStateHolder.updateStatus(VpnStatus.ERROR, t.message ?: "Connection error")
        stopVpn()
    }

    private fun startMetricsReporting() {
        metricsJob = serviceScope.launch {
            while (isActive && isRunning.get()) {
                delay(1000)
                val curTx = totalTxBytes.get()
                val curRx = totalRxBytes.get()
                val speedTx = (curTx - prevTxBytes.getAndSet(curTx)) * 8
                val speedRx = (curRx - prevRxBytes.getAndSet(curRx)) * 8
                val duration = if (sessionStartTime > 0) (System.currentTimeMillis() - sessionStartTime) / 1000 else 0

                VpnStateHolder.updateMetrics(
                    bytesIn = curRx,
                    bytesOut = curTx,
                    speedIn = speedRx,
                    speedOut = speedTx,
                    duration = duration
                )
            }
        }
    }

    private fun fetchPublicIp() {
        serviceScope.launch(Dispatchers.IO) {
            try {
                val okHttp = OkHttpClient.Builder().callTimeout(5, java.util.concurrent.TimeUnit.SECONDS).build()
                val req = Request.Builder().url("https://api.ipify.org").build()
                val resp = okHttp.newCall(req).execute()
                val ip = resp.body?.string()?.trim() ?: ""
                if (ip.isNotBlank()) {
                    VpnStateHolder.updatePublicIp(ip)
                }
            } catch (_: Exception) {}
        }
    }

    private fun stopVpn() {
        if (!isRunning.compareAndSet(true, false)) return
        metricsJob?.cancel()
        tunReaderJob?.cancel()
        tunWriterJob?.cancel()
        sstpClient?.close()
        dotClient?.close()
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        try { connectivityManager.unregisterNetworkCallback(networkCallback) } catch (_: Exception) {}
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        VpnStateHolder.reset()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Aether VPN Tunnel",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows live VPN connection status"
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

        val disconnectIntent = Intent(this, AetherVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val pDisconnect = PendingIntent.getService(
            this, 1, disconnectIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Aether VPN")
            .setContentText(statusText)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pOpenIntent)
            .setOngoing(true)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", pDisconnect)
            .build()
    }

    private fun updateNotification(statusText: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(statusText))
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}

