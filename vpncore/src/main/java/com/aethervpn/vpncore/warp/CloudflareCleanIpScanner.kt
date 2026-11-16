package com.aethervpn.vpncore.warp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket

data class CleanEndpoint(
    val ip: String,
    val port: Int,
    val pingMs: Long
)

object CloudflareCleanIpScanner {

    // Curated high-yield Anycast prefixes known to bypass Iranian filtering
    val CANDIDATE_IPS = listOf(
        // 188.114.96.0/24 - 188.114.99.0/24
        "188.114.97.1", "188.114.96.1", "188.114.98.1", "188.114.99.1",
        "188.114.97.2", "188.114.96.2", "188.114.98.2", "188.114.99.2",
        "188.114.97.10", "188.114.96.10", "188.114.98.10", "188.114.99.10",
        "188.114.97.66", "188.114.98.66", "188.114.96.66", "188.114.99.66",
        "188.114.97.120", "188.114.98.120", "188.114.96.120", "188.114.99.120",
        "188.114.97.150", "188.114.98.150", "188.114.96.150", "188.114.99.150",
        // 162.159.192.0/24 - 162.159.195.0/24
        "162.159.192.1", "162.159.193.1", "162.159.195.1",
        "162.159.192.2", "162.159.193.2", "162.159.195.2",
        "162.159.192.10", "162.159.193.10", "162.159.195.10",
        "162.159.192.66", "162.159.193.66", "162.159.195.66",
        "162.159.192.120", "162.159.193.120", "162.159.195.120",
        "162.159.192.150", "162.159.193.150", "162.159.195.150",
        // 172.64.0.0/16 Anycast nodes
        "172.64.155.1", "172.64.156.1", "172.64.157.1", "172.64.158.1",
        "172.64.155.2", "172.64.156.2", "172.64.157.2",
        // 104.16.0.0 - 104.28.0.0 edge
        "104.16.132.229", "104.16.133.229", "104.19.154.25", "104.20.154.25"
    )

    // Curated ports: 2408 (WARP standard), 500 & 1701 (IPsec/L2TP bypass ports), 443 (HTTPS), 854, 880, 8080
    val CANDIDATE_PORTS = listOf(2408, 500, 1701, 443, 854, 880, 989, 990, 8080)

    suspend fun findBestCleanEndpoint(
        targetPort: Int = 2408,
        timeoutMs: Int = 850,
        sampleSize: Int = 16
    ): CleanEndpoint? = withContext(Dispatchers.IO) {
        val candidates = findTopCleanEndpoints(
            targetPort = targetPort,
            timeoutMs = timeoutMs,
            sampleSize = sampleSize,
            maxResults = 1
        )
        candidates.firstOrNull()
    }

    /**
     * Probes candidate Cloudflare Anycast IPs and returns the top [maxResults] clean endpoints
     * paired with diverse fallback ports (e.g. 2408, 500, 1701, 443) for resilient multi-port rotation.
     */
    suspend fun findTopCleanEndpoints(
        targetPort: Int = 2408,
        timeoutMs: Int = 850,
        sampleSize: Int = 24,
        maxResults: Int = 5
    ): List<CleanEndpoint> = withContext(Dispatchers.IO) {
        val shuffledIps = CANDIDATE_IPS.shuffled().take(sampleSize)
        val validPings = coroutineScope {
            val jobs = shuffledIps.map { ip ->
                async {
                    probeEndpoint(ip, 443, timeoutMs)
                }
            }
            jobs.awaitAll().filterNotNull().sortedBy { it.pingMs }
        }

        if (validPings.isEmpty()) return@withContext emptyList()

        val portPool = listOf(
            targetPort,
            if (targetPort != 500) 500 else 1701,
            if (targetPort != 1701) 1701 else 2408,
            if (targetPort != 443) 443 else 880,
            854
        )

        validPings.take(maxResults).mapIndexed { idx, res ->
            val assignedPort = portPool[idx % portPool.size]
            res.copy(port = assignedPort)
        }
    }

    private fun probeEndpoint(ip: String, port: Int, timeoutMs: Int): CleanEndpoint? {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                val duration = System.currentTimeMillis() - start
                CleanEndpoint(ip, port, duration)
            }
        } catch (_: Exception) {
            null
        }
    }
}
