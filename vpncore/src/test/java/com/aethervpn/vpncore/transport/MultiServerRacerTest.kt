package com.aethervpn.vpncore.transport

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicInteger

class MultiServerRacerTest {

    @Test
    fun picksFastestPassingCandidateAbortsLosersAndFlagsBlockedHost() = runBlocking {
        val abortCalls = AtomicInteger(0)

        val blockedHost = RaceCandidate(
            id = "blocked-1",
            host = "blocked.opengw.net",
            ipAddress = InetAddress.getByName("198.51.100.1"),
            port = 443
        )
        val slowHost = RaceCandidate(
            id = "slow-2",
            host = "slow.opengw.net",
            ipAddress = InetAddress.getByName("198.51.100.2"),
            port = 443
        )
        val fastHost = RaceCandidate(
            id = "fast-3",
            host = "fast.opengw.net",
            ipAddress = InetAddress.getByName("198.51.100.3"),
            port = 443
        )

        val execIndex = AtomicInteger(0)
        val outcome = MultiServerRacer.raceCandidates(
            candidates = listOf(blockedHost, slowHost, fastHost),
            networkProfile = "CELLULAR",
            executorFactory = {
                val idx = execIndex.getAndIncrement()
                object : BypassProbeExecutor {
                    override fun checkTcpReachable(ipAddress: InetAddress, port: Int, timeoutMs: Int): Boolean {
                        return ipAddress.hostAddress != "198.51.100.1"
                    }

                    override fun testTlsStrategy(
                        strategy: SniStrategy,
                        host: String,
                        ipAddress: InetAddress,
                        port: Int,
                        customSni: String?,
                        strictCert: Boolean,
                        timeoutMs: Int
                    ): String? {
                        return when (ipAddress.hostAddress) {
                            "198.51.100.2" -> {
                                try { Thread.sleep(1500) } catch (_: InterruptedException) {}
                                "Timeout"
                            }
                            "198.51.100.3" -> {
                                Thread.sleep(15)
                                if (strategy == SniStrategy.TLS_HEADER_DESYNC) null else "TCP RST"
                            }
                            else -> "Blocked"
                        }
                    }

                    override fun abortPending() {
                        abortCalls.incrementAndGet()
                    }
                }
            }
        )

        assertNotNull(outcome.winner)
        assertEquals("fast-3", outcome.winner!!.id)
        assertEquals(SniStrategy.TLS_HEADER_DESYNC, outcome.diagnosis?.recommendedStrategy)
        assertTrue(outcome.blockedCandidateIds.contains("blocked-1"))
        assertTrue(abortCalls.get() >= 1)
    }
}

