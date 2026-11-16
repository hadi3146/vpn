package com.aethervpn.vpncore.transport

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

data class RaceCandidate(
    val id: String,
    val host: String,
    val ipAddress: InetAddress,
    val port: Int,
    val preferredStrategy: SniStrategy? = null,
    val customSni: String? = null
)

data class ServerRaceOutcome(
    val winner: RaceCandidate?,
    val diagnosis: CensorshipDiagnosis?,
    val blockedCandidateIds: Set<String>,
    val failedCandidateIds: Set<String>,
    val allDiagnoses: Map<String, CensorshipDiagnosis>,
    val elapsedMs: Long
)

/**
 * Parallel multi-server bypass racer.
 * Probes up to K diverse server candidates simultaneously using isolated probe executors,
 * picks the first server + bypass strategy that completes a clean TLS handshake, and cancels
 * all losing sockets immediately via [BypassProbeExecutor.abortPending].
 */
object MultiServerRacer {

    suspend fun raceCandidates(
        candidates: List<RaceCandidate>,
        networkProfile: String,
        strictCert: Boolean = false,
        socketProtector: SocketProtector? = null,
        tcpTimeoutMs: Int = 2200,
        probeTimeoutMs: Int = 3500,
        executorFactory: () -> BypassProbeExecutor = { LiveBypassProbeExecutor(socketProtector) }
    ): ServerRaceOutcome = withContext(Dispatchers.IO) {
        val startedAt = System.currentTimeMillis()
        if (candidates.isEmpty()) {
            return@withContext ServerRaceOutcome(
                winner = null,
                diagnosis = null,
                blockedCandidateIds = emptySet(),
                failedCandidateIds = emptySet(),
                allDiagnoses = emptyMap(),
                elapsedMs = 0L
            )
        }

        val perCandidateExecutors = ConcurrentHashMap<String, BypassProbeExecutor>()
        val diagnoses = ConcurrentHashMap<String, CensorshipDiagnosis>()
        val blockedIds = ConcurrentHashMap.newKeySet<String>()
        val failedIds = ConcurrentHashMap.newKeySet<String>()

        var winningCandidate: RaceCandidate? = null
        var winningDiagnosis: CensorshipDiagnosis? = null

        coroutineScope {
            val resultsChannel = Channel<Pair<RaceCandidate, CensorshipDiagnosis>>(candidates.size)

            for (candidate in candidates) {
                val exec = executorFactory()
                perCandidateExecutors[candidate.id] = exec
                async(Dispatchers.IO) {
                    val diag = try {
                        CensorshipDetector.detectBestStrategy(
                            host = candidate.host,
                            ipAddress = candidate.ipAddress,
                            port = candidate.port,
                            networkProfile = networkProfile,
                            preferredStrategy = candidate.preferredStrategy,
                            customSni = candidate.customSni,
                            strictCert = strictCert,
                            socketProtector = socketProtector,
                            stopOnFirstWinner = true,
                            tcpTimeoutMs = tcpTimeoutMs,
                            probeTimeoutMs = probeTimeoutMs,
                            executor = exec
                        )
                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        CensorshipDiagnosis(
                            targetHost = candidate.host,
                            targetIp = candidate.ipAddress.hostAddress.orEmpty(),
                            port = candidate.port,
                            networkProfile = networkProfile,
                            classification = FilterClassification.UNKNOWN,
                            recommendedStrategy = null
                        )
                    }
                    resultsChannel.trySend(candidate to diag)
                }
            }

            repeat(candidates.size) {
                val (cand, diag) = resultsChannel.receive()
                diagnoses[cand.id] = diag
                if (diag.classification == FilterClassification.IP_OR_PORT_BLOCKED) {
                    blockedIds.add(cand.id)
                } else if (diag.recommendedStrategy == null) {
                    failedIds.add(cand.id)
                }

                if (diag.recommendedStrategy != null) {
                    winningCandidate = cand
                    winningDiagnosis = diag
                    for ((id, exec) in perCandidateExecutors) {
                        if (id != cand.id) {
                            try { exec.abortPending() } catch (_: Exception) {}
                        }
                    }
                    coroutineContext.cancelChildren()
                    resultsChannel.close()
                    return@coroutineScope
                }
            }
            resultsChannel.close()
        }

        val elapsed = (System.currentTimeMillis() - startedAt).coerceAtLeast(1L)
        ServerRaceOutcome(
            winner = winningCandidate,
            diagnosis = winningDiagnosis,
            blockedCandidateIds = blockedIds.toSet(),
            failedCandidateIds = failedIds.toSet(),
            allDiagnoses = diagnoses.toMap(),
            elapsedMs = elapsed
        )
    }
}

