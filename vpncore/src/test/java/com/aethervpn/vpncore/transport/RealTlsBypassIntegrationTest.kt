package com.aethervpn.vpncore.transport

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.Executors
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket

class RealTlsBypassIntegrationTest {

    private companion object {
        // Test-only self-signed localhost PKCS12 keystore (password: "changeit")
        private const val TEST_PKCS12_B64 =
            "MIIKIAIBAzCCCcoGCSqGSIb3DQEHAaCCCbsEggm3MIIJszCCBaoGCSqGSIb3DQEHAaCCBZsEggWX" +
                "MIIFkzCCBY8GCyqGSIb3DQEMCgECoIIFQDCCBTwwZgYJKoZIhvcNAQUNMFkwOAYJKoZIhvcNAQUM" +
                "MCsEFL1NG7sL3t0YdAakH6NWvVXroOBGAgInEAIBIDAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQB" +
                "KgQQEYnNkFkoBtvUPhfa+w4S1gSCBNCH/Q1Da641Si0KiDbyhOyQ5VJmxlBdFNeEYJLKTuj18Hgm" +
                "wIzOYWVCqae4e3XLZ4CzycBAbXFS3jcKAOmmGnut0vGXAXcTEzq9S6Hj5Q2qrMkQBSOVOUKoE9a8" +
                "VCPxmiMvIcpW/ry35XLnqG0wP3vSvxM5UYdbgoNI/5mV7PgUy4/plRumqCAMT1RJIkFJ9nKhNCmm" +
                "e+04Zzpgi4/hUKbrLolqA2YNtIBFDsMY3BWC9JQKONUbd9zwiuJ9YJatwMFNtHASQmlLh3gwE++4" +
                "Ji8uMipiesjDBubGjJG8d6a2De9lY/p2nBOmEAhrqCDEs3DSRhxE1In5BfsOWqP62Jbe8eYu5QQp" +
                "esaALNL9gCOa00AstX/WaawI2AGj+R1nOYBVwzsWg08CNzvMkPuM9OOaQsrNkamod5yMn5T023yO" +
                "qLUxzWYnU45kWQMwvp/vEVkYP6uKz6l1q98zZ9v6rRUE9y9XHMmXY1UeWOTduWW2OoHGSQNce2Y7" +
                "oSaWy8KJ2N3XK5nXD1UAT3d2Opqh9g4Bf0WYg+c/DLC1cZkghbmci9gVtQ/qFAPHZLPYKKmTU5fG" +
                "QkQsKLhGFFNB/AH/4Jwb35iHSGzdxJ52O+aWy2oBEOnG6NEyHzoebrlTjvgSyu5mcTh7caARjUun" +
                "S03v6SkXro0jUq29se7/TA8Ts/W7gn3K6TLm+D1GngQNmGBVh4CUwiDLx7Amqt3SHG4Wo4zNSAgW" +
                "L46khauWJbn1JVH23Vd7/8SeJWG5gkGGhhi6D8dECnNhJlhwcJhIl+V6UN2Q1Ly/e7c4X9hINnVvM" +
                "SMEA0vjnEi7CWQsJLxPG1AkI0vurus/9wpjNYn6zAH+CisIMGqdE/xy84kIZ1Vpa35cZ7r64N4hVt" +
                "HSfrm3Sgm97SCxdUl+vuJ7nY4MM/MIWSQrakZpFOweBlj/d8KgLLw0dyW+DqoE9FiZB6OL5DqAVcb" +
                "Nz5BsK/qYvCN4Xw4erQ76V0t6g5ESrt340CFjbJ2IXtJwtsfhDvkQpsZB7ZcQa9TGqQxFHf5HDoW" +
                "U59+h9lPNsr2BhILsQJjzcZd2njlHBDZLzP717//ox/M8CeFCHv+68FVH9eRg2dq9jyaEZfGHMRS" +
                "iyULdMAZJOyMnyADq0bLpd0C8YI0fL4dCJVSflzYPfUveOrh/ek5jHXxnUgITg3Xa3nZwRyLRjip2" +
                "eKXmGCH1Z0ZVypmEUjOGF96vfUhSwkGu0BYDGMX6RnmUo+TW4p/FyJj2/4Myc7BRGQt/lpqWd0kvI" +
                "Dovp13wYq+BUiXmsJUg5Mt65r9s3IuQdbLdEVrXcOxfXGHMHySIjn3fOMcCVzCkDojazDw8m82vDl" +
                "pMnf3gP5ronrkCJ6CVUxS+ylBVJ5CwRezXG7mq+Pag2NxfecJWKQCIXCE817HTYpCOj0cpu8VG1jh" +
                "54UHFg7yKJGHTRkFT0I1tOZ3BAuucZYEueJejPXb+S33ERsqP4Lj0tCGWWmxB6Wt8bxISlvuOIY0t" +
                "5PVeIhvvJSOeQ+vlIsv/0xMZNDdEfiOWo4amo65ZDX2To5NcPSk0qndQLMCf0z26XKTVSdC1cE0M+" +
                "u7D7P1xIWB+GHgnqXSS/Fv19bj1/eG/yoNqGWwhxGMgZ2sCaG6irUSOdendP1UKQVheiTE8MBcGCS" +
                "qGSIb3DQEJFDEKHggAdABlAHMAdDAhBgkqhkiG9w0BCRUxFAQSVGltZSAxNzk0NDgwODYxMjgyMIIE" +
                "AQYJKoZIhvcNAQcGoIID8jCCA+4CAQAwggPnBgkqhkiG9w0BBwEwZgYJKoZIhvcNAQUNMFkwOAYJ" +
                "KoZIhvcNAQUMMCsEFPEA3u33UbxoJJx2c9SU2qns8Wu9AgInEAIBIDAMBggqhkiG9w0CCQUAMB0G" +
                "CWCGSAFlAwQBKgQQ3Hu7kAiw6MEZgGQDXa/eaoCCA3BlqIqR0lsME0SC6ijSL3inXlQmWAaGjaAk" +
                "uN24TUveRSuIKHkcTlEpFDG+ug4QkGtp0Uucl1cydnHsuJAKaKGcptDNjbesCCL2k9nWD15L5Slt" +
                "FRpG6z7xSzqwgfnWhegnpQQpB2gKKkiwLKBYBdnRgveefcgr+9HH6OMLKOWjKfB0Rcchk3gYvsR8" +
                "QoqxGSut6ptzQzh1wqWOvvkkOADDgG0G4UadUfv0fz7Rhr41Kpc7RnNzRKN0plBOA2PGrIJwwbTw" +
                "kFxSnfMRy0lQV5+W/Qv5ZDfmIdCD/w8BNIdaUCIzI1LUt9n5HBlCtOphmvngQjNyb+lmBGgdKfDZ" +
                "dVweZsVcCAoMSym0e3COf2E7qoXtO3DwrryROYf9auTkqaj/EW/Q4MZJR5kYBkPVDlcNYjVWxYEA" +
                "o229gTwxmnn+fsTRJKwfro3dE/xEZbQjVPAoNMic32Kr+CeHzLGjuJz8Ojytn/AjsMlqJl6LzgfH" +
                "1Njucsht9rbsqZ4IFhG76UHqJvvT02IpJj1E5vC56tdBSm8hqQ7SoezYBuoeNLnVPxQu0x06ZxSV" +
                "CKlMy1rDz5clOjxPkJkljRpMuZbQX04nCrz8ghPUJlEUWcWxisFgTYTSU3DZe4x+LZvEM3aY942U" +
                "RJeRQjzVoKroqmSE3MNQQgKqeRDOS2SJP8q63bnQbolwU0Ayz8pmQJS1i2Jf9hKCW/jNDnFs6MMT" +
                "EdC6IsCk/b0tumR6wDiGbRT1jeJEjxD5vst1VCgYvRYkHXYQ3uSdg9Mvb6v/o1w534ujps9B6iR2" +
                "Kh40lMAUqNujUwnKGx73knNqu1zHXB8Q95Ddo+MavMxSd9SrWGnpe2uxU1Qfy1bgrHK/45h18/DB" +
                "C0Rd7hwi6bLqn8jCigbU+tmjAF4VUo9nn3D0JKcHPrnUC1SO0XkMy+XjXtpuktZDexZNBSS7Faso" +
                "0BKAdlDIEN4aMnyHQX0GBSlruBvwvCSmcoWMx4SfKkap5a1+m8abrr9BDX7K2Rg7lNw+E7ErM14r" +
                "LuOVQ9R6ndhpZeEmiG0cxWB26m+wmqRwcXqr6IzE6fLKNkVWL44byFOy0+5876xAjYfOhi36Pji" +
                "D1c7k/RRwQjc7jmlCWoYgyEnzDZyyz9pFlV2Ekg693+P+xsymxcba/WKk/y3lugQ/U4qYVgw1PBX" +
                "UME0wMTANBglghkgBZQMEAgEFAAQgEpBJwr/EkyY8ooBjOhpoUVy/rjmQP2hy3qYopy6AvgAEFMEW" +
                "4HfH1sqzemOVqOCVxhohtozyAgInEA=="
    }

    private fun createLoopbackSslServer(): SSLServerSocket {
        val p12Bytes = Base64.getDecoder().decode(TEST_PKCS12_B64)
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(ByteArrayInputStream(p12Bytes), "changeit".toCharArray())
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        kmf.init(ks, "changeit".toCharArray())
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(kmf.keyManagers, null, null)
        return ctx.serverSocketFactory.createServerSocket(0, 16, InetAddress.getLoopbackAddress()) as SSLServerSocket
    }

    private fun startDpiProxy(
        targetPort: Int,
        blockedHost: String,
        dropOnIntactClientHelloHeader: Boolean
    ): Pair<ServerSocket, () -> Unit> {
        val proxySocket = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
        val pool = Executors.newCachedThreadPool()
        val blockedBytes = blockedHost.toByteArray(Charsets.US_ASCII)

        pool.submit {
            while (!proxySocket.isClosed) {
                val client = try { proxySocket.accept() } catch (_: Exception) { break }
                pool.submit {
                    var upstream: java.net.Socket? = null
                    try {
                        val cIn = client.getInputStream()
                        val firstChunk = ByteArray(4096)
                        val firstLen = cIn.read(firstChunk)
                        if (firstLen <= 0) {
                            client.close()
                            return@submit
                        }

                        val firstSlice = firstChunk.copyOf(firstLen)
                        val containsBlockedSni = indexOfBytes(firstSlice, blockedBytes) >= 0
                        val hasIntactHeaderAndBody = firstLen >= 6 &&
                            (firstSlice[0].toInt() and 0xFF) == 0x16 &&
                            (firstSlice[1].toInt() and 0xFF) == 0x03 &&
                            (firstSlice[5].toInt() and 0xFF) == 0x01

                        if (containsBlockedSni || (dropOnIntactClientHelloHeader && hasIntactHeaderAndBody)) {
                            // Simulate Iranian DPI TCP RST injection
                            client.setSoLinger(true, 0)
                            client.close()
                            return@submit
                        }

                        upstream = java.net.Socket(InetAddress.getLoopbackAddress(), targetPort)
                        val uOut = upstream.getOutputStream()
                        uOut.write(firstSlice)
                        uOut.flush()

                        val forwardBack = pool.submit {
                            try {
                                upstream.getInputStream().copyTo(client.getOutputStream())
                            } catch (_: Exception) {} finally {
                                try { client.close() } catch (_: Exception) {}
                            }
                        }
                        try {
                            cIn.copyTo(uOut)
                        } catch (_: Exception) {} finally {
                            try { upstream.close() } catch (_: Exception) {}
                            forwardBack.cancel(true)
                        }
                    } catch (_: Exception) {
                        try { client.close() } catch (_: Exception) {}
                        try { upstream?.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        val shutdown = {
            try { proxySocket.close() } catch (_: Exception) {}
            pool.shutdownNow()
            Unit
        }
        return proxySocket to shutdown
    }

    private fun indexOfBytes(haystack: ByteArray, needle: ByteArray): Int {
        if (needle.isEmpty() || haystack.size < needle.size) return -1
        outer@ for (i in 0..(haystack.size - needle.size)) {
            for (j in needle.indices) {
                if (haystack[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return -1
    }

    @Test
    fun realTlsHandshakeDefeatsSimulatedSniDpiProxy() = runBlocking {
        val tlsServer = createLoopbackSslServer()
        val serverExecutor = Executors.newCachedThreadPool()
        serverExecutor.submit {
            while (!tlsServer.isClosed) {
                val s = try { tlsServer.accept() } catch (_: Exception) { break }
                serverExecutor.submit {
                    try {
                        val buf = ByteArray(64)
                        val n = s.getInputStream().read(buf)
                        if (n > 0) {
                            s.getOutputStream().write("OK".toByteArray())
                            s.getOutputStream().flush()
                        }
                    } catch (_: Exception) {} finally {
                        try { s.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        val (dpiProxy, stopProxy) = startDpiProxy(
            targetPort = tlsServer.localPort,
            blockedHost = "blocked.opengw.net",
            dropOnIntactClientHelloHeader = false
        )

        try {
            val diagnosis = CensorshipDetector.detectBestStrategy(
                host = "blocked.opengw.net",
                ipAddress = InetAddress.getLoopbackAddress(),
                port = dpiProxy.localPort,
                networkProfile = "TEST",
                stopOnFirstWinner = false
            )

            val disabledResult = diagnosis.results.first { it.strategy == SniStrategy.DISABLED }
            val multiChunkResult = diagnosis.results.first { it.strategy == SniStrategy.MULTI_CHUNK_FRAGMENTATION }
            val desyncResult = diagnosis.results.first { it.strategy == SniStrategy.TLS_HEADER_DESYNC }
            val directIpResult = diagnosis.results.first { it.strategy == SniStrategy.DIRECT_IP_NO_SNI }

            assertTrue("Unprotected ClientHello should be dropped by DPI", !disabledResult.succeeded)
            assertTrue("TLS_HEADER_DESYNC should defeat SNI DPI", desyncResult.succeeded)
            assertTrue("MULTI_CHUNK_FRAGMENTATION should defeat SNI DPI", multiChunkResult.succeeded)
            assertTrue("DIRECT_IP_NO_SNI should bypass SNI DPI", directIpResult.succeeded)
            assertEquals(FilterClassification.SNI_DPI_ACTIVE, diagnosis.classification)

            val transport = SniBypassSocketFactory(
                strategy = SniStrategy.MULTI_CHUNK_FRAGMENTATION,
                strictCert = false
            ).createAndConnectTransport(
                host = "blocked.opengw.net",
                ipAddress = InetAddress.getLoopbackAddress(),
                port = dpiProxy.localPort,
                timeoutMs = 5000
            )
            transport.outputStream.write("PING".toByteArray(), 0, 4)
            transport.outputStream.flush()
            val reply = ByteArray(16)
            val n = transport.inputStream.read(reply, 0, reply.size)
            assertEquals("OK", String(reply, 0, n))
            transport.close()
        } finally {
            stopProxy()
            try { tlsServer.close() } catch (_: Exception) {}
            serverExecutor.shutdownNow()
        }
    }

    @Test
    fun tlsHeaderDesyncDefeatsStrictHeaderPrefixDpiOverRealTls() = runBlocking {
        val tlsServer = createLoopbackSslServer()
        val serverExecutor = Executors.newCachedThreadPool()
        serverExecutor.submit {
            while (!tlsServer.isClosed) {
                val s = try { tlsServer.accept() } catch (_: Exception) { break }
                serverExecutor.submit {
                    try {
                        val buf = ByteArray(64)
                        val n = s.getInputStream().read(buf)
                        if (n > 0) {
                            s.getOutputStream().write("OK".toByteArray())
                            s.getOutputStream().flush()
                        }
                    } catch (_: Exception) {} finally {
                        try { s.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        val (dpiProxy, stopProxy) = startDpiProxy(
            targetPort = tlsServer.localPort,
            blockedHost = "blocked.opengw.net",
            dropOnIntactClientHelloHeader = true
        )

        try {
            var directFailed = false
            try {
                SniBypassSocketFactory(strategy = SniStrategy.DISABLED, strictCert = false)
                    .createAndConnectTransport("blocked.opengw.net", InetAddress.getLoopbackAddress(), dpiProxy.localPort, 2500)
                    .close()
            } catch (_: Exception) {
                directFailed = true
            }
            assertTrue("Unfragmented ClientHello header must be dropped by strict DPI", directFailed)

            val transport = SniBypassSocketFactory(
                strategy = SniStrategy.TLS_HEADER_DESYNC,
                strictCert = false
            ).createAndConnectTransport(
                host = "blocked.opengw.net",
                ipAddress = InetAddress.getLoopbackAddress(),
                port = dpiProxy.localPort,
                timeoutMs = 5000
            )
            transport.outputStream.write("PING".toByteArray(), 0, 4)
            transport.outputStream.flush()
            val reply = ByteArray(16)
            val n = transport.inputStream.read(reply, 0, reply.size)
            assertEquals("OK", String(reply, 0, n))
            transport.close()
        } finally {
            stopProxy()
            try { tlsServer.close() } catch (_: Exception) {}
            serverExecutor.shutdownNow()
        }
    }

    @Test
    fun windowAlpnMicroDesyncDefeatsStatefulMultiSegmentTimeoutDpiOverRealTls() = runBlocking {
        val tlsServer = createLoopbackSslServer()
        val serverExecutor = Executors.newCachedThreadPool()
        serverExecutor.submit {
            while (!tlsServer.isClosed) {
                val s = try { tlsServer.accept() } catch (_: Exception) { break }
                serverExecutor.submit {
                    try {
                        val buf = ByteArray(64)
                        val n = s.getInputStream().read(buf)
                        if (n > 0) {
                            s.getOutputStream().write("OK".toByteArray())
                            s.getOutputStream().flush()
                        }
                    } catch (_: Exception) {} finally {
                        try { s.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        // Stateful DPI simulator: reassembles TCP chunks within a 15ms fast-path window and resets if SNI appears
        val blockedBytes = "stateful-blocked.opengw.net".toByteArray(Charsets.US_ASCII)
        val dpiProxy = ServerSocket(0, 16, InetAddress.getLoopbackAddress())
        val proxyPool = Executors.newCachedThreadPool()
        proxyPool.submit {
            while (!dpiProxy.isClosed) {
                val client = try { dpiProxy.accept() } catch (_: Exception) { break }
                proxyPool.submit {
                    var upstream: java.net.Socket? = null
                    try {
                        client.soTimeout = 15
                        val cIn = client.getInputStream()
                        val assembled = java.io.ByteArrayOutputStream()
                        val buf = ByteArray(4096)
                        var segmentsRead = 0
                        while (segmentsRead < 6) {
                            val n = try {
                                cIn.read(buf)
                            } catch (_: java.net.SocketTimeoutException) {
                                break
                            }
                            if (n <= 0) break
                            assembled.write(buf, 0, n)
                            segmentsRead++
                        }
                        client.soTimeout = 0
                        val windowBytes = assembled.toByteArray()
                        if (windowBytes.isEmpty()) {
                            client.close()
                            return@submit
                        }
                        if (indexOfBytes(windowBytes, blockedBytes) >= 0) {
                            client.setSoLinger(true, 0)
                            client.close()
                            return@submit
                        }

                        upstream = java.net.Socket(InetAddress.getLoopbackAddress(), tlsServer.localPort)
                        val uOut = upstream.getOutputStream()
                        uOut.write(windowBytes)
                        uOut.flush()
                        val forwardBack = proxyPool.submit {
                            try {
                                upstream.getInputStream().copyTo(client.getOutputStream())
                            } catch (_: Exception) {} finally {
                                try { client.close() } catch (_: Exception) {}
                            }
                        }
                        try {
                            cIn.copyTo(uOut)
                        } catch (_: Exception) {} finally {
                            try { upstream.close() } catch (_: Exception) {}
                            forwardBack.cancel(true)
                        }
                    } catch (_: Exception) {
                        try { client.close() } catch (_: Exception) {}
                        try { upstream?.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        try {
            var basicDesyncFailed = false
            try {
                SniBypassSocketFactory(strategy = SniStrategy.TLS_HEADER_DESYNC, strictCert = false)
                    .createAndConnectTransport(
                        host = "stateful-blocked.opengw.net",
                        ipAddress = InetAddress.getLoopbackAddress(),
                        port = dpiProxy.localPort,
                        timeoutMs = 2500
                    ).close()
            } catch (_: Exception) {
                basicDesyncFailed = true
            }
            assertTrue("Basic 4-slice header desync should be caught by 15ms stateful reassembler", basicDesyncFailed)

            val transport = SniBypassSocketFactory(
                strategy = SniStrategy.WINDOW_ALPN_MICRO_DESYNC,
                strictCert = false
            ).createAndConnectTransport(
                host = "stateful-blocked.opengw.net",
                ipAddress = InetAddress.getLoopbackAddress(),
                port = dpiProxy.localPort,
                timeoutMs = 5000
            )
            transport.outputStream.write("PING".toByteArray(), 0, 4)
            transport.outputStream.flush()
            val reply = ByteArray(16)
            val n = transport.inputStream.read(reply, 0, reply.size)
            assertEquals("OK", String(reply, 0, n))
            transport.close()
        } finally {
            try { dpiProxy.close() } catch (_: Exception) {}
            proxyPool.shutdownNow()
            try { tlsServer.close() } catch (_: Exception) {}
            serverExecutor.shutdownNow()
        }
    }

    @Test
    fun zapretSplit1DefeatsStrictDpiOverRealTls() = runBlocking {
        val tlsServer = createLoopbackSslServer()
        val serverExecutor = Executors.newCachedThreadPool()
        serverExecutor.submit {
            while (!tlsServer.isClosed) {
                val s = try { tlsServer.accept() } catch (_: Exception) { break }
                serverExecutor.submit {
                    try {
                        val buf = ByteArray(64)
                        val n = s.getInputStream().read(buf)
                        if (n > 0) {
                            s.getOutputStream().write("OK".toByteArray())
                            s.getOutputStream().flush()
                        }
                    } catch (_: Exception) {} finally {
                        try { s.close() } catch (_: Exception) {}
                    }
                }
            }
        }

        val (dpiProxy, stopProxy) = startDpiProxy(
            targetPort = tlsServer.localPort,
            blockedHost = "blocked.opengw.net",
            dropOnIntactClientHelloHeader = true
        )

        try {
            val transport = SniBypassSocketFactory(
                strategy = SniStrategy.ZAPRET_SPLIT1_DESYNC,
                strictCert = false
            ).createAndConnectTransport(
                host = "blocked.opengw.net",
                ipAddress = InetAddress.getLoopbackAddress(),
                port = dpiProxy.localPort,
                timeoutMs = 5000
            )
            transport.outputStream.write("PING".toByteArray(), 0, 4)
            transport.outputStream.flush()
            val reply = ByteArray(16)
            val n = transport.inputStream.read(reply, 0, reply.size)
            assertEquals("OK", String(reply, 0, n))
            transport.close()
        } finally {
            stopProxy()
            try { tlsServer.close() } catch (_: Exception) {}
            serverExecutor.shutdownNow()
        }
    }
}
