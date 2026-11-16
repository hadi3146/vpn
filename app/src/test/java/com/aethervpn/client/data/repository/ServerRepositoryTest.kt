package com.aethervpn.client.data.repository

import com.aethervpn.client.data.model.VpnServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class ServerRepositoryTest {

    @Test
    fun parseHttpResponseDecodesChunkedBody() {
        val raw = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/plain\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5\r\nHello\r\n" +
                "7\r\n, World\r\n" +
                "0\r\n\r\n"
            ).toByteArray(Charsets.ISO_8859_1)

        val resp = ServerRepository.parseHttpResponse(ByteArrayInputStream(raw))
        assertNotNull(resp)
        assertEquals(200, resp!!.statusCode)
        assertEquals("Hello, World", String(resp.body, Charsets.UTF_8))
    }

    @Test
    fun parseHttpResponseHonorsContentLengthAndRedirect() {
        val raw = (
            "HTTP/1.1 302 Found\r\n" +
                "Location: https://mirror.example.org/api/iphone/\r\n" +
                "Content-Length: 4\r\n" +
                "\r\n" +
                "moveIGNORED"
            ).toByteArray(Charsets.ISO_8859_1)

        val resp = ServerRepository.parseHttpResponse(ByteArrayInputStream(raw))
        assertNotNull(resp)
        assertEquals(302, resp!!.statusCode)
        assertEquals("https://mirror.example.org/api/iphone/", resp.location)
        assertEquals("move", String(resp.body, Charsets.UTF_8))
    }

    @Test
    fun parseHttpResponseReturnsNullOnIncompleteHeaders() {
        val raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n".toByteArray(Charsets.ISO_8859_1)
        assertNull(ServerRepository.parseHttpResponse(ByteArrayInputStream(raw)))
    }

    @Test
    fun buildOrderedBypassCandidatesPromotesPreferredStrategyFirst() {
        val ordered = ServerRepository.buildOrderedBypassCandidates("TCP_FRAGMENTATION:3")
        assertEquals(ServerRepository.DEFAULT_MIRROR_BYPASS_CANDIDATES.size, ordered.size)
        assertEquals("TCP_FRAGMENTATION:3", ordered.first().key)
        assertEquals(
            ServerRepository.DEFAULT_MIRROR_BYPASS_CANDIDATES.map { it.key }.toSet(),
            ordered.map { it.key }.toSet()
        )
    }

    @Test
    fun buildOrderedBypassCandidatesFallsBackToDefaultOrderForUnknownKey() {
        val ordered = ServerRepository.buildOrderedBypassCandidates("UNKNOWN")
        assertEquals(ServerRepository.DEFAULT_MIRROR_BYPASS_CANDIDATES, ordered)
    }

    @Test
    fun selectProbeCandidatesEnsuresCountryDiversityAcrossDominantRegion() {
        val jpServers = (1..30).map { i ->
            VpnServer(
                hostName = "jp-$i.opengw.net",
                ip = "219.100.37.$i",
                score = 5_000_000L - i * 1000L,
                countryLong = "Japan",
                countryShort = "JP"
            )
        }
        val diverseServers = listOf(
            VpnServer(hostName = "us-1.opengw.net", ip = "198.51.100.1", score = 900_000L, countryLong = "United States", countryShort = "US"),
            VpnServer(hostName = "de-1.opengw.net", ip = "203.0.113.2", score = 800_000L, countryLong = "Germany", countryShort = "DE"),
            VpnServer(hostName = "ro-1.opengw.net", ip = "217.138.212.62", score = 700_000L, countryLong = "Romania", countryShort = "RO")
        )
        val picked = ServerRepository.selectProbeCandidates(jpServers + diverseServers, limit = 10)
        assertEquals(10, picked.size)
        val countries = picked.map { it.countryShort }.toSet()
        assertTrue(countries.containsAll(setOf("JP", "US", "DE", "RO")))
    }

    @Test
    fun smartSortServersDemotesCooldownAndPrioritizesVerifiedHealthy() {
        val now = 1_700_000_000_000L
        val deadTopScore = VpnServer(
            hostName = "blackhole.opengw.net",
            ip = "219.100.37.209",
            score = 9_999_999L,
            ping = 30,
            failureCount = 1,
            cooldownUntil = now + 600_000L
        )
        val untestedHigherScore = VpnServer(
            hostName = "untested.opengw.net",
            ip = "219.100.37.10",
            score = 4_000_000L,
            ping = 80
        )
        val provenHealthy = VpnServer(
            hostName = "healthy.opengw.net",
            ip = "219.100.37.184",
            score = 2_000_000L,
            ping = 75,
            successCount = 3,
            lastVerifiedAt = now - 5_000L
        )
        val favoriteHealthy = VpnServer(
            hostName = "fav.opengw.net",
            ip = "219.100.37.85",
            score = 1_000_000L,
            ping = 90,
            isFavorite = true,
            successCount = 1,
            lastVerifiedAt = now - 10_000L
        )

        val sorted = ServerRepository.smartSortServers(
            listOf(deadTopScore, untestedHigherScore, provenHealthy, favoriteHealthy),
            nowMs = now
        )
        assertEquals(
            listOf("fav.opengw.net", "healthy.opengw.net", "untested.opengw.net", "blackhole.opengw.net"),
            sorted.map { it.hostName }
        )
    }

    @Test
    fun selectRaceCandidatesPutsPrimaryFirstAndMaximizesCountryAndSubnetDiversity() {
        val now = 1_700_000_000_000L
        val primary = VpnServer(hostName = "jp-1.opengw.net", ip = "133.242.10.10", score = 9_000_000L, countryShort = "JP", ping = 60)
        val sameSubnetJp = VpnServer(hostName = "jp-2.opengw.net", ip = "133.242.10.11", score = 8_500_000L, countryShort = "JP", ping = 55)
        val krBackup = VpnServer(hostName = "kr-1.opengw.net", ip = "121.135.10.5", score = 4_000_000L, countryShort = "KR", ping = 90)
        val deBackup = VpnServer(hostName = "de-1.opengw.net", ip = "203.0.113.8", score = 3_000_000L, countryShort = "DE", ping = 110)
        val excluded = VpnServer(hostName = "us-dead.opengw.net", ip = "198.51.100.9", score = 9_999_999L, countryShort = "US", ping = 40)

        val picked = ServerRepository.selectRaceCandidates(
            servers = listOf(primary, sameSubnetJp, krBackup, deBackup, excluded),
            primary = primary,
            excludedHosts = setOf("us-dead.opengw.net"),
            maxCandidates = 3,
            nowMs = now
        )

        assertEquals(listOf("jp-1.opengw.net", "de-1.opengw.net", "kr-1.opengw.net"), picked.map { it.hostName })
    }

    @Test
    fun `smartSortServers ranks European servers ahead of Asia and US in same health tier`() {
        val now = 1_700_000_000_000L
        val jpTopScore = VpnServer(hostName = "jp-fast.opengw.net", ip = "133.242.10.10", score = 9_900_000L, countryShort = "JP", ping = 45)
        val usTopScore = VpnServer(hostName = "us-fast.opengw.net", ip = "198.51.100.2", score = 8_000_000L, countryShort = "US", ping = 60)
        val roServer = VpnServer(hostName = "ro-eu.opengw.net", ip = "217.138.212.62", score = 1_000_000L, countryShort = "RO", ping = 110)
        val deServer = VpnServer(hostName = "de-eu.opengw.net", ip = "203.0.113.20", score = 2_000_000L, countryShort = "DE", ping = 95)

        val sorted = ServerRepository.smartSortServers(
            listOf(jpTopScore, usTopScore, roServer, deServer),
            nowMs = now
        )
        assertEquals(
            listOf("de-eu.opengw.net", "ro-eu.opengw.net", "jp-fast.opengw.net", "us-fast.opengw.net"),
            sorted.map { it.hostName }
        )
    }

    @Test
    fun `smartSortServers demotes restricted Tsukuba academic subnet below regular servers`() {
        val now = 1_700_000_000_000L
        val tsukubaAcademic = VpnServer(hostName = "tsukuba.opengw.net", ip = "219.100.37.10", score = 10_000_000L, countryShort = "JP", ping = 30)
        val normalServer = VpnServer(hostName = "normal-jp.opengw.net", ip = "133.242.10.10", score = 1_000_000L, countryShort = "JP", ping = 80)

        val sorted = ServerRepository.smartSortServers(listOf(tsukubaAcademic, normalServer), nowMs = now)
        assertEquals("normal-jp.opengw.net", sorted.first().hostName)
        assertEquals("tsukuba.opengw.net", sorted.last().hostName)
    }

    @Test
    fun `buildRefreshedServerPool supplements sparse probe results up to target 36 servers`() {
        val parsed = (1..60).map { idx ->
            val cc = if (idx <= 12) "DE" else "JP"
            VpnServer(
                hostName = "srv-$idx.opengw.net",
                ip = "203.0.${idx / 250}.${idx % 250 + 1}",
                score = 1_000_000L - idx * 1000L,
                countryShort = cc,
                ping = 40 + idx
            )
        }
        val verified = parsed.take(15)
        val pool = ServerRepository.buildRefreshedServerPool(parsed, verified, targetMinServers = 36)

        assertEquals(36, pool.size)
        // First 15 keep their measured ping while supplemented entries get ping = -1
        assertEquals(15, pool.count { it.ping > 0 })
        assertEquals(21, pool.count { it.ping == -1 })
    }

    @Test
    fun `deprioritized subnets skip failing 24 prefix before falling back`() {
        val now = 1_700_000_000_000L
        val jpSame1 = VpnServer(hostName = "jp-1.opengw.net", ip = "219.100.37.28", score = 9_900_000L, countryShort = "JP", ping = 40)
        val jpSame2 = VpnServer(hostName = "jp-2.opengw.net", ip = "219.100.37.29", score = 9_800_000L, countryShort = "JP", ping = 45)
        val inHealthy = VpnServer(hostName = "in-1.opengw.net", ip = "14.98.67.213", score = 2_000_000L, countryShort = "IN", ping = 120)
        val krHealthy = VpnServer(hostName = "kr-1.opengw.net", ip = "121.135.10.5", score = 1_500_000L, countryShort = "KR", ping = 140)

        val picked = ServerRepository.selectRaceCandidates(
            servers = listOf(jpSame1, jpSame2, inHealthy, krHealthy),
            primary = null,
            excludedHosts = emptySet(),
            deprioritizedSubnets = setOf("219.100.37"),
            maxCandidates = 3,
            nowMs = now
        )
        // Fresh /24 subnets must lead the batch before reusing the failing 219.100.37.* cluster
        assertEquals(listOf("in-1.opengw.net", "kr-1.opengw.net"), picked.take(2).map { it.hostName })

        val next = ServerRepository.selectNextCandidate(
            servers = listOf(jpSame1, jpSame2, inHealthy),
            excludedHosts = emptySet(),
            deprioritizedSubnets = setOf("219.100.37"),
            nowMs = now
        )
        assertEquals("in-1.opengw.net", next?.hostName)

        // When all fresh /24 subnets are excluded, fallback still returns remaining servers cleanly
        val fallbackNext = ServerRepository.selectNextCandidate(
            servers = listOf(jpSame1, inHealthy),
            excludedHosts = setOf("in-1.opengw.net"),
            deprioritizedSubnets = setOf("219.100.37"),
            nowMs = now
        )
        assertEquals("jp-1.opengw.net", fallbackNext?.hostName)
    }

    @Test
    fun `resolveEffectiveMtu clamps tunnel MTU cleanly for cellular LTE interfaces`() {
        // Cellular rmnet interface MTU 1358 -> capped well below outer SSTP+TLS+TCP header overhead
        assertEquals(1274, ServerRepository.resolveEffectiveMtu(configuredMtu = 1430, physicalMtu = 1358, isCellular = true))
        // Cellular with unknown physical MTU falls back to conservative 1280
        assertEquals(1280, ServerRepository.resolveEffectiveMtu(configuredMtu = 1430, physicalMtu = 0, isCellular = true))
        // Standard 1500 Wi-Fi keeps configured MTU
        assertEquals(1430, ServerRepository.resolveEffectiveMtu(configuredMtu = 1430, physicalMtu = 1500, isCellular = false))
    }

    @Test
    fun `censored exit nodes are excluded from auto failover and race pools`() {
        val now = 1_700_000_000_000L
        val ruFast = VpnServer(hostName = "ru-fast.opengw.net", ip = "80.70.96.50", score = 9_999_999L, countryShort = "RU", ping = 35)
        val irNode = VpnServer(hostName = "ir-node.opengw.net", ip = "5.200.10.2", score = 9_000_000L, countryShort = "IR", ping = 20)
        val cnNode = VpnServer(hostName = "cn-node.opengw.net", ip = "114.114.114.114", score = 8_000_000L, countryShort = "CN", ping = 50)
        val deBackup = VpnServer(hostName = "de-1.opengw.net", ip = "203.0.113.8", score = 3_000_000L, countryShort = "DE", ping = 110)
        val jpBackup = VpnServer(hostName = "jp-1.opengw.net", ip = "219.100.37.10", score = 2_000_000L, countryShort = "JP", ping = 140)

        val race = ServerRepository.selectRaceCandidates(
            servers = listOf(ruFast, irNode, cnNode, deBackup, jpBackup),
            primary = null,
            excludedHosts = emptySet(),
            maxCandidates = 3,
            nowMs = now
        )
        // Censored countries (RU, IR, CN) must NEVER enter the race pool
        assertEquals(listOf("de-1.opengw.net", "jp-1.opengw.net"), race.map { it.hostName })

        val next = ServerRepository.selectNextCandidate(
            servers = listOf(ruFast, irNode, cnNode, deBackup),
            nowMs = now
        )
        assertEquals("de-1.opengw.net", next?.hostName)

        val sorted = ServerRepository.smartSortServers(
            servers = listOf(ruFast, deBackup, irNode, jpBackup),
            nowMs = now
        )
        // Free countries lead; RU and IR are demoted to the bottom despite lower ping/higher score
        assertEquals(listOf("de-1.opengw.net", "jp-1.opengw.net", "ru-fast.opengw.net", "ir-node.opengw.net"), sorted.map { it.hostName })
    }

    @Test
    fun `restricted academic Tsukuba nodes are deprioritized behind commercial servers`() {
        val now = 1_700_000_000_000L
        val tsukuba = VpnServer(hostName = "tsukuba.opengw.net", ip = "219.100.37.121", score = 9_999_999L, countryShort = "JP", ping = 30)
        val commercialJp = VpnServer(hostName = "jp-ocn.opengw.net", ip = "121.86.244.13", score = 1_000_000L, countryShort = "JP", ping = 70)
        val koreaCommercial = VpnServer(hostName = "kr-kt.opengw.net", ip = "221.165.229.38", score = 1_200_000L, countryShort = "KR", ping = 80)

        val sorted = ServerRepository.smartSortServers(listOf(tsukuba, commercialJp, koreaCommercial), nowMs = now)
        // Commercial JP and KR must sort before Tsukuba academic node despite lower score
        assertEquals("kr-kt.opengw.net", sorted[0].hostName)
        assertEquals("jp-ocn.opengw.net", sorted[1].hostName)
        assertEquals("tsukuba.opengw.net", sorted[2].hostName)

        val race = ServerRepository.selectRaceCandidates(listOf(tsukuba, commercialJp, koreaCommercial), nowMs = now)
        assertEquals(listOf("kr-kt.opengw.net", "jp-ocn.opengw.net", "tsukuba.opengw.net"), race.map { it.hostName })
    }
}

