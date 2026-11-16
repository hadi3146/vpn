package com.aethervpn.vpncore.tun

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class Ipv4RouteCalculatorTest {

    @Test
    fun parseNormalizesHostBitsAndRejectsInvalidInputs() {
        val c = Ipv4Cidr.parse("185.188.107.12/22")
        assertNotNull(c)
        assertEquals("185.188.104.0", c!!.hostAddress)
        assertEquals(22, c.prefixLen)

        val single = Ipv4Cidr.parse("1.1.1.1")
        assertNotNull(single)
        assertEquals(32, single!!.prefixLen)
        assertEquals("1.1.1.1", single.hostAddress)

        assertNull(Ipv4Cidr.parse("# comment only"))
        assertNull(Ipv4Cidr.parse("999.1.1.1/24"))
        assertNull(Ipv4Cidr.parse("1.1.1.1/33"))
    }

    @Test
    fun coalesceMergesAdjacentSiblingsAndDropsOverlaps() {
        val raw = listOfNotNull(
            Ipv4Cidr.parse("192.168.0.0/25"),
            Ipv4Cidr.parse("192.168.0.128/25"),
            Ipv4Cidr.parse("192.168.0.64/26"), // overlapped by /25 sibling merge -> /24
            Ipv4Cidr.parse("192.168.1.0/24")    // merges with 192.168.0.0/24 -> 192.168.0.0/23
        )
        val merged = Ipv4RouteCalculator.coalesce(raw)
        assertEquals(1, merged.size)
        assertEquals("192.168.0.0", merged[0].hostAddress)
        assertEquals(23, merged[0].prefixLen)
    }

    @Test
    fun computeAllowedRoutesProducesExactComplementPartition() {
        val excludes = Ipv4RouteCalculator.LAN_AND_MULTICAST_EXCLUDES + listOfNotNull(
            Ipv4Cidr.parse("2.176.0.0/12"),      // TCI Iran block
            Ipv4Cidr.parse("5.106.0.0/16"),      // Rightel/Iran block
            Ipv4Cidr.parse("185.167.72.0/22"),   // Shaparak Iran block
            Ipv4Cidr.parse("185.188.104.0/22")   // Digikala Iran block
        )
        val cleanExcluded = Ipv4RouteCalculator.coalesce(excludes)
        val allowed = Ipv4RouteCalculator.computeAllowedRoutes(cleanExcluded)

        fun sizeOf(c: Ipv4Cidr): Long = 1L shl (32 - c.prefixLen)
        val excludedSum = cleanExcluded.sumOf(::sizeOf)
        val allowedSum = allowed.sumOf(::sizeOf)
        assertEquals(1L shl 32, excludedSum + allowedSum)

        // Iranian and LAN IPs must NOT match any allowed route
        val directSamples = listOf("2.189.58.6", "5.106.8.151", "185.167.73.34", "185.188.107.12", "192.168.100.1", "224.0.0.251")
        for (ip in directSamples) {
            val addr = InetAddress.getByName(ip)
            assertTrue("Expected $ip in excluded", Ipv4RouteCalculator.containsIp(cleanExcluded, addr))
            assertFalse("Expected $ip excluded from tunnel", Ipv4RouteCalculator.containsIp(allowed, addr))
        }

        // Foreign and internal VPN DNS IPs MUST match allowed routes
        val tunnelSamples = listOf("1.1.1.1", "8.8.8.8", "149.154.167.91", "157.240.1.174", "10.254.254.254")
        for (ip in tunnelSamples) {
            val addr = InetAddress.getByName(ip)
            assertFalse("Expected $ip not in excluded", Ipv4RouteCalculator.containsIp(cleanExcluded, addr))
            assertTrue("Expected $ip routed via tunnel", Ipv4RouteCalculator.containsIp(allowed, addr))
        }
    }
}

